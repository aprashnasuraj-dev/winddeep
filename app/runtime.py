"""Production runtime wiring for Windeep's guarded local desktop server."""
from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
import time
import uuid
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from app.brain.hypothesis_engine import HypothesisEngine
from app.brain.llm_client import LLMClient
from app.capture.flow_database import ExportFormat
from app.engine.event_bus import Event, EventBus
from app.engine.scan_context import ScanContext
from app.engine.scheduler import TaskScheduler, TaskSpec
from app.engine.tool_wrapper import Finding, ToolExecutionError, ToolWrapperFactory
from app.migrations import MigrationManager
from app.modules.test_packs import HunterContext, list_test_metadata, run_selected_tests
from app.security.audit import AuditLog
from app.security.consent import ConsentAuthority
from app.security.crypto import CryptoManager
from app.security.preflight import PreFlightGuard
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase
from app.submissions import SubmissionTracker


def resource_root() -> Path:
    """Return the source/PyInstaller resource root."""
    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        return Path(str(frozen)).resolve()
    return Path(__file__).resolve().parents[1]


class RuntimeErrorSafe(RuntimeError):
    """Operational error safe to return through the localhost API."""


class WindeepRuntime:
    """Own long-lived production services and guarded background execution."""

    EVENT_PATTERNS = ("scan.*", "tool.*", "finding.*", "log.*", "flow.*", "brain.*", "report.*")

    def __init__(
        self,
        *,
        state_dir: str | Path,
        crypto: CryptoManager,
        audit: AuditLog,
        consent: ConsentAuthority,
    ) -> None:
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.root = resource_root()
        self.crypto = crypto
        self.audit = audit
        self.consent = consent
        self.database_path = self.state_dir / "windeep.db"
        self.database = SecureDatabase(self.database_path, crypto=crypto)
        migrations_dir = self.root / "app" / "data" / "migrations"
        MigrationManager(self.database_path, migrations_dir, backup_dir=self.state_dir / "backups").apply()
        self.flows = SecureFlowDatabase(self.database)
        self.submissions = SubmissionTracker(self.database)
        self.event_bus = EventBus()
        self.wrapper_factory = ToolWrapperFactory(self.root / "tools_config.json")
        self.wrapper_classes = self.wrapper_factory.load()
        self.tools_dir = self.root / "tools"
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="windeep-runtime", daemon=True)
        self._ready = threading.Event()
        self._stopping = threading.Event()
        self._futures: dict[int, Future[Any]] = {}
        self._future_lock = threading.RLock()
        self._sse_lock = threading.RLock()
        self._sse_subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._capture_lock = threading.RLock()
        self._capture_contexts: dict[int, dict[str, Any]] = {}
        self.capture_token = uuid.uuid4().hex + uuid.uuid4().hex
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("background runtime failed to start")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        for pattern in self.EVENT_PATTERNS:
            self._loop.create_task(self._bridge(pattern), name=f"windeep-bridge:{pattern}")
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.run_until_complete(self.event_bus.close())
            self._loop.close()

    async def _bridge(self, pattern: str) -> None:
        async for event in self.event_bus.subscribe(pattern):
            payload = self._event_payload(event)
            with self._sse_lock:
                subscribers = list(self._sse_subscribers)
            for subscriber in subscribers:
                try:
                    subscriber.put_nowait(payload)
                except queue.Full:
                    try:
                        subscriber.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        subscriber.put_nowait(payload)
                    except queue.Full:
                        pass

    @staticmethod
    def _event_payload(event: Event) -> dict[str, Any]:
        return {"id": event.id, "topic": event.topic, "timestamp": event.timestamp, "payload": event.payload}

    def subscribe_events(self, *, maxsize: int = 512) -> queue.Queue[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=maxsize)
        with self._sse_lock:
            self._sse_subscribers.add(subscriber)
        return subscriber

    def unsubscribe_events(self, subscriber: queue.Queue[dict[str, Any]]) -> None:
        with self._sse_lock:
            self._sse_subscribers.discard(subscriber)

    def publish(self, topic: str, payload: Mapping[str, Any] | None = None) -> Future[Any]:
        return asyncio.run_coroutine_threadsafe(self.event_bus.publish(topic, payload or {}), self._loop)

    def close(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        with self._future_lock:
            futures = list(self._futures.values())
        for future in futures:
            future.cancel()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    def _target(self, target_id: int) -> dict[str, Any]:
        item = self.database.get_target(int(target_id))
        if item is None:
            raise RuntimeErrorSafe(f"target not found: {target_id}")
        return item

    def guard_for_target(
        self,
        target: Mapping[str, Any],
        consent_id: str,
        *,
        global_rps: float = 5.0,
        global_burst: float = 5.0,
    ) -> PreFlightGuard:
        scope = ScopeEnforcer(
            target=str(target["target"]),
            allow=[str(v) for v in target.get("scope") or []],
            deny=[str(v) for v in target.get("out_of_scope") or []],
        )
        governor = RateGovernor(global_policy=RatePolicy(rate_per_second=max(0.1, min(float(global_rps), 25.0)), burst=max(1.0, min(float(global_burst), 50.0))))
        guard = PreFlightGuard(scope=scope, rate_governor=governor, consent=self.consent, crypto=self.crypto, audit=self.audit)
        guard.authorize_scan(target=str(target["target"]), consent_id=consent_id)
        return guard

    def list_tools(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for name, cls in sorted(self.wrapper_classes.items()):
            wrapper = cls(tools_dir=self.tools_dir, scope_validator=lambda _candidate: False)
            output.append(
                {
                    "name": name,
                    "category": cls.category,
                    "description": cls.description,
                    "binary": cls.binary,
                    "release_support": getattr(cls, "release_support", "unreviewed"),
                    "unsupported_reason": getattr(cls, "unsupported_reason", ""),
                    "replacement": getattr(cls, "replacement", ""),
                    "installed": wrapper.validate_installed(),
                    "missing_environment": list(wrapper.missing_environment()),
                }
            )
        return output

    def start_tool_scan(
        self,
        *,
        target_id: int,
        consent_id: str,
        tool_names: Iterable[str],
        scan_type: str = "module",
        global_rps: float = 5.0,
    ) -> int:
        target = self._target(target_id)
        guard = self.guard_for_target(target, consent_id, global_rps=global_rps, global_burst=max(2.0, global_rps))
        names = [str(name) for name in tool_names]
        if not names:
            raise RuntimeErrorSafe("at least one tool is required")
        unknown = [name for name in names if name not in self.wrapper_classes]
        if unknown:
            raise RuntimeErrorSafe("unknown tool(s): " + ", ".join(sorted(unknown)))
        unsupported = [name for name in names if getattr(self.wrapper_classes[name], "release_support", "unreviewed") not in {"bundled", "runtime", "internal", "system"}]
        if unsupported:
            raise RuntimeErrorSafe("tool(s) are not enabled in this Windows release: " + ", ".join(sorted(unsupported)))
        scan_id = self.database.create_scan(target_id, scan_type, names)
        context = ScanContext(
            target=str(target["target"]),
            scope=[str(v) for v in target.get("scope") or []],
            out_of_scope=[str(v) for v in target.get("out_of_scope") or []],
            consent_id=consent_id,
            target_id=target_id,
        )
        with self._capture_lock:
            self._capture_contexts[scan_id] = {"target": target, "consent_id": consent_id, "started_at": time.time()}
        future = asyncio.run_coroutine_threadsafe(self._execute_scan(scan_id, context, guard, names), self._loop)
        with self._future_lock:
            self._futures[scan_id] = future
        return scan_id

    async def _execute_scan(self, scan_id: int, context: ScanContext, guard: PreFlightGuard, names: list[str]) -> None:
        self.database.update_scan(scan_id, status="running", started_at=time.time(), progress=0.0)
        scheduler = TaskScheduler(self.event_bus, preflight=guard, global_concurrency=min(8, max(1, len(names))))
        persisted = 0

        def make_runner(tool_name: str):
            async def runner(_context: ScanContext, _dependencies: Mapping[str, Any]) -> list[dict[str, Any]]:
                nonlocal persisted
                cls = self.wrapper_classes[tool_name]
                if getattr(cls, "release_support", "unreviewed") == "internal":
                    await self.event_bus.publish("tool.completed", {"scan_id": scan_id, "tool": tool_name, "note": "internal adapter has no external process"})
                    return []
                wrapper = cls(tools_dir=self.tools_dir, scope_validator=_context.is_in_scope)
                run_id = self.database.create_tool_run(tool_name=tool_name, status="running", scan_id=scan_id, target_id=context.target_id)
                command = [cls.binary, *cls.args_template]
                try:
                    with self.database._connect() as conn:
                        conn.execute("UPDATE tool_runs SET command = ? WHERE id = ?", (json.dumps(command), run_id))
                    findings = await wrapper.run(context.target)
                    records: list[dict[str, Any]] = []
                    for finding in findings:
                        record = finding.model_dump()
                        records.append(record)
                        if self._is_reportable(finding):
                            finding_id, created = self.database.create_finding(
                                int(context.target_id or 0),
                                finding.title,
                                finding.severity,
                                scan_id=scan_id,
                                vuln_type=finding.vuln_type,
                                tool=finding.tool,
                                endpoint=finding.endpoint,
                                description=finding.description,
                                evidence=finding.evidence,
                                confidence=finding.confidence,
                            )
                            if created:
                                persisted += 1
                                await self.event_bus.publish("finding.created", {"scan_id": scan_id, "target_id": context.target_id, "finding_id": finding_id, "title": finding.title, "severity": finding.severity, "tool": finding.tool})
                    self.database.finish_tool_run(run_id, status="completed", exit_code=0, stdout_tail=f"normalized records: {len(records)}")
                    return records
                except asyncio.CancelledError:
                    self.database.finish_tool_run(run_id, status="cancelled", error="cancelled")
                    raise
                except Exception as exc:
                    self.database.finish_tool_run(run_id, status="failed", error=str(exc))
                    raise
            return runner

        tasks = [TaskSpec(name=name, runner=make_runner(name), tool_name=name, continue_on_error=True) for name in names]
        try:
            results = await scheduler.execute(tasks, context, scan_id=str(scan_id))
            summary = {"tools": len(names), "reportable_findings": persisted, "records": sum(len(v) for v in results.values() if isinstance(v, list))}
            self.database.update_scan(scan_id, status="completed", progress=100.0, finished_at=time.time(), results_summary=summary)
        except asyncio.CancelledError:
            self.database.update_scan(scan_id, status="cancelled", finished_at=time.time())
            raise
        except Exception as exc:
            self.database.update_scan(scan_id, status="failed", finished_at=time.time(), results_summary={"error": str(exc), "reportable_findings": persisted})
            await self.event_bus.publish("scan.failed", {"scan_id": scan_id, "error": str(exc)})
        finally:
            with self._future_lock:
                self._futures.pop(scan_id, None)
            with self._capture_lock:
                self._capture_contexts.pop(scan_id, None)

    @staticmethod
    def _is_reportable(finding: Finding) -> bool:
        return finding.severity in {"critical", "high", "medium", "low"} and finding.vuln_type != "tool_output" and finding.confidence >= 0.5

    def cancel_scan(self, scan_id: int) -> bool:
        with self._future_lock:
            future = self._futures.get(scan_id)
        if future is None:
            return False
        cancelled = future.cancel()
        if cancelled:
            self.audit.append("scan.cancel_requested", {"scan_id": scan_id})
        return cancelled

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        for field, default in (("modules", []), ("results_summary", {})):
            try:
                item[field] = json.loads(item.get(field) or "")
            except (TypeError, json.JSONDecodeError):
                item[field] = default
        return item

    def list_scans(self, *, target_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self.database._connect() as conn:
            if target_id is None:
                rows = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = conn.execute("SELECT id FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT ?", (target_id, limit)).fetchall()
        return [item for row in rows if (item := self.get_scan(int(row["id"]))) is not None]

    def list_scan_logs(self, scan_id: int, *, limit: int = 1000) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id DESC LIMIT ?", (scan_id, max(1, min(limit, 5000)))).fetchall()
        return [dict(row) for row in reversed(rows)]

    def run_test_packs(
        self,
        *,
        target_id: int,
        consent_id: str,
        packs: Iterable[str] | None = None,
        test_ids: Iterable[str] | None = None,
        authenticated: bool = False,
        account_count: int = 0,
        mobile_artifact: bool = False,
        signals: Iterable[str] = (),
    ) -> list[dict[str, Any]]:
        target = self._target(target_id)
        self.guard_for_target(target, consent_id, global_rps=1.0, global_burst=1.0)
        ctx = HunterContext(
            target_url=str(target["target"]),
            target_id=target_id,
            flows=self.flows.get_flows_by_target(target_id, limit=1000),
            findings=self.database.list_findings(target_id=target_id, limit=1000),
            authenticated=authenticated,
            account_count=account_count,
            mobile_artifact=mobile_artifact,
            signals={str(v).casefold() for v in signals},
        )
        future = asyncio.run_coroutine_threadsafe(run_selected_tests(ctx, packs=packs, test_ids=test_ids), self._loop)
        results = future.result(timeout=120)
        self.audit.append("test_packs.executed", {"target_id": target_id, "count": len(results), "observed": sum(1 for r in results if r.get("passed"))})
        return results

    def generate_brain_hypotheses(self, *, target_id: int, consent_id: str) -> list[dict[str, Any]]:
        target = self._target(target_id)
        self.guard_for_target(target, consent_id, global_rps=1.0, global_burst=1.0)
        context = ScanContext(
            target=str(target["target"]),
            scope=[str(v) for v in target.get("scope") or []],
            out_of_scope=[str(v) for v in target.get("out_of_scope") or []],
            consent_id=consent_id,
            target_id=target_id,
        )
        findings = self.database.list_findings(target_id=target_id, limit=1000)
        engine = HypothesisEngine(LLMClient([]), self.event_bus, database=self.database)
        future = asyncio.run_coroutine_threadsafe(engine.generate(findings, context, target_id=target_id), self._loop)
        return [item.model_dump() for item in future.result(timeout=120)]

    def resolve_capture_target(self, url: str) -> tuple[int | None, int | None]:
        if not url or not urlsplit(url).hostname:
            return None, None
        with self._capture_lock:
            items = list(self._capture_contexts.items())
        for scan_id, entry in reversed(items):
            target = entry["target"]
            try:
                guard = self.guard_for_target(target, str(entry["consent_id"]), global_rps=1.0, global_burst=1.0)
                if guard.scope.is_allowed(url):
                    return int(target["id"]), int(scan_id)
            except Exception:
                continue
        return None, None

    def ingest_capture_event(self, topic: str, payload: Mapping[str, Any]) -> None:
        if not topic.startswith(("flow.", "log.")):
            raise RuntimeErrorSafe("capture event topic is not allowed")
        self.publish(topic, payload)

    def generate_report(self, target_id: int, *, title: str = "Windeep Audit Report", template: str = "generic") -> dict[str, Any]:
        target = self._target(target_id)
        findings = self.database.list_findings(target_id=target_id, limit=5000)
        lines = [f"# {title}", "", f"Target: `{target['target']}`", "", f"Findings: **{len(findings)}**", ""]
        for finding in findings:
            lines.extend([
                f"## [{str(finding['severity']).upper()}] {finding['title']}",
                "",
                f"- Tool: `{finding.get('tool') or 'manual'}`",
                f"- Endpoint: `{finding.get('endpoint') or target['target']}`",
                f"- Type: `{finding.get('vuln_type') or 'informational'}`",
                f"- Confidence: `{float(finding.get('confidence') or 0):.2f}`",
                "",
                str(finding.get("description") or "No description recorded."),
                "",
            ])
        content = "\n".join(lines)
        now = time.time()
        encrypted = self.crypto.encrypt_text(content, aad=b"windeep:report.content")
        with self.database._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO reports(target_id,title,template,content,format,finding_ids,created_at) VALUES (?,?,?,?,?,?,?)",
                (target_id, title, template, encrypted, "markdown+aesgcm", json.dumps([f["id"] for f in findings]), now),
            )
            report_id = int(cursor.lastrowid)
        self.publish("report.generated", {"report_id": report_id, "target_id": target_id, "finding_count": len(findings)})
        return {"id": report_id, "target_id": target_id, "title": title, "template": template, "format": "markdown", "content": content, "finding_ids": [f["id"] for f in findings], "created_at": now}

    def list_reports(self, target_id: int | None = None) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            if target_id is None:
                rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 500").fetchall()
            else:
                rows = conn.execute("SELECT * FROM reports WHERE target_id = ? ORDER BY id DESC LIMIT 500", (target_id,)).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            if str(item.get("format")) == "markdown+aesgcm":
                item["content"] = self.crypto.decrypt_text(str(item["content"]), aad=b"windeep:report.content")
                item["format"] = "markdown"
            try:
                item["finding_ids"] = json.loads(item.get("finding_ids") or "[]")
            except json.JSONDecodeError:
                item["finding_ids"] = []
            output.append(item)
        return output

    def summary(self) -> dict[str, Any]:
        with self.database._connect() as conn:
            target_count = int(conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0])
            scan_count = int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
            rows = conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall()
        return {
            "targets": target_count,
            "scans": scan_count,
            "findings": {str(severity): int(count) for severity, count in rows},
            "tools": len(self.wrapper_classes),
            "test_packs": len(list_test_metadata()),
        }
