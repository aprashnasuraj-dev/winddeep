"""P0 scheduler-driven v2 scan pipeline.

This module is deliberately narrow: it wires existing Windeep engines into a
single-loop DAG without weakening preflight. It does not add signatures,
payloads, exploitation, or direct network/subprocess paths.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from app.brain.chain_builder import ChainBuilder
from app.brain.finding_ranker import FindingRanker
from app.brain.hypothesis_engine import HypothesisEngine
from app.brain.llm_client import LLMClient
from app.database import finding_fingerprint
from app.duplicates import DuplicateDetector
from app.engine.event_bus import EventBus
from app.engine.scan_context import ScanContext
from app.engine.scheduler import TaskScheduler, TaskSpec
from app.engine.tool_wrapper import ToolCancelledError
from app.security.preflight import PreFlightError

_ALLOWED_RESOURCE_CLASSES = frozenset({"recon", "active", "web3", "browser", "llm"})
_EXPORT_EVENT_TYPES = frozenset({"finding", "progress", "log", "evidence", "chain", "ranked"})
_SECRET_KEY_RE = re.compile(r"(?:authorization|cookie|set-cookie|api[_-]?key|token|password|secret|credential)", re.I)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*")
_SECRET_LITERAL_RE = re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)")


def canonical_bytes(value: Any) -> bytes:
    """Serialize stage output with stable key ordering and fixed separators."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sanitize_string(value: str) -> str:
    value = _BEARER_RE.sub("Bearer [REDACTED]", value)
    return _SECRET_LITERAL_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def sanitize_export(value: Any) -> Any:
    """Apply the P0 export-surface safety pass before SSE/broadcast output."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            text_key = str(key)
            if _SECRET_KEY_RE.search(text_key):
                result[text_key] = "[REDACTED]"
            else:
                result[text_key] = sanitize_export(value[key])
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_export(item) for item in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)} sha256={hashlib.sha256(value).hexdigest()}>"
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded task retry policy; guardrail denials are never retried."""

    max_attempts: int = 1
    base_delay: float = 0.25
    max_delay: float = 2.0
    jitter: float = 0.20

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_attempts > 8:
            raise ValueError("max_attempts must be between 1 and 8")
        if self.base_delay < 0 or self.max_delay < self.base_delay:
            raise ValueError("invalid retry delay bounds")
        if not 0.0 <= self.jitter <= 1.0:
            raise ValueError("jitter must be between 0 and 1")

    def delay(self, attempt: int) -> float:
        base = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        spread = base * self.jitter
        return max(0.0, min(self.max_delay, base + random.uniform(-spread, spread)))


Runner = Callable[[Any, Mapping[str, Any]], Awaitable[Any] | Any]


@dataclass(frozen=True, slots=True)
class PipelineNode:
    """P0 task node contract compiled onto the existing TaskScheduler."""

    id: str
    kind: str
    runner: Runner
    depends_on: tuple[str, ...] = ()
    resource_class: str = "active"
    timeout: float = 120.0
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    cancellable: bool = True
    tool_name: str | None = None
    rate_cost: float = 1.0

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("task id cannot be empty")
        if self.resource_class not in _ALLOWED_RESOURCE_CLASSES:
            raise ValueError(f"unsupported resource class: {self.resource_class}")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

    def to_task_spec(self) -> TaskSpec:
        return TaskSpec(
            self.id,
            self.runner,
            dependencies=self.depends_on,
            tool_name=self.tool_name or self.id,
            continue_on_error=True,
            rate_cost=self.rate_cost,
        )


def _resource_class(category: str) -> str:
    if category == "recon_passive":
        return "recon"
    if category == "web3":
        return "web3"
    return "active"


def build_tool_nodes(
    selected: Sequence[str],
    wrapper_classes: Mapping[str, Any],
    *,
    runner_factory: Callable[[str], Runner],
) -> list[PipelineNode]:
    """Build explicit dependencies: passive recon fans out; active/web wait for it."""
    passive_ids = tuple(
        f"tool:{name}"
        for name in sorted(selected)
        if str(getattr(wrapper_classes[name], "category", "")) == "recon_passive"
    )
    nodes: list[PipelineNode] = []
    for name in sorted(selected):
        cls = wrapper_classes[name]
        category = str(getattr(cls, "category", "utilities"))
        dependencies = passive_ids if category in {"recon_active", "web_vulns", "network"} else ()
        retries = max(0, int(getattr(cls, "retries", 0)))
        nodes.append(
            PipelineNode(
                id=f"tool:{name}",
                kind="tool",
                runner=runner_factory(name),
                depends_on=dependencies,
                resource_class=_resource_class(category),
                timeout=max(1.0, float(getattr(cls, "timeout", 120.0))),
                retry_policy=RetryPolicy(max_attempts=min(8, retries + 1)),
                cancellable=True,
                tool_name=name,
            )
        )
    return nodes


class ScanEventLog:
    """Encrypted, monotonic, replayable SSE event log."""

    def __init__(self, database: Any, crypto: Any) -> None:
        self.database = database
        self.crypto = crypto

    def ensure_schema(self) -> None:
        with self.database._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_events (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(scan_id, seq)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_replay ON scan_events(scan_id, seq)")

    def append(self, scan_id: int, event_type: str, data: Mapping[str, Any]) -> dict[str, Any]:
        if event_type not in _EXPORT_EVENT_TYPES:
            raise ValueError(f"unsupported export event type: {event_type}")
        sanitized = sanitize_export(dict(data))
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM scan_events WHERE scan_id = ?", (scan_id,)).fetchone()
            seq = int(row["seq"]) + 1
            body = {"schema": "windeep.sse.v1", "scan_id": scan_id, "seq": seq, "type": event_type, "data": sanitized}
            encrypted = self.crypto.encrypt_text(canonical_bytes(body).decode("utf-8"), aad=f"windeep:sse:{scan_id}:{seq}".encode("utf-8"))
            conn.execute(
                "INSERT INTO scan_events(scan_id, seq, event_type, schema_version, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, seq, event_type, "1", encrypted, time.time()),
            )
        return body

    def list_after(self, scan_id: int, last_seq: int, *, limit: int = 1000) -> list[dict[str, Any]]:
        if last_seq < 0:
            raise ValueError("last_seq cannot be negative")
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT seq, payload FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (scan_id, last_seq, limit),
            ).fetchall()
        events: list[dict[str, Any]] = []
        expected = last_seq + 1
        for row in rows:
            seq = int(row["seq"])
            if seq != expected:
                raise RuntimeError(f"scan event gap detected: expected {expected}, got {seq}")
            plaintext = self.crypto.decrypt_text(str(row["payload"]), aad=f"windeep:sse:{scan_id}:{seq}".encode("utf-8"))
            events.append(json.loads(plaintext))
            expected += 1
        return events


class FindingBatchWriter:
    """Persist one tool's normalized findings in one encrypted transaction."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def ensure_schema(self) -> None:
        with self.database._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
                    finding_fingerprint TEXT NOT NULL,
                    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(scan_id, tool_run_id, finding_fingerprint)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id, finding_fingerprint)")

    def persist(
        self,
        *,
        scan_id: int,
        tool_run_id: int,
        target_id: int,
        tool_name: str,
        findings: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for raw in findings:
            payload = dict(raw)
            payload["title"] = str(payload.get("title") or "Untitled finding")
            payload["severity"] = str(payload.get("severity") or "info").lower()
            payload["vuln_type"] = str(payload.get("vuln_type") or "tool_output")
            payload["tool"] = tool_name
            payload["confidence"] = float(payload.get("confidence") or 0.5)
            payload["evidence"] = dict(payload.get("evidence") or {})
            endpoint = str(payload.get("endpoint") or "<scope-bound target>")
            payload["steps"] = str(payload.get("steps") or "").strip() or (
                f"1. Run `{tool_name}` against the same authorized target and observation point `{endpoint}`.\n"
                "2. Keep the same approved scope and authentication context used by the recorded scan.\n"
                "3. Compare the resulting non-destructive observation with the stored evidence; do not add an exploitation step."
            )
            payload["fingerprint"] = finding_fingerprint(
                target_id=target_id,
                title=payload["title"],
                vuln_type=payload["vuln_type"],
                endpoint=str(payload.get("endpoint")) if payload.get("endpoint") else None,
            )
            payload["stable_json"] = canonical_bytes({key: value for key, value in payload.items() if key != "stable_json"}).decode("utf-8")
            normalized.append(payload)
        normalized.sort(key=lambda item: (item["fingerprint"], item["title"], str(item.get("endpoint") or "")))
        if not normalized:
            return []

        fingerprints = [item["fingerprint"] for item in normalized]
        placeholders = ",".join("?" for _ in fingerprints)
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_rows = conn.execute(
                f"SELECT finding_fingerprint FROM scan_findings WHERE scan_id = ? AND tool_run_id = ? AND finding_fingerprint IN ({placeholders})",
                (scan_id, tool_run_id, *fingerprints),
            ).fetchall()
            existing_keys = {str(row["finding_fingerprint"]) for row in existing_rows}

            finding_rows: list[tuple[Any, ...]] = []
            for item in normalized:
                evidence_json = json.dumps(item["evidence"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
                finding_rows.append(
                    (
                        scan_id,
                        target_id,
                        item["title"],
                        item["severity"],
                        item.get("cvss_score"),
                        item.get("cvss_vector"),
                        item["vuln_type"],
                        tool_name,
                        item.get("endpoint"),
                        self.database._enc(str(item.get("description") or ""), field="finding.description"),
                        self.database._enc(evidence_json, field="finding.evidence"),
                        self.database._enc(str(item.get("request") or ""), field="finding.request"),
                        self.database._enc(str(item.get("response") or ""), field="finding.response"),
                        self.database._enc(str(item.get("steps") or ""), field="finding.steps"),
                        self.database._enc(str(item.get("impact") or ""), field="finding.impact"),
                        self.database._enc(str(item.get("remediation") or ""), field="finding.remediation"),
                        str(item.get("status") or "new"),
                        item["fingerprint"],
                        item["confidence"],
                        now,
                        now,
                    )
                )
            conn.executemany(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, target_id, title, severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, description, evidence, request, response,
                    steps, impact, remediation, status, fingerprint, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                finding_rows,
            )
            id_rows = conn.execute(
                f"SELECT id, fingerprint FROM findings WHERE fingerprint IN ({placeholders})",
                tuple(fingerprints),
            ).fetchall()
            finding_ids = {str(row["fingerprint"]): int(row["id"]) for row in id_rows}
            scan_rows: list[tuple[Any, ...]] = []
            for item in normalized:
                finding_id = finding_ids[item["fingerprint"]]
                stored_payload = dict(item)
                stored_payload["finding_id"] = finding_id
                encrypted_payload = self.database._enc(
                    canonical_bytes(stored_payload).decode("utf-8"), field="scan_finding.payload"
                )
                scan_rows.append((scan_id, tool_run_id, item["fingerprint"], finding_id, encrypted_payload, now, now))
                item["finding_id"] = finding_id
                item["created"] = item["fingerprint"] not in existing_keys
            conn.executemany(
                """
                INSERT INTO scan_findings(scan_id, tool_run_id, finding_fingerprint, finding_id, payload, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, tool_run_id, finding_fingerprint) DO UPDATE SET
                    finding_id = excluded.finding_id,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                scan_rows,
            )
        return normalized

    def read_scan_findings(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM scan_findings WHERE scan_id = ? ORDER BY finding_fingerprint, tool_run_id",
                (scan_id,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            plaintext = self.database._dec(str(row["payload"]), field="scan_finding.payload")
            items.append(json.loads(plaintext))
        return items


class SchedulerRuntimeRegistry:
    """Own every background scan thread and its one asyncio loop."""

    @dataclass(slots=True)
    class Handle:
        cancel_event: threading.Event
        thread: threading.Thread

    def __init__(self) -> None:
        self._handles: dict[int, SchedulerRuntimeRegistry.Handle] = {}
        self._lock = threading.Lock()

    def start(self, scan_id: int, coroutine_factory: Callable[[threading.Event], Awaitable[None]]) -> None:
        cancel_event = threading.Event()
        handle_box: dict[str, SchedulerRuntimeRegistry.Handle] = {}

        def run_registered() -> None:
            try:
                with asyncio.Runner() as runner:
                    runner.run(coroutine_factory(cancel_event))
            finally:
                with self._lock:
                    current = self._handles.get(scan_id)
                    if current is handle_box.get("handle"):
                        self._handles.pop(scan_id, None)

        thread = threading.Thread(target=run_registered, daemon=True, name=f"windeep-scheduler-scan-{scan_id}")
        handle = self.Handle(cancel_event=cancel_event, thread=thread)
        handle_box["handle"] = handle
        with self._lock:
            if scan_id in self._handles:
                raise RuntimeError(f"scan {scan_id} is already registered")
            self._handles[scan_id] = handle
        thread.start()

    def stop(self, scan_id: int) -> bool:
        with self._lock:
            handle = self._handles.get(scan_id)
        if handle is None:
            return False
        handle.cancel_event.set()
        return True

    def is_active(self, scan_id: int) -> bool:
        with self._lock:
            handle = self._handles.get(scan_id)
        return bool(handle and handle.thread.is_alive())


class DependencyBlocked(RuntimeError):
    pass


def _successful_dependencies(dependencies: Mapping[str, Any]) -> dict[str, Any]:
    failures = {key: value for key, value in dependencies.items() if isinstance(value, BaseException)}
    if failures:
        detail = ", ".join(f"{key}: {value}" for key, value in sorted(failures.items()))
        raise DependencyBlocked(detail)
    return dict(dependencies)


def _host_rate_key(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    return f"host:{(parsed.hostname or target).casefold()}"


async def run_p0_scan(
    *,
    scan_id: int,
    target_row: Mapping[str, Any],
    selected: Sequence[str],
    skipped: Sequence[Mapping[str, Any]],
    mode: str,
    consent_id: str,
    tool_options: Mapping[str, Any],
    cancel_event: threading.Event,
    database: Any,
    crypto: Any,
    audit: Any,
    wrapper_classes: Mapping[str, Any],
    tools_dir: Any,
    target_scope: Callable[[dict[str, Any]], Any],
    preflight_for: Callable[..., Any],
    broadcast: Callable[[str, dict[str, Any], int | None], None],
    environment: Mapping[str, str],
) -> None:
    """Execute one v2 scan on one scheduler-owned event loop."""
    target = str(target_row["target"])
    target_id = int(target_row["id"])
    guard = preflight_for(dict(target_row), consent_id)
    context = ScanContext(
        target=target,
        target_id=target_id,
        scope=list(target_row.get("scope") or [target]),
        out_of_scope=list(target_row.get("out_of_scope") or []),
        consent_id=consent_id,
    )
    event_bus = EventBus(heartbeat_interval=60.0)
    event_log = ScanEventLog(database, crypto)
    writer = FindingBatchWriter(database)
    event_log.ensure_schema()
    writer.ensure_schema()

    def emit(event_type: str, data: Mapping[str, Any]) -> dict[str, Any]:
        event = event_log.append(scan_id, event_type, data)
        broadcast(event_type, dict(event["data"]), scan_id)
        return event

    database.update_scan(scan_id, status="running", started_at=time.time(), progress=0.0)
    emit("log", {"level": "info", "module": "v2-orchestrator", "message": f"{mode} DAG scan starting with {len(selected)} integration(s)."})

    def runner_factory(tool_name: str) -> Runner:
        cls = wrapper_classes[tool_name]
        timeout = max(1.0, float(getattr(cls, "timeout", 120.0)))
        retry_policy = RetryPolicy(max_attempts=min(8, max(0, int(getattr(cls, "retries", 0))) + 1))

        async def run_tool(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> list[dict[str, Any]]:
            _successful_dependencies(dependencies)
            if cancel_event.is_set():
                raise asyncio.CancelledError
            guard.authorize_scan(target=target, consent_id=consent_id)
            await guard.acquire_rate(_host_rate_key(target))
            scope = target_scope(dict(target_row))
            wrapper = cls(
                tools_dir=tools_dir,
                scope_validator=scope.is_allowed,
                environment=dict(environment),
                cancel_check=cancel_event.is_set,
            )
            run_id = database.create_tool_run(
                tool_name=tool_name,
                status="running",
                scan_id=scan_id,
                target_id=target_id,
                command=[tool_name, "<scope-bound target>"],
            )
            options = tool_options.get(tool_name) if isinstance(tool_options.get(tool_name), Mapping) else None
            last_error: BaseException | None = None
            for attempt in range(1, retry_policy.max_attempts + 1):
                if cancel_event.is_set():
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise asyncio.CancelledError
                try:
                    guard.authorize_scan(target=target, consent_id=consent_id)
                    await guard.acquire_rate(_host_rate_key(target))
                    findings = await asyncio.wait_for(wrapper.run(target, options=options), timeout=timeout)
                    payloads = [finding.model_dump() for finding in findings]
                    persisted = writer.persist(
                        scan_id=scan_id,
                        tool_run_id=run_id,
                        target_id=target_id,
                        tool_name=tool_name,
                        findings=payloads,
                    )
                    database.finish_tool_run(run_id, status="completed", exit_code=0, stdout_tail=f"{len(persisted)} normalized result(s)")
                    for item in persisted:
                        public = {key: value for key, value in item.items() if key != "stable_json"}
                        emit("finding", {"finding": public})
                    emit(
                        "evidence",
                        {
                            "tool": tool_name,
                            "tool_run_id": run_id,
                            "finding_count": len(persisted),
                            "fingerprints": [item["fingerprint"] for item in persisted],
                        },
                    )
                    return persisted
                except (PreFlightError, PermissionError) as exc:
                    database.finish_tool_run(run_id, status="failed", error=str(exc))
                    raise
                except ToolCancelledError:
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise asyncio.CancelledError
                except asyncio.CancelledError:
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise
                except Exception as exc:
                    last_error = exc
                    if attempt >= retry_policy.max_attempts:
                        database.finish_tool_run(run_id, status="failed", error=str(exc))
                        raise
                    await asyncio.sleep(retry_policy.delay(attempt))
            if last_error is not None:
                raise last_error
            return []

        return run_tool

    tool_nodes = build_tool_nodes(selected, wrapper_classes, runner_factory=runner_factory)
    tool_ids = tuple(node.id for node in tool_nodes)

    async def dedup_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        guard.authorize_scan(target=target, consent_id=consent_id)
        records = writer.read_scan_findings(scan_id)
        records.sort(key=lambda item: (str(item.get("fingerprint") or ""), int(item.get("finding_id") or 0)))
        detector = DuplicateDetector(database)
        primary: dict[str, dict[str, Any]] = {}
        duplicate_groups: list[dict[str, Any]] = []
        for item in records:
            fingerprint = str(item["fingerprint"])
            if fingerprint not in primary:
                primary[fingerprint] = item
                continue
            first = primary[fingerprint]
            duplicate_groups.append(
                {
                    "fingerprint": fingerprint,
                    "primary_finding_id": int(first["finding_id"]),
                    "duplicate_finding_id": int(item["finding_id"]),
                    "similarity": detector.similarity(first, item),
                }
            )
        findings = [primary[key] for key in sorted(primary)]
        return {"findings": findings, "duplicates": sorted(duplicate_groups, key=lambda row: (row["fingerprint"], row["duplicate_finding_id"]))}

    async def chain_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        dedup = values["stage:dedup"]
        findings = dedup["findings"]
        builder = ChainBuilder(LLMClient([]), event_bus, database=database)
        edges = await builder.build(findings, target_id=target_id, scan_id=scan_id)
        edge_rows = sorted((edge.model_dump() for edge in edges), key=lambda row: (row["source_finding_id"], row["target_finding_id"], row["edge_type"]))
        for edge in edge_rows:
            emit("chain", {"edge": edge})
        return {"findings": findings, "duplicates": dedup["duplicates"], "chains": edge_rows}

    async def rank_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        chained = values["stage:chain"]
        ranked = FindingRanker().rank(chained["findings"])
        rows = [
            {
                "finding_id": int(item.finding.get("finding_id") or item.finding.get("id") or 0),
                "fingerprint": str(item.finding.get("fingerprint") or ""),
                "impact": item.impact,
                "exploitability": item.exploitability,
                "confidence": item.confidence,
                "score": item.score,
            }
            for item in ranked
        ]
        rows.sort(key=lambda row: (-row["score"], row["fingerprint"], row["finding_id"]))
        for row in rows:
            emit("ranked", row)
        return {**chained, "ranked": rows}

    async def hypothesis_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        ranked = values["stage:rank"]
        engine = HypothesisEngine(LLMClient([]), event_bus, database=database)
        hypotheses = await engine.generate(ranked["findings"], scan_context, target_id=target_id, scan_id=scan_id)
        hypothesis_rows = sorted((item.model_dump() for item in hypotheses), key=lambda row: row["id"])
        return {**ranked, "hypotheses": hypothesis_rows}

    stage_nodes = [
        PipelineNode("stage:dedup", "stage", dedup_stage, depends_on=tool_ids, resource_class="active", timeout=60.0, cancellable=True, tool_name="stage:dedup"),
        PipelineNode("stage:chain", "stage", chain_stage, depends_on=("stage:dedup",), resource_class="llm", timeout=60.0, cancellable=True, tool_name="stage:chain"),
        PipelineNode("stage:rank", "stage", rank_stage, depends_on=("stage:chain",), resource_class="active", timeout=30.0, cancellable=True, tool_name="stage:rank"),
        PipelineNode("stage:hypothesis", "stage", hypothesis_stage, depends_on=("stage:rank",), resource_class="llm", timeout=60.0, cancellable=True, tool_name="stage:hypothesis"),
    ]

    scheduler = TaskScheduler(
        event_bus,
        preflight=guard,
        global_concurrency=max(1, min(8, len(tool_nodes) or 1)),
        per_tool_concurrency={"*": 1},
    )
    try:
        results = await scheduler.execute(
            [node.to_task_spec() for node in [*tool_nodes, *stage_nodes]],
            context,
            scan_id=str(scan_id),
        )
        errors = [
            {"task": task_id, "error": state.error or "task failed"}
            for task_id, state in sorted(scheduler.states.items())
            if state.status == "failed"
        ]
        final_stage = results.get("stage:hypothesis")
        final_payload = final_stage if isinstance(final_stage, Mapping) else {}
        finding_count = len(final_payload.get("findings", [])) if isinstance(final_payload, Mapping) else 0
        chain_count = len(final_payload.get("chains", [])) if isinstance(final_payload, Mapping) else 0
        ranked_count = len(final_payload.get("ranked", [])) if isinstance(final_payload, Mapping) else 0
        status = "completed_with_errors" if errors else "completed"
        summary = {
            "mode": mode,
            "tools_planned": len(selected),
            "findings": finding_count,
            "chains": chain_count,
            "ranked": ranked_count,
            "errors": errors,
            "skipped": list(skipped),
        }
        database.update_scan(scan_id, status=status, progress=100.0, finished_at=time.time(), results_summary=summary)
        emit("progress", {"progress": 100.0, "status": status, "summary": summary})
        audit.append("v2.scan.completed", {"scan_id": scan_id, "status": status, "errors": len(errors)})
    except asyncio.CancelledError:
        reason = "operator cancellation requested" if cancel_event.is_set() else "scheduler cancellation"
        database.update_scan(scan_id, status="cancelled", finished_at=time.time(), results_summary={"cancel_reason": reason})
        emit("progress", {"status": "cancelled", "reason": reason})
        audit.append("v2.scan.cancelled", {"scan_id": scan_id, "reason": reason})
    except Exception as exc:
        database.add_scan_log(scan_id, str(exc), "error", "v2-orchestrator")
        database.update_scan(scan_id, status="failed", finished_at=time.time(), results_summary={"errors": [{"task": "v2-orchestrator", "error": str(exc)}]})
        emit("progress", {"status": "failed", "error": str(exc)})
        audit.append("v2.scan.failed", {"scan_id": scan_id, "error": str(exc)})
    finally:
        await event_bus.close()
