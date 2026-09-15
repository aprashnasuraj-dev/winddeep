"""Scheduler-backed v3 execution pipeline used by the v2 HTTP scan surface."""
from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from app.engine.event_bus import EventBus
from app.engine.pipeline_store import PipelineStore
from app.engine.post_pipeline import DeterministicPostPipeline
from app.engine.scan_context import ScanContext
from app.engine.scheduler import RetryPolicy, TaskScheduler, TaskSpec
from app.engine.tool_wrapper import ToolCancelledError

_RESOURCE_BY_CATEGORY = {
    "recon_passive": "recon",
    "recon_active": "active",
    "web_vulns": "active",
    "network": "active",
    "secrets": "active",
    "mobile": "active",
    "web3": "web3",
    "utilities": "active",
}


class V3ScanPipeline:
    """Drive one scan through a single event loop and dependency-aware scheduler."""

    def __init__(
        self,
        *,
        database: Any,
        wrapper_classes: Mapping[str, type[Any]],
        tools_dir: Any,
        target_scope: Callable[[dict[str, Any]], Any],
        preflight_for: Callable[..., Any],
        runtime_environment: Callable[[], Mapping[str, str]],
        broadcast: Callable[[str, dict[str, Any], int | None], None],
    ) -> None:
        self.database = database
        self.wrapper_classes = wrapper_classes
        self.tools_dir = tools_dir
        self.target_scope = target_scope
        self.preflight_for = preflight_for
        self.runtime_environment = runtime_environment
        self.broadcast = broadcast
        self.store = PipelineStore(database)

    def run_sync(
        self,
        *,
        scan_id: int,
        target_row: dict[str, Any],
        selected: Sequence[str],
        consent_id: str,
        tool_options: Mapping[str, Any],
        cancel_event: threading.Event,
        mode: str,
        skipped: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Run exactly one asyncio event loop for the complete scan."""
        return asyncio.run(
            self.run(
                scan_id=scan_id,
                target_row=target_row,
                selected=selected,
                consent_id=consent_id,
                tool_options=tool_options,
                cancel_event=cancel_event,
                mode=mode,
                skipped=skipped,
            )
        )

    async def run(
        self,
        *,
        scan_id: int,
        target_row: dict[str, Any],
        selected: Sequence[str],
        consent_id: str,
        tool_options: Mapping[str, Any],
        cancel_event: threading.Event,
        mode: str,
        skipped: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if not selected:
            raise ValueError("scan plan contains no runnable integrations")
        guard = self.preflight_for(target_row, consent_id)
        bus = EventBus(heartbeat_interval=30.0)
        context = ScanContext(
            target=str(target_row["target"]),
            scope=tuple(str(item) for item in target_row.get("scope") or (str(target_row["target"]),)),
            out_of_scope=tuple(str(item) for item in target_row.get("out_of_scope") or ()),
            consent_id=consent_id,
            target_id=str(target_row["id"]),
            metadata={"scan_id": scan_id, "mode": mode},
        )
        scheduler = TaskScheduler(
            bus,
            preflight=guard,
            global_concurrency=min(16, max(2, len(selected))),
            per_tool_concurrency={name: max(1, int(getattr(self.wrapper_classes[name], "concurrency", 1))) for name in selected},
        )
        total = len(selected)
        completed = 0
        progress_lock = asyncio.Lock()

        async def execute_tool(tool_name: str, _context: ScanContext, _deps: Mapping[str, Any]) -> list[dict[str, Any]]:
            nonlocal completed
            if cancel_event.is_set():
                raise asyncio.CancelledError()
            cls = self.wrapper_classes[tool_name]
            scope = self.target_scope(target_row)
            wrapper = cls(
                tools_dir=self.tools_dir,
                scope_validator=scope.is_allowed,
                environment=dict(self.runtime_environment()),
                cancel_check=cancel_event.is_set,
            )
            run_id = self.database.create_tool_run(
                tool_name=tool_name,
                status="running",
                scan_id=scan_id,
                target_id=int(target_row["id"]),
                command=[tool_name, "<scope-bound target>"],
            )
            self._emit(scan_id, "log", {"level": "info", "module": tool_name, "message": f"Starting {tool_name}"})
            try:
                raw_findings = await wrapper.run(
                    str(target_row["target"]),
                    options=tool_options.get(tool_name) if isinstance(tool_options.get(tool_name), Mapping) else None,
                )
                normalized: list[dict[str, Any]] = []
                for finding in raw_findings:
                    payload = finding.model_dump()
                    evidence = dict(payload.get("evidence") or {})
                    evidence.setdefault("windeep", {})
                    if isinstance(evidence["windeep"], dict):
                        evidence["windeep"].update(
                            {
                                "scan_id": scan_id,
                                "tool_run_id": run_id,
                                "tool": tool_name,
                                "target": str(target_row["target"]),
                            }
                        )
                    steps = str(payload.get("steps") or "").strip() or (
                        f"Run {tool_name} against the same authorized target `{target_row['target']}` and compare the resulting observation with evidence from tool run {run_id}."
                    )
                    payload.update({"evidence": evidence, "steps": steps})
                    normalized.append(payload)
                persisted = self.store.upsert_tool_findings(
                    target_id=int(target_row["id"]),
                    scan_id=scan_id,
                    tool_run_id=run_id,
                    tool_name=tool_name,
                    findings=normalized,
                )
                for finding in persisted:
                    safe = self._safe_finding_event(finding)
                    self._emit(scan_id, "finding", {"finding": safe})
                    self._emit(
                        scan_id,
                        "evidence",
                        {
                            "finding_id": int(finding["id"]),
                            "tool_run_id": run_id,
                            "finding_fingerprint": finding["finding_fingerprint"],
                            "encrypted_at_rest": hasattr(self.database, "_enc"),
                        },
                    )
                self.database.finish_tool_run(
                    run_id,
                    status="completed",
                    exit_code=0,
                    stdout_tail=f"{len(persisted)} normalized result(s)",
                )
                return persisted
            except ToolCancelledError:
                self.database.finish_tool_run(run_id, status="cancelled", error="cancelled by user")
                raise asyncio.CancelledError()
            except asyncio.CancelledError:
                self.database.finish_tool_run(run_id, status="cancelled", error="cancelled by user")
                raise
            except Exception as exc:
                self.database.finish_tool_run(run_id, status="failed", error=str(exc))
                self.database.add_scan_log(scan_id, str(exc), "error", tool_name)
                self._emit(scan_id, "log", {"level": "error", "module": tool_name, "message": str(exc)})
                raise
            finally:
                async with progress_lock:
                    completed += 1
                    progress = round((completed / total) * 80.0, 2)
                    self.database.update_scan(scan_id, progress=progress)
                    self._emit(scan_id, "progress", {"progress": progress, "status": "running"})

        passive_ids = tuple(f"tool:{name}" for name in selected if str(getattr(self.wrapper_classes[name], "category", "")) == "recon_passive")
        tasks: list[TaskSpec] = []
        for tool_name in selected:
            cls = self.wrapper_classes[tool_name]
            category = str(getattr(cls, "category", "utilities"))
            depends_on = () if category == "recon_passive" else passive_ids

            async def runner(scan_context: ScanContext, deps: Mapping[str, Any], *, _name: str = tool_name) -> list[dict[str, Any]]:
                return await execute_tool(_name, scan_context, deps)

            tasks.append(
                TaskSpec(
                    id=f"tool:{tool_name}",
                    kind="tool",
                    runner=runner,
                    depends_on=depends_on,
                    tool_name=tool_name,
                    resource_class=_RESOURCE_BY_CATEGORY.get(category, "active"),
                    timeout=max(1.0, float(getattr(cls, "timeout", 120.0))),
                    retry_policy=RetryPolicy(max_attempts=min(3, max(1, int(getattr(cls, "retries", 0)) + 1))),
                    cancellable=True,
                )
            )

        self.database.update_scan(scan_id, status="running", started_at=time.time(), progress=0.0)
        self._emit(
            scan_id,
            "log",
            {"level": "info", "module": "v3-orchestrator", "message": f"{mode} scan starting with {len(tasks)} integration(s)."},
        )
        try:
            task_results = await scheduler.execute(tasks, context, scan_id=str(scan_id), raise_on_error=False)
        except asyncio.CancelledError:
            cancel_event.set()
            self.database.update_scan(scan_id, status="cancelled", finished_at=time.time())
            self._emit(scan_id, "progress", {"status": "cancelled", "reason": "operator cancellation"})
            raise

        if cancel_event.is_set() or any(state.status == "cancelled" for state in scheduler.states.values()):
            self.database.update_scan(scan_id, status="cancelled", finished_at=time.time())
            self._emit(scan_id, "progress", {"status": "cancelled", "reason": "operator cancellation"})
            return {"status": "cancelled", "findings": 0, "errors": []}

        findings = self.store.list_tool_findings(scan_id=scan_id)
        post = DeterministicPostPipeline(self.database, bus)
        stage_output = await post.run(
            findings,
            context,
            target_id=int(target_row["id"]),
            scan_id=scan_id,
        )
        for edge in stage_output["chains"]:
            self._emit(scan_id, "chain", {"edge": edge})
        for ranked in stage_output["ranked"]:
            self._emit(scan_id, "ranked", ranked)

        errors = [
            {"task": name, "error": state.error or state.status}
            for name, state in sorted(scheduler.states.items())
            if state.status in {"failed", "blocked"}
        ]
        status = "completed_with_errors" if errors else "completed"
        summary = {
            "mode": mode,
            "tools_planned": len(tasks),
            "findings": len(stage_output["deduplicated"]),
            "chains": len(stage_output["chains"]),
            "ranked": len(stage_output["ranked"]),
            "hypotheses": len(stage_output["hypotheses"]),
            "errors": errors,
            "skipped": [dict(item) for item in skipped],
        }
        self.database.update_scan(
            scan_id,
            status=status,
            progress=100.0,
            finished_at=time.time(),
            results_summary=summary,
        )
        self._emit(scan_id, "progress", {"progress": 100.0, "status": status, "summary": summary})
        await bus.close()
        return {"status": status, "summary": summary, "task_results": task_results, "stages": stage_output}

    def _emit(self, scan_id: int, event_type: str, payload: Mapping[str, Any]) -> None:
        event = self.store.append_scan_event(scan_id, event_type, dict(payload), schema_version="windeep.sse.v1")
        wire = dict(payload)
        wire["_sse_schema"] = event["schema_version"]
        wire["_sse_seq"] = event["seq"]
        self.broadcast(event_type, wire, scan_id)

    @staticmethod
    def _safe_finding_event(finding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: finding.get(key)
            for key in (
                "id",
                "title",
                "severity",
                "vuln_type",
                "tool",
                "endpoint",
                "confidence",
                "finding_fingerprint",
                "tool_run_id",
            )
        }
