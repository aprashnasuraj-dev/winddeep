"""Unified v3 stage coordinator layered over the frozen P0-P8 components."""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any

V3_STAGE_ORDER = (
    "scope_consent",
    "recon",
    "engines",
    "dedup",
    "chain",
    "rank",
    "hypothesis",
    "handling",
    "bundle_close",
    "verification",
    "report",
    "export_submission",
)


class V3PipelineCoordinator:
    """Persist stage boundaries and emit audit/SSE transition records."""

    def __init__(self, *, database: Any, audit: Any, event_sink: Callable[[str, dict[str, Any]], None]) -> None:
        self.database = database
        self.audit = audit
        self.event_sink = event_sink

    def _enc(self, payload: Mapping[str, Any], *, field: str) -> str:
        raw = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        encoder = getattr(self.database, "_enc", None)
        if not callable(encoder):
            raise RuntimeError("v3 pipeline checkpoints require encrypted database fields")
        return encoder(raw, field=field)

    def _dec(self, value: str, *, field: str) -> dict[str, Any]:
        decoder = getattr(self.database, "_dec", None)
        if not callable(decoder):
            raise RuntimeError("v3 pipeline checkpoints require encrypted database fields")
        return json.loads(decoder(value, field=field) or "{}")

    def _checkpoint(self, scan_id: int, stage: str) -> dict[str, Any] | None:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM v3_pipeline_checkpoint WHERE scan_id = ? AND stage = ?",
                (int(scan_id), stage),
            ).fetchone()
        return None if row is None else self._dec(str(row["payload"]), field="v3.pipeline_checkpoint.payload")

    def _transition(self, scan_id: int, stage: str, status: str, payload: Mapping[str, Any]) -> None:
        body = {"stage": stage, "status": status, **dict(payload)}
        encrypted = self._enc(body, field="v3.scan_transition.payload")
        now = time.time()
        with self.database._connect() as conn:
            conn.execute(
                "INSERT INTO v3_scan_transitions(scan_id, stage, status, payload, created_at) VALUES (?, ?, ?, ?, ?)",
                (int(scan_id), stage, status, encrypted, now),
            )
        self.audit.append(
            "v3.pipeline.transition",
            {"scan_id": int(scan_id), "stage": stage, "status": status},
        )
        self.event_sink("progress", body)

    def run(
        self,
        *,
        scan_id: int,
        stages: Mapping[str, Callable[[], Any]],
        cancel_check: Callable[[], bool],
        budget: Any | None = None,
    ) -> dict[str, Any]:
        missing = [stage for stage in V3_STAGE_ORDER if stage not in stages]
        if missing:
            raise ValueError(f"missing v3 pipeline stage callback(s): {', '.join(missing)}")
        outputs: dict[str, Any] = {}
        for stage in V3_STAGE_ORDER:
            if cancel_check():
                self._transition(scan_id, stage, "cancelled", {})
                return {"status": "cancelled", "last_stage": stage, "outputs": outputs}
            if budget is not None:
                budget.check_wall_clock()
            committed = self._checkpoint(scan_id, stage)
            if committed is not None:
                outputs[stage] = committed
                self._transition(scan_id, stage, "resumed", {"committed": True})
                continue
            self._transition(scan_id, stage, "started", {})
            result = stages[stage]()
            payload = dict(result) if isinstance(result, Mapping) else {"result": result}
            encrypted = self._enc(payload, field="v3.pipeline_checkpoint.payload")
            with self.database._connect() as conn:
                conn.execute(
                    "INSERT INTO v3_pipeline_checkpoint(scan_id, stage, payload, committed_at) VALUES (?, ?, ?, ?)",
                    (int(scan_id), stage, encrypted, time.time()),
                )
            outputs[stage] = payload
            self._transition(scan_id, stage, "completed", {"committed": True})
        return {"status": "completed", "last_stage": V3_STAGE_ORDER[-1], "outputs": outputs}
