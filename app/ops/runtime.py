"""P6 operational hygiene: durable checkpoints, budgets, logs, backpressure, cleanup."""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

_STAGE_ORDER = ("capture", "dedup", "chain", "rank", "hypothesis", "bundle", "report", "complete")
_SECRET_KEY = re.compile(r"authorization|cookie|token|password|passwd|secret|api[_-]?key|credential|session", re.I)
_SECRET_VALUE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/]+=*|\b(token|password|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+")


class BudgetExceeded(RuntimeError):
    """Raised when a persisted per-scan or per-tool budget is exhausted."""


class CleanupError(RuntimeError):
    """Raised when scan-end cleanup invariants are violated."""


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY.search(str(key)) else _redact(child)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub(lambda match: (match.group(1) if match.lastindex and match.group(1) else "") + "[REDACTED]", value)
    return value


class ScanResumeCoordinator:
    """Persist idempotent stage boundaries so a fresh process can resume safely."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def _stage_row(self, scan_id: int, stage: str):
        with self.database._connect() as conn:
            return conn.execute(
                "SELECT stage, payload, committed_at FROM scan_checkpoints WHERE scan_id = ? AND stage = ? ORDER BY id DESC LIMIT 1",
                (scan_id, stage),
            ).fetchone()

    def _decode_payload(self, value: str) -> dict[str, Any]:
        plaintext = self.database._dec(value, field="scan_checkpoint.payload")
        return json.loads(plaintext or "{}")

    def commit(self, scan_id: int, stage: str, *, payload: Mapping[str, Any] | None = None) -> None:
        if stage not in _STAGE_ORDER:
            raise ValueError(f"unknown stage: {stage}")
        current = self.state(scan_id)
        if current["last_stage"] is not None:
            current_idx = _STAGE_ORDER.index(str(current["last_stage"]))
            new_idx = _STAGE_ORDER.index(stage)
            if new_idx < current_idx:
                if self._stage_row(scan_id, stage) is not None:
                    return
                raise ValueError(f"stage regression refused: {current['last_stage']} -> {stage}")
            if new_idx == current_idx:
                return
        encoded = json.dumps(dict(payload or {}), sort_keys=True, separators=(",", ":"), default=str)
        encrypted = self.database._enc(encoded, field="scan_checkpoint.payload")
        with self.database._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scan_checkpoints(scan_id, stage, payload, committed_at) VALUES (?, ?, ?, ?)",
                (scan_id, stage, encrypted, time.time()),
            )

    def run_stage(self, scan_id: int, stage: str, callback: Callable[[], Any]) -> Any:
        """Execute one stage once; a committed stage is returned instead of rerun."""
        if stage not in _STAGE_ORDER:
            raise ValueError(f"unknown stage: {stage}")
        row = self._stage_row(scan_id, stage)
        if row is not None:
            return self._decode_payload(str(row["payload"]))
        result = callback()
        payload = dict(result) if isinstance(result, Mapping) else {"result": result}
        self.commit(scan_id, stage, payload=payload)
        return result

    def state(self, scan_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT stage, payload, committed_at FROM scan_checkpoints WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
        if row is None:
            return {"last_stage": None, "next_stage": _STAGE_ORDER[0], "payload": {}, "committed_at": None}
        stage = str(row["stage"])
        idx = _STAGE_ORDER.index(stage)
        return {
            "last_stage": stage,
            "next_stage": _STAGE_ORDER[idx + 1] if idx + 1 < len(_STAGE_ORDER) else None,
            "payload": self._decode_payload(str(row["payload"])),
            "committed_at": float(row["committed_at"]),
        }


class BudgetLedger:
    """Persist and enforce per-scan artifact/token/wall-clock plus per-tool budgets."""

    def __init__(
        self,
        database: Any,
        audit: Any,
        *,
        scan_id: int,
        wall_clock_seconds: float,
        artifact_bytes: int,
        llm_tokens: int,
        per_tool_seconds: float = 300.0,
    ) -> None:
        if wall_clock_seconds <= 0 or artifact_bytes < 0 or llm_tokens < 0 or per_tool_seconds <= 0:
            raise ValueError("budget limits must be positive/non-negative")
        self.database = database
        self.audit = audit
        self.scan_id = scan_id
        self.per_tool_seconds = float(per_tool_seconds)
        now = time.time()
        with self.database._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO scan_budgets(
                    scan_id, started_at, wall_clock_seconds, artifact_byte_limit,
                    artifact_bytes_used, llm_token_limit, llm_tokens_used,
                    per_tool_seconds, status
                ) VALUES (?, ?, ?, ?, 0, ?, 0, ?, 'active')
                """,
                (scan_id, now, float(wall_clock_seconds), int(artifact_bytes), int(llm_tokens), self.per_tool_seconds),
            )

    def _exceed(self, kind: str, requested: int | float, limit: int | float, *, tool_run_id: int | None = None) -> None:
        with self.database._connect() as conn:
            conn.execute("UPDATE scan_budgets SET status = 'incomplete' WHERE scan_id = ?", (self.scan_id,))
            if tool_run_id is not None:
                conn.execute(
                    "UPDATE scan_tool_budgets SET status = 'incomplete' WHERE scan_id = ? AND tool_run_id = ?",
                    (self.scan_id, int(tool_run_id)),
                )
        data = {"scan_id": self.scan_id, "kind": kind, "requested": requested, "limit": limit}
        if tool_run_id is not None:
            data["tool_run_id"] = int(tool_run_id)
        self.audit.append("p6.budget.exceeded", data)
        raise BudgetExceeded(f"scan {self.scan_id} exceeded {kind} budget")

    def consume_artifact(self, size: int) -> None:
        if size < 0:
            raise ValueError("artifact size cannot be negative")
        with self.database._connect() as conn:
            row = conn.execute("SELECT artifact_bytes_used, artifact_byte_limit FROM scan_budgets WHERE scan_id = ?", (self.scan_id,)).fetchone()
            if row is None:
                raise BudgetExceeded("scan budget row is missing")
            used, limit = int(row["artifact_bytes_used"]), int(row["artifact_byte_limit"])
            requested = used + size
            if requested <= limit:
                conn.execute("UPDATE scan_budgets SET artifact_bytes_used = ? WHERE scan_id = ?", (requested, self.scan_id))
                return
        self._exceed("artifact_bytes", requested, limit)

    def consume_llm(self, tokens: int) -> None:
        if tokens < 0:
            raise ValueError("LLM token count cannot be negative")
        with self.database._connect() as conn:
            row = conn.execute("SELECT llm_tokens_used, llm_token_limit FROM scan_budgets WHERE scan_id = ?", (self.scan_id,)).fetchone()
            if row is None:
                raise BudgetExceeded("scan budget row is missing")
            used, limit = int(row["llm_tokens_used"]), int(row["llm_token_limit"])
            requested = used + tokens
            if requested <= limit:
                conn.execute("UPDATE scan_budgets SET llm_tokens_used = ? WHERE scan_id = ?", (requested, self.scan_id))
                return
        self._exceed("llm_tokens", requested, limit)

    def consume_tool_time(self, *, tool_run_id: int, elapsed_seconds: float) -> None:
        if elapsed_seconds < 0:
            raise ValueError("tool elapsed time cannot be negative")
        with self.database._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scan_tool_budgets(scan_id, tool_run_id, elapsed_seconds, limit_seconds, status) VALUES (?, ?, 0, ?, 'active')",
                (self.scan_id, int(tool_run_id), self.per_tool_seconds),
            )
            row = conn.execute(
                "SELECT elapsed_seconds, limit_seconds FROM scan_tool_budgets WHERE scan_id = ? AND tool_run_id = ?",
                (self.scan_id, int(tool_run_id)),
            ).fetchone()
            used, limit = float(row["elapsed_seconds"]), float(row["limit_seconds"])
            requested = used + float(elapsed_seconds)
            if requested <= limit:
                conn.execute(
                    "UPDATE scan_tool_budgets SET elapsed_seconds = ? WHERE scan_id = ? AND tool_run_id = ?",
                    (requested, self.scan_id, int(tool_run_id)),
                )
                return
        self._exceed("tool_wall_clock", requested, limit, tool_run_id=tool_run_id)

    def check_wall_clock(self) -> None:
        with self.database._connect() as conn:
            row = conn.execute("SELECT started_at, wall_clock_seconds FROM scan_budgets WHERE scan_id = ?", (self.scan_id,)).fetchone()
        if row is None:
            raise BudgetExceeded("scan budget row is missing")
        elapsed = time.time() - float(row["started_at"])
        limit = float(row["wall_clock_seconds"])
        if elapsed > limit:
            self._exceed("wall_clock_seconds", elapsed, limit)

    def mark_complete(self) -> None:
        snapshot = self.snapshot()
        if str(snapshot["status"]) != "active":
            raise BudgetExceeded(f"scan {self.scan_id} budget is not active")
        with self.database._connect() as conn:
            conn.execute("UPDATE scan_budgets SET status = 'complete' WHERE scan_id = ?", (self.scan_id,))
            conn.execute("UPDATE scan_tool_budgets SET status = 'complete' WHERE scan_id = ? AND status = 'active'", (self.scan_id,))

    def snapshot(self) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM scan_budgets WHERE scan_id = ?", (self.scan_id,)).fetchone()
        if row is None:
            raise BudgetExceeded("scan budget row is missing")
        return dict(row)

    def tool_snapshot(self, tool_run_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_tool_budgets WHERE scan_id = ? AND tool_run_id = ?",
                (self.scan_id, int(tool_run_id)),
            ).fetchone()
        if row is None:
            raise BudgetExceeded(f"tool budget row is missing: {tool_run_id}")
        return dict(row)


class StructuredEventLogger:
    """Persist redacted structured operational events in encrypted form."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def log(self, *, scan_id: int, task_id: str | None, actor: str, event: str, payload: Mapping[str, Any]) -> None:
        if not actor.strip() or not event.strip():
            raise ValueError("actor and event are required")
        safe = _redact(dict(payload))
        encoded = json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)
        encrypted = self.database._enc(encoded, field="structured_log.payload")
        with self.database._connect() as conn:
            conn.execute(
                "INSERT INTO structured_logs(scan_id, task_id, actor, event, payload, wall_time, monotonic_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, task_id, actor, event, encrypted, time.time(), time.monotonic()),
            )

    def list(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute("SELECT * FROM structured_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,)).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            plain = self.database._dec(item["payload"], field="structured_log.payload")
            item["payload"] = json.loads(plain or "{}")
            output.append(item)
        return output


class BackpressureChannel:
    """Bounded non-blocking producer channel for SSE/log fanout."""

    def __init__(self, *, max_items: int = 256) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=max_items)
        self._capacity = max_items
        self._dropped = 0

    def publish(self, item: Any) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            return False

    async def receive(self) -> Any:
        return await self._queue.get()

    def stats(self) -> dict[str, int]:
        return {"queued": self._queue.qsize(), "dropped": self._dropped, "capacity": self._capacity}


class DurableFanout:
    """Persist evidence/events first, then attempt non-blocking UI delivery."""

    def __init__(self, *, persist: Callable[[Mapping[str, Any]], Any], channel: BackpressureChannel) -> None:
        if not callable(persist):
            raise TypeError("persist must be callable")
        self.persist = persist
        self.channel = channel

    def publish(self, event: Mapping[str, Any]) -> dict[str, Any]:
        durable_id = self.persist(dict(event))
        ui_queued = self.channel.publish(dict(event))
        return {"durable_id": durable_id, "ui_queued": ui_queued}


class CleanupSweeper:
    """Actively remove scan temp/orphan state, then assert the cleanup invariant."""

    def __init__(
        self,
        encrypted_tmp: str | Path,
        *,
        orphan_chunk_check: Callable[[], Any] | None = None,
        orphan_chunk_sweep: Callable[[], Any] | None = None,
    ) -> None:
        self.encrypted_tmp = Path(encrypted_tmp).resolve()
        self.orphan_chunk_check = orphan_chunk_check
        self.orphan_chunk_sweep = orphan_chunk_sweep
        self._temps: set[Path] = set()
        self._processes: list[Any] = []

    def register_temp(self, path: str | Path) -> None:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.encrypted_tmp):
            raise CleanupError("temporary file is outside encrypted-tmp namespace")
        self._temps.add(resolved)

    def register_process(self, process: Any) -> None:
        self._processes.append(process)

    def sweep(self, *, process_timeout: float = 2.0) -> dict[str, int]:
        if process_timeout < 0:
            raise ValueError("process_timeout cannot be negative")
        removed = 0
        for path in sorted(self._temps):
            if path.exists():
                if path.is_dir():
                    raise CleanupError(f"registered temporary path is a directory: {path}")
                path.unlink()
                removed += 1

        stopped = 0
        for process in self._processes:
            if getattr(process, "returncode", None) is not None:
                continue
            terminate = getattr(process, "terminate", None)
            if callable(terminate):
                terminate()
            wait = getattr(process, "wait", None)
            try:
                if callable(wait):
                    wait(timeout=process_timeout)
            except (TimeoutError, asyncio.TimeoutError):
                kill = getattr(process, "kill", None)
                if callable(kill):
                    kill()
                if callable(wait):
                    wait(timeout=process_timeout)
            if getattr(process, "returncode", None) is None:
                raise CleanupError("process did not stop during cleanup")
            stopped += 1

        orphan_before = [] if self.orphan_chunk_check is None else list(self.orphan_chunk_check())
        if orphan_before and self.orphan_chunk_sweep is not None:
            self.orphan_chunk_sweep()
        self.assert_clean()
        return {
            "temp_files_removed": removed,
            "processes_stopped": stopped,
            "orphan_chunks_removed": len(orphan_before),
        }

    def assert_clean(self) -> None:
        leaked = sorted(str(path) for path in self._temps if path.exists())
        running = [proc for proc in self._processes if getattr(proc, "returncode", None) is None]
        orphan_chunks = [] if self.orphan_chunk_check is None else list(self.orphan_chunk_check())
        if leaked or running or orphan_chunks:
            raise CleanupError(
                f"cleanup invariant failed: temp_files={leaked}, running_processes={len(running)}, orphan_chunks={len(orphan_chunks)}"
            )
