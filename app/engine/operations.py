"""P6 operational durability controls for Windeep v3."""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SECRET_KEYS = ("authorization", "cookie", "set-cookie", "token", "secret", "password", "api_key", "apikey", "credential")


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            text = str(key)
            if any(marker in text.casefold() for marker in _SECRET_KEYS):
                output[text] = "[REDACTED]"
            else:
                output[text] = _redact(item)
        return output
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


class BudgetExceeded(RuntimeError):
    """Raised when a configured scan budget is exhausted."""


@dataclass(frozen=True, slots=True)
class ScanBudgets:
    wall_seconds: float
    artifact_bytes: int
    llm_tokens: int

    def __post_init__(self) -> None:
        if self.wall_seconds <= 0:
            raise ValueError("wall_seconds must be positive")
        if self.artifact_bytes < 0 or self.llm_tokens < 0:
            raise ValueError("artifact_bytes and llm_tokens cannot be negative")


class ScanBudgetGuard:
    """Track bounded resources and audit every denial."""

    def __init__(
        self,
        *,
        scan_id: int,
        budgets: ScanBudgets,
        audit: Any,
        monotonic: Callable[[], float] = time.monotonic,
        started_monotonic: float | None = None,
    ) -> None:
        self.scan_id = int(scan_id)
        self.budgets = budgets
        self.audit = audit
        self.monotonic = monotonic
        self.started_monotonic = monotonic() if started_monotonic is None else float(started_monotonic)
        self.artifact_bytes = 0
        self.llm_tokens = 0

    def _deny(self, budget: str, *, used: float, limit: float, requested: float = 0.0) -> None:
        self.audit.append(
            "scan.budget_exceeded",
            {
                "scan_id": self.scan_id,
                "budget": budget,
                "used": used,
                "limit": limit,
                "requested": requested,
            },
        )
        raise BudgetExceeded(f"scan {self.scan_id} exceeded {budget}: used={used}, limit={limit}, requested={requested}")

    def check_wall(self) -> float:
        elapsed = max(0.0, float(self.monotonic()) - self.started_monotonic)
        if elapsed > self.budgets.wall_seconds:
            self._deny("wall_seconds", used=elapsed, limit=self.budgets.wall_seconds)
        return elapsed

    def charge_artifact(self, count: int) -> int:
        if count < 0:
            raise ValueError("artifact charge cannot be negative")
        self.check_wall()
        proposed = self.artifact_bytes + int(count)
        if proposed > self.budgets.artifact_bytes:
            self._deny("artifact_bytes", used=self.artifact_bytes, limit=self.budgets.artifact_bytes, requested=count)
        self.artifact_bytes = proposed
        return self.artifact_bytes

    def charge_llm(self, tokens: int) -> int:
        if tokens < 0:
            raise ValueError("LLM token charge cannot be negative")
        self.check_wall()
        proposed = self.llm_tokens + int(tokens)
        if proposed > self.budgets.llm_tokens:
            self._deny("llm_tokens", used=self.llm_tokens, limit=self.budgets.llm_tokens, requested=tokens)
        self.llm_tokens = proposed
        return self.llm_tokens

    def snapshot(self) -> dict[str, Any]:
        return {
            "wall_seconds": self.check_wall(),
            "artifact_bytes": self.artifact_bytes,
            "llm_tokens": self.llm_tokens,
            "limits": {
                "wall_seconds": self.budgets.wall_seconds,
                "artifact_bytes": self.budgets.artifact_bytes,
                "llm_tokens": self.budgets.llm_tokens,
            },
        }


class StageCheckpointStore:
    """Append-only encrypted stage checkpoints used for deterministic resume."""

    def __init__(self, database: Any, audit: Any) -> None:
        self.database = database
        self.audit = audit

    def commit(self, *, scan_id: int, stage: str, state: Mapping[str, Any]) -> int:
        stage_name = str(stage).strip()
        if not stage_name:
            raise ValueError("checkpoint stage cannot be empty")
        canonical = _canonical(dict(state))
        encoder = getattr(self.database, "_enc", None)
        payload = encoder(canonical, field="scan_checkpoint.state") if callable(encoder) else canonical
        with self.database._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_checkpoints(scan_id, stage, state, committed_at) VALUES (?, ?, ?, ?)",
                (int(scan_id), stage_name, payload, time.time()),
            )
            checkpoint_id = int(cursor.lastrowid)
        self.audit.append("scan.checkpoint_committed", {"scan_id": int(scan_id), "stage": stage_name, "checkpoint_id": checkpoint_id})
        return checkpoint_id

    def last(self, scan_id: int) -> dict[str, Any] | None:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_checkpoints WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (int(scan_id),),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        decoder = getattr(self.database, "_dec", None)
        text = decoder(str(item["state"]), field="scan_checkpoint.state") if callable(decoder) else str(item["state"])
        item["state"] = json.loads(text)
        return item

    def resume_after(self, scan_id: int, stages: Sequence[str]) -> str | None:
        ordered = [str(item) for item in stages]
        if not ordered:
            return None
        last = self.last(scan_id)
        if last is None:
            return ordered[0]
        stage = str(last["stage"])
        if stage not in ordered:
            raise ValueError(f"checkpoint stage is not in current pipeline: {stage}")
        index = ordered.index(stage) + 1
        return ordered[index] if index < len(ordered) else None


class BackpressureBuffer:
    """Bounded async buffer that drops the oldest event rather than blocking producers."""

    def __init__(self, *, max_items: int = 256) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=max_items)
        self.dropped = 0

    def publish_nowait(self, item: Any) -> bool:
        if self.queue.full():
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
        try:
            self.queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            return False

    async def get(self) -> Any:
        return await self.queue.get()


class StructuredScanLogger:
    """Redaction-aware structured operational log persisted per scan/task/actor."""

    def __init__(self, database: Any, audit: Any) -> None:
        self.database = database
        self.audit = audit

    def emit(self, *, scan_id: int, task_id: str, actor: str, event: str, data: Mapping[str, Any]) -> dict[str, Any]:
        clean = _redact(dict(data))
        record = {
            "scan_id": int(scan_id),
            "task_id": str(task_id),
            "actor": str(actor),
            "event": str(event),
            "data": clean,
            "created_at": time.time(),
        }
        canonical = _canonical(record)
        encoder = getattr(self.database, "_enc", None)
        payload = encoder(canonical, field="scan_operation.payload") if callable(encoder) else canonical
        with self.database._connect() as conn:
            conn.execute(
                "INSERT INTO scan_operations(scan_id, task_id, actor, event, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (record["scan_id"], record["task_id"], record["actor"], record["event"], payload, record["created_at"]),
            )
        self.audit.append("scan.operation", {"scan_id": record["scan_id"], "task_id": record["task_id"], "actor": record["actor"], "event": record["event"]})
        return record


class ScanSweeper:
    """Detect plaintext temp residue and relational evidence orphans."""

    def __init__(self, database: Any, audit: Any, *, encrypted_tmp: str | Path) -> None:
        self.database = database
        self.audit = audit
        self.encrypted_tmp = Path(encrypted_tmp)

    def inspect(self, *, scan_id: int) -> dict[str, Any]:
        plaintext = []
        if self.encrypted_tmp.exists():
            plaintext = sorted(str(path) for path in self.encrypted_tmp.rglob("*") if path.is_file())
        with self.database._connect() as conn:
            orphan_chunks = [
                int(row["artifact_id"])
                for row in conn.execute(
                    "SELECT DISTINCT c.artifact_id FROM artifact_chunks c LEFT JOIN artifacts a ON a.id = c.artifact_id WHERE a.id IS NULL ORDER BY c.artifact_id"
                ).fetchall()
            ]
            orphan_flow_evidence = [
                int(row["flow_id"])
                for row in conn.execute(
                    "SELECT e.flow_id FROM flow_evidence e LEFT JOIN flows f ON f.id = e.flow_id WHERE f.id IS NULL ORDER BY e.flow_id"
                ).fetchall()
            ]
        result = {
            "scan_id": int(scan_id),
            "plaintext_temp_files": plaintext,
            "orphan_artifact_chunks": orphan_chunks,
            "orphan_flow_evidence": orphan_flow_evidence,
        }
        result["ok"] = not plaintext and not orphan_chunks and not orphan_flow_evidence
        if not result["ok"]:
            self.audit.append("scan.sweeper_failed", result)
        else:
            self.audit.append("scan.sweeper_clean", {"scan_id": int(scan_id)})
        return result


__all__ = [
    "BackpressureBuffer",
    "BudgetExceeded",
    "ScanBudgetGuard",
    "ScanBudgets",
    "ScanSweeper",
    "StageCheckpointStore",
    "StructuredScanLogger",
]
