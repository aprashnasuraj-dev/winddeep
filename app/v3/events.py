"""Persistent v3 SSE publisher on the frozen ``windeep.sse.v1`` contract.

P0's event log schema is frozen for v3.0.0. This adapter adds the v3 event
vocabulary without modifying P0 internals: it writes the same encrypted
``scan_events`` rows, keeps the same monotonic sequence, and reuses P0 replay.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from app.v2_pipeline import ScanEventLog, canonical_bytes, sanitize_export
from app.v3.contracts import V3_EVENT_TYPES


class V3EventPublisher:
    """Emit all v3 event types into P0's gap-free encrypted replay log."""

    def __init__(
        self,
        database: Any,
        crypto: Any,
        audit: Any,
        *,
        broadcast: Callable[[str, dict[str, Any], int | None], None],
    ) -> None:
        self.database = database
        self.crypto = crypto
        self.audit = audit
        self.broadcast = broadcast
        self.replay = ScanEventLog(database, crypto)
        self.replay.ensure_schema()

    def emit(self, scan_id: int, event_type: str, data: Mapping[str, Any]) -> dict[str, Any]:
        if event_type not in V3_EVENT_TYPES:
            raise ValueError(f"unsupported v3 event type: {event_type}")
        sanitized = sanitize_export(dict(data))
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS seq FROM scan_events WHERE scan_id = ?",
                (int(scan_id),),
            ).fetchone()
            seq = int(row["seq"]) + 1
            body = {
                "schema": "windeep.sse.v1",
                "scan_id": int(scan_id),
                "seq": seq,
                "type": event_type,
                "data": sanitized,
            }
            encrypted = self.crypto.encrypt_text(
                canonical_bytes(body).decode("utf-8"),
                aad=f"windeep:sse:{int(scan_id)}:{seq}".encode("utf-8"),
            )
            conn.execute(
                "INSERT INTO scan_events(scan_id, seq, event_type, schema_version, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (int(scan_id), seq, event_type, "1", encrypted, time.time()),
            )
        self.audit.append(
            "v3.sse.emitted",
            {"scan_id": int(scan_id), "seq": seq, "type": event_type, "schema": "windeep.sse.v1"},
        )
        self.broadcast(event_type, dict(sanitized), int(scan_id))
        return body

    def list_after(self, scan_id: int, last_seq: int, *, limit: int = 1000) -> list[dict[str, Any]]:
        return self.replay.list_after(int(scan_id), int(last_seq), limit=limit)


__all__ = ["V3EventPublisher"]
