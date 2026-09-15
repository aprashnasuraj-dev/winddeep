"""Immutable P5 Web3 finding provenance store."""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class Web3ProvenanceStore:
    """Append-only provenance records with explicit supersession links."""

    def __init__(self, database: Any) -> None:
        self.database = database

    @staticmethod
    def validate_hash(value: str, *, field: str) -> str:
        text = str(value).lower()
        if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
            raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
        return text

    def record_finding(
        self,
        *,
        finding_id: int | None,
        scan_id: int,
        engine_run_id: int,
        detector_id: str,
        function_name: str | None,
        source_location: Mapping[str, Any],
        corroborated: bool,
    ) -> int:
        detector = str(detector_id).strip()
        if not detector:
            raise ValueError("detector_id is required")
        payload = _canonical(dict(source_location))
        encoder = getattr(self.database, "_enc", None)
        stored = encoder(payload, field="web3.source_location") if callable(encoder) else payload
        now = time.time()
        with self.database._connect() as conn:
            previous = conn.execute(
                """
                SELECT id FROM web3_finding_provenance
                WHERE scan_id = ? AND engine_run_id = ? AND detector_id = ?
                  AND COALESCE(function_name, '') = COALESCE(?, '')
                ORDER BY id DESC LIMIT 1
                """,
                (scan_id, engine_run_id, detector, function_name),
            ).fetchone()
            cursor = conn.execute(
                """
                INSERT INTO web3_finding_provenance(
                    finding_id, scan_id, engine_run_id, detector_id, function_name,
                    source_location, corroborated, supersedes_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    scan_id,
                    engine_run_id,
                    detector,
                    function_name,
                    stored,
                    1 if corroborated else 0,
                    int(previous["id"]) if previous is not None else None,
                    now,
                ),
            )
            return int(cursor.lastrowid)

    def resolve(self, provenance_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM web3_finding_provenance WHERE id = ?", (provenance_id,)).fetchone()
        if row is None:
            raise KeyError(f"web3 provenance not found: {provenance_id}")
        item = dict(row)
        decoder = getattr(self.database, "_dec", None)
        text = decoder(str(item["source_location"]), field="web3.source_location") if callable(decoder) else str(item["source_location"])
        item["source_location"] = json.loads(text)
        item["corroborated"] = bool(item["corroborated"])
        return item

    @staticmethod
    def fingerprint(record: Mapping[str, Any]) -> str:
        normalized = {
            "engine_run_id": int(record["engine_run_id"]),
            "detector_id": str(record["detector_id"]),
            "function_name": record.get("function_name"),
            "source_location": record.get("source_location") or {},
            "corroborated": bool(record.get("corroborated")),
        }
        return hashlib.sha256(_canonical(normalized).encode("utf-8")).hexdigest()


__all__ = ["Web3ProvenanceStore"]
