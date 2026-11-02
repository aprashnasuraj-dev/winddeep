"""Scan-specific finding observations layered over canonical finding cases.

The canonical `findings` table deduplicates a logical finding by fingerprint.
`scan_findings` records each scan/tool-run observation of that case.  This
module makes that distinction explicit so scan reports do not accidentally use
the canonical finding's first-seen scan_id as their inclusion boundary.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from typing import Any


class FindingObservationStore:
    """Read encrypted per-scan observations without duplicating finding cases."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def list_scan(self, scan_id: int) -> list[dict[str, Any]]:
        try:
            with self.database._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT scan_id, tool_run_id, finding_fingerprint, finding_id,
                           payload, created_at, updated_at
                    FROM scan_findings
                    WHERE scan_id = ?
                    ORDER BY finding_fingerprint, tool_run_id
                    """,
                    (int(scan_id),),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).casefold():
                return []
            raise

        observations: list[dict[str, Any]] = []
        decoder = getattr(self.database, "_dec", None)
        if not callable(decoder):
            raise RuntimeError("finding observations require encrypted database fields")
        for row in rows:
            payload = json.loads(decoder(str(row["payload"]), field="scan_finding.payload") or "{}")
            observations.append(
                {
                    "scan_id": int(row["scan_id"]),
                    "tool_run_id": int(row["tool_run_id"]),
                    "finding_id": int(row["finding_id"]),
                    "fingerprint": str(row["finding_fingerprint"]),
                    "created_at": float(row["created_at"]),
                    "updated_at": float(row["updated_at"]),
                    "payload": payload,
                }
            )
        return observations

    def grouped_scan(self, scan_id: int) -> list[dict[str, Any]]:
        grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for observation in self.list_scan(scan_id):
            grouped[int(observation["finding_id"])].append(observation)
        return [
            {
                "finding_id": finding_id,
                "observations": sorted(
                    values,
                    key=lambda item: (
                        str(item["fingerprint"]),
                        int(item["tool_run_id"]),
                        float(item["updated_at"]),
                    ),
                ),
            }
            for finding_id, values in sorted(grouped.items())
        ]

    def scan_cases(self, scan_id: int) -> list[dict[str, Any]]:
        """Return the union of observed cases and legacy/manual scan cases.

        `scan_findings` is authoritative for scheduler observations, including
        rediscovery of a case whose canonical first-seen scan differs. Direct
        manual/historical findings can still be associated only through
        `findings.scan_id`; those rows are unioned rather than suppressed.
        """
        by_id = {int(item["finding_id"]): item for item in self.grouped_scan(scan_id)}
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM findings WHERE scan_id = ? ORDER BY id ASC",
                (int(scan_id),),
            ).fetchall()
        for row in rows:
            finding_id = int(row["id"])
            by_id.setdefault(finding_id, {"finding_id": finding_id, "observations": []})
        return [by_id[finding_id] for finding_id in sorted(by_id)]


__all__ = ["FindingObservationStore"]
