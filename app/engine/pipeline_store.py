"""P0 transactional persistence for scheduler output and replayable scan events.

The additive runtime bootstrap mirrors migration 0002 so a brand-new encrypted
store can serve the current binary before an operator has historical data to
migrate. Existing evidence tables are never dropped or rewritten here.
"""
from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from typing import Any

from app.database import _SEVERITIES, _json_dumps, cvss31_base_score, finding_fingerprint


class PipelineStore:
    """Batch findings per tool run and persist a gap-free per-scan event log."""

    def __init__(self, database: Any) -> None:
        self.database = database
        self.ensure_schema()

    def ensure_schema(self) -> None:
        """Create only the additive P0 tables required by the current runtime."""
        with self.database._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    schema_version TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(scan_id, seq)
                );
                CREATE TABLE IF NOT EXISTS tool_finding_refs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
                    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    finding_fingerprint TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(scan_id, tool_run_id, finding_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_scan_events_replay ON scan_events(scan_id, seq);
                CREATE INDEX IF NOT EXISTS idx_tool_finding_refs_scan ON tool_finding_refs(scan_id, tool_run_id);
                CREATE INDEX IF NOT EXISTS idx_tool_finding_refs_fingerprint ON tool_finding_refs(finding_fingerprint);
                """
            )

    def append_scan_event(
        self,
        scan_id: int,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        schema_version: str = "windeep.sse.v1",
    ) -> dict[str, Any]:
        """Atomically allocate the next sequence number and append one event."""
        normalized_type = event_type.strip().lower()
        if not normalized_type:
            raise ValueError("event_type is required")
        encoded = self._encode_json(dict(payload), field="scan_event.payload")
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM scan_events WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            seq = int(row["next_seq"] if hasattr(row, "keys") else row[0])
            conn.execute(
                "INSERT INTO scan_events(scan_id, seq, schema_version, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, seq, schema_version, normalized_type, encoded, now),
            )
            conn.commit()
        return {
            "scan_id": scan_id,
            "seq": seq,
            "schema_version": schema_version,
            "event_type": normalized_type,
            "payload": dict(payload),
            "created_at": now,
        }

    def list_scan_events(self, scan_id: int, *, after_seq: int = 0, limit: int = 5000) -> list[dict[str, Any]]:
        """Replay scan events strictly after ``after_seq`` in sequence order."""
        if after_seq < 0:
            raise ValueError("after_seq must be >= 0")
        if limit < 1 or limit > 10000:
            raise ValueError("limit must be between 1 and 10000")
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id, seq, schema_version, event_type, payload, created_at "
                "FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (scan_id, after_seq, limit),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = self._decode_json(item["payload"], field="scan_event.payload")
            result.append(item)
        return result

    def upsert_tool_findings(
        self,
        *,
        target_id: int,
        scan_id: int,
        tool_run_id: int,
        tool_name: str,
        findings: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Persist all normalized findings for a tool in one SQLite transaction.

        The canonical ``findings`` row remains backward compatible.  A separate
        encrypted occurrence snapshot is keyed by scan/tool-run/fingerprint, so
        rerunning the same tool updates the occurrence rather than duplicating it.
        """
        prepared = [self._prepare_finding(target_id, tool_name, item) for item in findings]
        if not prepared:
            return []
        now = time.time()
        keys = [(scan_id, tool_run_id, item["fingerprint"]) for item in prepared]
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing: set[str] = set()
            for _, _, fingerprint in keys:
                row = conn.execute(
                    "SELECT 1 FROM tool_finding_refs WHERE scan_id = ? AND tool_run_id = ? AND finding_fingerprint = ?",
                    (scan_id, tool_run_id, fingerprint),
                ).fetchone()
                if row is not None:
                    existing.add(fingerprint)

            conn.executemany(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, target_id, title, severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, description, evidence, request,
                    response, steps, impact, remediation, status, fingerprint,
                    confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        target_id,
                        item["title"],
                        item["severity"],
                        item["cvss_score"],
                        item["cvss_vector"],
                        item["vuln_type"],
                        tool_name,
                        item["endpoint"],
                        item["stored_description"],
                        item["stored_evidence"],
                        item["stored_request"],
                        item["stored_response"],
                        item["stored_steps"],
                        item["stored_impact"],
                        item["stored_remediation"],
                        item["status"],
                        item["fingerprint"],
                        item["confidence"],
                        now,
                        now,
                    )
                    for item in prepared
                ],
            )

            id_by_fingerprint: dict[str, int] = {}
            for item in prepared:
                row = conn.execute(
                    "SELECT id FROM findings WHERE fingerprint = ?",
                    (item["fingerprint"],),
                ).fetchone()
                if row is None:
                    raise RuntimeError("failed to resolve persisted finding")
                id_by_fingerprint[item["fingerprint"]] = int(row["id"] if hasattr(row, "keys") else row[0])

            conn.executemany(
                """
                INSERT INTO tool_finding_refs(
                    scan_id, tool_run_id, finding_id, finding_fingerprint, payload, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, tool_run_id, finding_fingerprint) DO UPDATE SET
                    finding_id = excluded.finding_id,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                [
                    (
                        scan_id,
                        tool_run_id,
                        id_by_fingerprint[item["fingerprint"]],
                        item["fingerprint"],
                        self._encode_json(item["public"], field="tool_finding.payload"),
                        now,
                        now,
                    )
                    for item in prepared
                ],
            )
            conn.commit()

        output: list[dict[str, Any]] = []
        for item in prepared:
            payload = dict(item["public"])
            payload["id"] = id_by_fingerprint[item["fingerprint"]]
            payload["finding_fingerprint"] = item["fingerprint"]
            payload["created"] = item["fingerprint"] not in existing
            payload["tool_run_id"] = tool_run_id
            output.append(payload)
        return output

    def list_tool_findings(self, *, scan_id: int, tool_run_id: int | None = None) -> list[dict[str, Any]]:
        """Return deterministic occurrence snapshots for one scan."""
        sql = (
            "SELECT finding_id, finding_fingerprint, tool_run_id, payload FROM tool_finding_refs "
            "WHERE scan_id = ?"
        )
        params: list[Any] = [scan_id]
        if tool_run_id is not None:
            sql += " AND tool_run_id = ?"
            params.append(tool_run_id)
        sql += " ORDER BY finding_fingerprint ASC, tool_run_id ASC"
        with self.database._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = self._decode_json(row["payload"], field="tool_finding.payload")
            item.update(
                {
                    "id": int(row["finding_id"]),
                    "finding_fingerprint": str(row["finding_fingerprint"]),
                    "tool_run_id": int(row["tool_run_id"]),
                }
            )
            result.append(item)
        return result

    def _prepare_finding(self, target_id: int, tool_name: str, finding: Mapping[str, Any]) -> dict[str, Any]:
        title = str(finding.get("title") or "").strip()
        if not title:
            raise ValueError("finding title is required")
        vuln_type = str(finding.get("vuln_type") or "informational")
        endpoint = str(finding.get("endpoint")) if finding.get("endpoint") is not None else None
        cvss_vector = str(finding.get("cvss_vector")) if finding.get("cvss_vector") else None
        cvss_score = finding.get("cvss_score")
        severity = str(finding.get("severity") or "").strip().lower() or None
        if cvss_vector and cvss_score is None:
            cvss_score, vector_severity = cvss31_base_score(cvss_vector)
            severity = severity or vector_severity
        severity = severity or "info"
        if severity not in _SEVERITIES:
            raise ValueError(f"invalid severity: {severity}")
        confidence = float(finding.get("confidence", 0.5))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        evidence = dict(finding.get("evidence") or {})
        public = dict(finding)
        public.update(
            {
                "title": title,
                "severity": severity,
                "vuln_type": vuln_type,
                "tool": tool_name,
                "endpoint": endpoint,
                "evidence": evidence,
                "confidence": confidence,
            }
        )
        fingerprint = finding_fingerprint(
            target_id=target_id,
            title=title,
            vuln_type=vuln_type,
            endpoint=endpoint,
        )
        description = str(finding.get("description") or "")
        request = str(finding.get("request") or "")
        response = str(finding.get("response") or "")
        steps = str(finding.get("steps") or "")
        impact = str(finding.get("impact") or "")
        remediation = str(finding.get("remediation") or "")
        return {
            "title": title,
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "cvss_vector": cvss_vector,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "status": str(finding.get("status") or "new"),
            "confidence": confidence,
            "fingerprint": fingerprint,
            "public": public,
            "stored_description": self._encode_text(description, field="finding.description"),
            "stored_evidence": self._encode_text(_json_dumps(evidence), field="finding.evidence"),
            "stored_request": self._encode_text(request, field="finding.request"),
            "stored_response": self._encode_text(response, field="finding.response"),
            "stored_steps": self._encode_text(steps, field="finding.steps"),
            "stored_impact": self._encode_text(impact, field="finding.impact"),
            "stored_remediation": self._encode_text(remediation, field="finding.remediation"),
        }

    def _encode_text(self, value: str, *, field: str) -> str:
        encoder = getattr(self.database, "_enc", None)
        return str(encoder(value, field=field)) if callable(encoder) else value

    def _encode_json(self, value: Mapping[str, Any], *, field: str) -> str:
        return self._encode_text(_json_dumps(dict(value)), field=field)

    def _decode_json(self, value: str, *, field: str) -> dict[str, Any]:
        decoder = getattr(self.database, "_dec", None)
        text = str(decoder(value, field=field)) if callable(decoder) else str(value)
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError(f"stored {field} payload is not an object")
        return parsed
