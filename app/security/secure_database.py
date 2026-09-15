"""Encrypted-at-rest persistence adapter for sensitive Windeep findings and flows."""

from __future__ import annotations

import base64
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.database import Database, _SEVERITIES, _json_dumps, _json_loads, cvss31_base_score, finding_fingerprint
from app.security.crypto import CryptoManager


class SecureDatabase(Database):
    """Database variant that transparently encrypts sensitive finding/flow fields."""

    def __init__(self, path: str | Path = "app/data/windeep.db", *, crypto: CryptoManager | None = None) -> None:
        self.crypto = crypto or CryptoManager()
        super().__init__(path)

    def _enc(self, value: str, *, field: str) -> str:
        return self.crypto.encrypt_text(value, aad=f"windeep:{field}".encode("utf-8"))

    def _dec(self, value: str | None, *, field: str) -> str:
        if value is None:
            return ""
        return self.crypto.decrypt_text(str(value), aad=f"windeep:{field}".encode("utf-8"))

    def create_finding(
        self,
        target_id: int,
        title: str,
        severity: str | None = None,
        *,
        scan_id: int | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        vuln_type: str = "informational",
        tool: str = "",
        endpoint: str | None = None,
        description: str = "",
        evidence: Mapping[str, Any] | None = None,
        request: str = "",
        response: str = "",
        steps: str = "",
        impact: str = "",
        remediation: str = "",
        status: str = "new",
        confidence: float = 0.5,
    ) -> tuple[int, bool]:
        """Insert a deduplicated finding with sensitive content encrypted."""
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        computed_severity = severity.lower() if severity else None
        if cvss_vector and cvss_score is None:
            cvss_score, vector_severity = cvss31_base_score(cvss_vector)
            computed_severity = computed_severity or vector_severity
        computed_severity = computed_severity or "info"
        if computed_severity not in _SEVERITIES:
            raise ValueError(f"invalid severity: {computed_severity}")
        fingerprint = finding_fingerprint(target_id=target_id, title=title, vuln_type=vuln_type, endpoint=endpoint)
        now = time.time()
        encrypted = {
            "description": self._enc(description, field="finding.description"),
            "evidence": self._enc(_json_dumps(dict(evidence or {})), field="finding.evidence"),
            "request": self._enc(request, field="finding.request"),
            "response": self._enc(response, field="finding.response"),
            "steps": self._enc(steps, field="finding.steps"),
            "impact": self._enc(impact, field="finding.impact"),
            "remediation": self._enc(remediation, field="finding.remediation"),
        }
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, target_id, title, severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, description, evidence, request,
                    response, steps, impact, remediation, status, fingerprint,
                    confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, target_id, title, computed_severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, encrypted["description"], encrypted["evidence"],
                    encrypted["request"], encrypted["response"], encrypted["steps"],
                    encrypted["impact"], encrypted["remediation"], status, fingerprint,
                    confidence, now, now,
                ),
            )
            if cursor.rowcount == 1:
                return int(cursor.lastrowid), True
            row = conn.execute("SELECT id FROM findings WHERE fingerprint = ?", (fingerprint,)).fetchone()
            if row is None:
                raise RuntimeError("failed to resolve deduplicated finding")
            return int(row["id"]), False

    def _decode_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        item["description"] = self._dec(item.get("description"), field="finding.description")
        evidence = self._dec(item.get("evidence"), field="finding.evidence")
        item["evidence"] = _json_loads(evidence, {})
        for field in ("request", "response", "steps", "impact", "remediation"):
            item[field] = self._dec(item.get(field), field=f"finding.{field}")
        return item

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Return one finding with sensitive fields transparently decrypted."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._decode_finding(dict(row)) if row is not None else None

    def list_findings(
        self,
        *,
        target_id: int | None = None,
        severity: str | None = None,
        status: str | None = None,
        vuln_type: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return filtered findings with transparent decryption."""
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("target_id", target_id), ("severity", severity), ("status", status), ("vuln_type", vuln_type)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?", (*values, limit)).fetchall()
        return [self._decode_finding(dict(row)) for row in rows]

    @staticmethod
    def _to_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, memoryview):
            return value.tobytes()
        return str(value).encode("utf-8")

    def insert_flow(self, flow: Mapping[str, Any]) -> int:
        """Insert a captured flow with headers, bodies, TLS and query encrypted."""
        required = {"method", "url", "host", "path"}
        missing = required.difference(flow)
        if missing:
            raise ValueError(f"missing flow fields: {sorted(missing)}")
        request_body = base64.b64encode(self._to_bytes(flow.get("request_body"))).decode("ascii")
        response_body = base64.b64encode(self._to_bytes(flow.get("response_body"))).decode("ascii")
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO flows(
                    target_id, scan_id, method, url, scheme, host, port, path,
                    query, request_headers, request_body, status, response_headers,
                    response_body, timing_ms, tls_info, client_ip, tags, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.get("target_id"), flow.get("scan_id"), str(flow["method"]), str(flow["url"]),
                    str(flow.get("scheme") or ""), str(flow["host"]), flow.get("port"), str(flow["path"]),
                    self._enc(str(flow.get("query") or ""), field="flow.query"),
                    self._enc(_json_dumps(dict(flow.get("request_headers") or {})), field="flow.request_headers"),
                    self._enc(request_body, field="flow.request_body").encode("utf-8"),
                    flow.get("status"),
                    self._enc(_json_dumps(dict(flow.get("response_headers") or {})), field="flow.response_headers"),
                    self._enc(response_body, field="flow.response_body").encode("utf-8"),
                    flow.get("timing_ms"),
                    self._enc(_json_dumps(dict(flow.get("tls_info") or {})), field="flow.tls_info"),
                    self._enc(str(flow.get("client_ip") or ""), field="flow.client_ip"),
                    _json_dumps(list(flow.get("tags") or [])),
                    float(flow.get("created_at") or time.time()),
                ),
            )
            return int(cursor.lastrowid)

    def decode_flow_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        """Decode one raw flow row returned by SQLite."""
        item = dict(row)
        item["query"] = self._dec(item.get("query"), field="flow.query")
        for field in ("request_headers", "response_headers", "tls_info"):
            item[field] = _json_loads(self._dec(item.get(field), field=f"flow.{field}"), {})
        for field in ("request_body", "response_body"):
            raw = item.get(field)
            text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray, memoryview)) else str(raw or "")
            decoded = self._dec(text, field=f"flow.{field}")
            item[field] = base64.b64decode(decoded) if decoded else b""
        item["client_ip"] = self._dec(item.get("client_ip"), field="flow.client_ip")
        item["tags"] = _json_loads(str(item.get("tags") or "[]"), [])
        return item
