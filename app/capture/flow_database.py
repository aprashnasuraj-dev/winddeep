"""SQLite-backed HTTP flow storage and export utilities for Windeep."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from typing import Any, Literal
from urllib.parse import urlsplit

from app.database import Database

ExportFormat = Literal["raw", "curl", "httpie", "har"]


class FlowDatabase:
    """High-level CRUD/search/export interface for captured traffic."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def insert_flow(self, flow: Mapping[str, Any]) -> int:
        """Persist one normalized captured flow and return its row id."""
        return self.database.insert_flow(flow)

    def get_flows_by_target(self, target_id: int, *, limit: int = 1000, offset: int = 0) -> list[dict[str, Any]]:
        """Return newest flows for a target with bounded pagination."""
        self._validate_page(limit, offset)
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM flows WHERE target_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (target_id, limit, offset),
            ).fetchall()
        return [self._decode_row(dict(row)) for row in rows]

    def get_flow_by_id(self, flow_id: int) -> dict[str, Any] | None:
        """Return one decoded flow by id."""
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        return self._decode_row(dict(row)) if row is not None else None

    def search_flows(
        self,
        query: str,
        *,
        target_id: int | None = None,
        method: str | None = None,
        host: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search URLs, paths, headers, and bodies using bound LIKE filters."""
        self._validate_page(limit, offset)
        clauses = [
            "(url LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' "
            "OR request_headers LIKE ? ESCAPE '\\' OR response_headers LIKE ? ESCAPE '\\' "
            "OR CAST(request_body AS TEXT) LIKE ? ESCAPE '\\' "
            "OR CAST(response_body AS TEXT) LIKE ? ESCAPE '\\')"
        ]
        pattern = f"%{self._escape_like(query)}%"
        values: list[Any] = [pattern] * 6
        if target_id is not None:
            clauses.append("target_id = ?")
            values.append(target_id)
        if method:
            clauses.append("method = ?")
            values.append(method.upper())
        if host:
            clauses.append("host = ?")
            values.append(host.lower())
        values.extend([limit, offset])
        sql = "SELECT * FROM flows WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ? OFFSET ?"
        with self.database._connect() as conn:
            rows = conn.execute(sql, tuple(values)).fetchall()
        return [self._decode_row(dict(row)) for row in rows]

    def delete_flow(self, flow_id: int) -> bool:
        """Delete one captured flow; return whether a row existed."""
        with self.database._connect() as conn:
            cursor = conn.execute("DELETE FROM flows WHERE id = ?", (flow_id,))
            return cursor.rowcount == 1

    def export_flow(self, flow_id: int, format: ExportFormat) -> str:
        """Export a captured flow as raw HTTP, cURL, HTTPie, or HAR JSON."""
        flow = self.get_flow_by_id(flow_id)
        if flow is None:
            raise KeyError(f"flow not found: {flow_id}")
        if format == "raw":
            return self._export_raw(flow)
        if format == "curl":
            return self._export_curl(flow)
        if format == "httpie":
            return self._export_httpie(flow)
        if format == "har":
            return json.dumps(self._export_har(flow), ensure_ascii=False, indent=2)
        raise ValueError(f"unsupported export format: {format}")

    @staticmethod
    def _validate_page(limit: int, offset: int) -> None:
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        if offset < 0:
            raise ValueError("offset must be >= 0")

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @staticmethod
    def _decode_row(row: dict[str, Any]) -> dict[str, Any]:
        for key, default in (
            ("request_headers", {}),
            ("response_headers", {}),
            ("tls_info", {}),
            ("tags", []),
        ):
            raw = row.get(key)
            if isinstance(raw, str):
                try:
                    row[key] = json.loads(raw)
                except json.JSONDecodeError:
                    row[key] = default
            elif raw is None:
                row[key] = default
        return row

    @staticmethod
    def _body_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, memoryview):
            return value.tobytes()
        return str(value).encode("utf-8")

    def _export_raw(self, flow: Mapping[str, Any]) -> str:
        url = urlsplit(str(flow["url"]))
        target = url.path or "/"
        if url.query:
            target += "?" + url.query
        headers = {str(k): str(v) for k, v in dict(flow.get("request_headers") or {}).items()}
        if not any(key.lower() == "host" for key in headers):
            headers["Host"] = url.netloc
        request_lines = [f"{flow['method']} {target} HTTP/1.1"]
        request_lines.extend(f"{key}: {value}" for key, value in headers.items())
        request = "\r\n".join(request_lines) + "\r\n\r\n"
        request += self._body_bytes(flow.get("request_body")).decode("utf-8", errors="replace")

        if flow.get("status") is None:
            return request
        response_headers = dict(flow.get("response_headers") or {})
        response_lines = [f"HTTP/1.1 {int(flow['status'])}"]
        response_lines.extend(f"{key}: {value}" for key, value in response_headers.items())
        response = "\r\n".join(response_lines) + "\r\n\r\n"
        response += self._body_bytes(flow.get("response_body")).decode("utf-8", errors="replace")
        return request + "\n\n--- RESPONSE ---\n" + response

    def _export_curl(self, flow: Mapping[str, Any]) -> str:
        parts = ["curl", "-i", "-X", shlex.quote(str(flow["method"])), shlex.quote(str(flow["url"]))]
        for key, value in dict(flow.get("request_headers") or {}).items():
            if str(key).lower() in {"host", "content-length"}:
                continue
            parts.extend(["-H", shlex.quote(f"{key}: {value}")])
        body = self._body_bytes(flow.get("request_body"))
        if body:
            parts.extend(["--data-binary", shlex.quote(body.decode("utf-8", errors="replace"))])
        return " ".join(parts)

    def _export_httpie(self, flow: Mapping[str, Any]) -> str:
        parts = ["http", shlex.quote(str(flow["method"])), shlex.quote(str(flow["url"]))]
        for key, value in dict(flow.get("request_headers") or {}).items():
            if str(key).lower() in {"host", "content-length"}:
                continue
            parts.append(shlex.quote(f"{key}:{value}"))
        body = self._body_bytes(flow.get("request_body"))
        if body:
            parts.append(f"<<< {shlex.quote(body.decode('utf-8', errors='replace'))}")
        return " ".join(parts)

    def _export_har(self, flow: Mapping[str, Any]) -> dict[str, Any]:
        request_body = self._body_bytes(flow.get("request_body"))
        response_body = self._body_bytes(flow.get("response_body"))
        response_text, response_encoding = self._har_body(response_body)
        request_text, request_encoding = self._har_body(request_body)
        request_headers = [
            {"name": str(key), "value": str(value)}
            for key, value in dict(flow.get("request_headers") or {}).items()
        ]
        response_headers = [
            {"name": str(key), "value": str(value)}
            for key, value in dict(flow.get("response_headers") or {}).items()
        ]
        request: dict[str, Any] = {
            "method": str(flow["method"]),
            "url": str(flow["url"]),
            "httpVersion": "HTTP/1.1",
            "headers": request_headers,
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(request_body),
        }
        if request_body:
            request["postData"] = {"mimeType": "application/octet-stream", "text": request_text}
            if request_encoding:
                request["postData"]["encoding"] = request_encoding
        response_content: dict[str, Any] = {
            "size": len(response_body),
            "mimeType": self._content_type(dict(flow.get("response_headers") or {})),
            "text": response_text,
        }
        if response_encoding:
            response_content["encoding"] = response_encoding
        entry = {
            "startedDateTime": self._iso_timestamp(float(flow.get("created_at") or 0.0)),
            "time": float(flow.get("timing_ms") or 0.0),
            "request": request,
            "response": {
                "status": int(flow.get("status") or 0),
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": response_headers,
                "cookies": [],
                "content": response_content,
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(response_body),
            },
            "cache": {},
            "timings": {"send": 0, "wait": float(flow.get("timing_ms") or 0.0), "receive": 0},
            "serverIPAddress": str(flow.get("host") or ""),
            "comment": f"Windeep flow {flow.get('id')}",
        }
        return {"log": {"version": "1.2", "creator": {"name": "Windeep", "version": "1"}, "entries": [entry]}}

    @staticmethod
    def _har_body(body: bytes) -> tuple[str, str | None]:
        if not body:
            return "", None
        try:
            text = body.decode("utf-8")
            if "\x00" not in text:
                return text, None
        except UnicodeDecodeError:
            pass
        return base64.b64encode(body).decode("ascii"), "base64"

    @staticmethod
    def _content_type(headers: Mapping[str, Any]) -> str:
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value).split(";", 1)[0].strip()
        return "application/octet-stream"

    @staticmethod
    def _iso_timestamp(timestamp: float) -> str:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
