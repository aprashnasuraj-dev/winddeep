"""Encrypted flow CRUD facade compatible with Windeep's FlowDatabase exports."""

from __future__ import annotations

from typing import Any

from app.capture.flow_database import FlowDatabase
from app.security.secure_database import SecureDatabase


class SecureFlowDatabase(FlowDatabase):
    """FlowDatabase that decrypts SecureDatabase rows before returning/exporting them."""

    def __init__(self, database: SecureDatabase) -> None:
        super().__init__(database)
        self.database = database

    def get_flows_by_target(self, target_id: int, *, limit: int = 1000, offset: int = 0) -> list[dict[str, Any]]:
        """Return decrypted flows for a target."""
        self._validate_page(limit, offset)
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM flows WHERE target_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (target_id, limit, offset),
            ).fetchall()
        return [self.database.decode_flow_row(dict(row)) for row in rows]

    def get_flow_by_id(self, flow_id: int) -> dict[str, Any] | None:
        """Return one decrypted flow by id."""
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        return self.database.decode_flow_row(dict(row)) if row is not None else None

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
        """Search indexed metadata then filter decrypted content in memory."""
        self._validate_page(limit, offset)
        clauses: list[str] = []
        values: list[Any] = []
        if target_id is not None:
            clauses.append("target_id = ?")
            values.append(target_id)
        if method:
            clauses.append("method = ?")
            values.append(method.upper())
        if host:
            clauses.append("host = ?")
            values.append(host.lower())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        fetch_limit = min(5000, max(limit * 5, 250))
        with self.database._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM flows{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                (*values, fetch_limit, offset),
            ).fetchall()
        needle = query.casefold()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = self.database.decode_flow_row(dict(row))
            haystack = "\n".join(
                [
                    str(item.get("url") or ""),
                    str(item.get("path") or ""),
                    str(item.get("query") or ""),
                    str(item.get("request_headers") or ""),
                    bytes(item.get("request_body") or b"").decode("utf-8", errors="replace"),
                    str(item.get("response_headers") or ""),
                    bytes(item.get("response_body") or b"").decode("utf-8", errors="replace"),
                ]
            ).casefold()
            if needle in haystack:
                results.append(item)
                if len(results) >= limit:
                    break
        return results
