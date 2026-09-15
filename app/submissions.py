"""Bug-bounty submission tracking and earnings aggregation for Windeep."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.database import Database

SUBMISSION_STATUSES = (
    "draft",
    "submitted",
    "triaged",
    "needs_info",
    "accepted",
    "duplicate",
    "informative",
    "not_applicable",
    "resolved",
    "paid",
)

_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"submitted"},
    "submitted": {"triaged", "needs_info", "duplicate", "informative", "not_applicable"},
    "triaged": {"needs_info", "accepted", "duplicate", "informative", "not_applicable"},
    "needs_info": {"submitted", "triaged", "accepted", "duplicate", "informative", "not_applicable"},
    "accepted": {"resolved", "not_applicable"},
    "resolved": {"paid"},
    "paid": set(),
    "duplicate": set(),
    "informative": set(),
    "not_applicable": set(),
}


class SubmissionError(ValueError):
    """Raised when a submission workflow operation is invalid."""


@dataclass(frozen=True, slots=True)
class EarningsSummary:
    """Aggregated paid bounty values grouped by currency."""

    by_currency: dict[str, float]
    paid_count: int


class SubmissionTracker:
    """Persist bug-bounty report workflow state and earnings."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._require_schema()

    def _require_schema(self) -> None:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?",
                ("table", "submissions"),
            ).fetchone()
        if row is None:
            raise SubmissionError("submissions table is missing; apply database migrations first")

    def create(
        self,
        *,
        platform: str,
        program_name: str,
        finding_id: int | None = None,
        target_id: int | None = None,
        external_id: str | None = None,
        external_url: str | None = None,
        notes: str = "",
    ) -> int:
        """Create a draft submission and return its id."""
        platform = platform.strip()
        program_name = program_name.strip()
        if not platform or not program_name:
            raise SubmissionError("platform and program_name are required")
        now = time.time()
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO submissions(
                    finding_id, target_id, platform, program_name, external_id,
                    external_url, status, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    target_id,
                    platform,
                    program_name,
                    external_id,
                    external_url,
                    "draft",
                    notes,
                    now,
                    now,
                ),
            )
            return int(cursor.lastrowid)

    def get(self, submission_id: int) -> dict[str, Any] | None:
        """Return one submission by id."""
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,)).fetchone()
        return dict(row) if row is not None else None

    def list(
        self,
        *,
        status: str | None = None,
        target_id: int | None = None,
        platform: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return newest submissions with optional bound filters."""
        if limit < 1 or limit > 5000:
            raise SubmissionError("limit must be between 1 and 5000")
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("status", status), ("target_id", target_id), ("platform", platform)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.database._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM submissions{where} ORDER BY updated_at DESC, id DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def transition(
        self,
        submission_id: int,
        new_status: str,
        *,
        external_id: str | None = None,
        external_url: str | None = None,
        notes: str | None = None,
        bounty_amount: float | None = None,
        bounty_currency: str | None = None,
    ) -> dict[str, Any]:
        """Apply one validated workflow transition and return the updated record."""
        new_status = new_status.strip().lower()
        if new_status not in SUBMISSION_STATUSES:
            raise SubmissionError(f"unsupported submission status: {new_status}")
        current = self.get(submission_id)
        if current is None:
            raise SubmissionError(f"submission not found: {submission_id}")
        current_status = str(current["status"])
        if new_status != current_status and new_status not in _ALLOWED_TRANSITIONS[current_status]:
            raise SubmissionError(f"invalid transition: {current_status} -> {new_status}")
        if bounty_amount is not None and bounty_amount < 0:
            raise SubmissionError("bounty_amount cannot be negative")
        if bounty_amount is not None and not (bounty_currency or current.get("bounty_currency")):
            raise SubmissionError("bounty_currency is required when bounty_amount is set")

        now = time.time()
        values: dict[str, Any] = {"status": new_status, "updated_at": now}
        if external_id is not None:
            values["external_id"] = external_id
        if external_url is not None:
            values["external_url"] = external_url
        if notes is not None:
            values["notes"] = notes
        if bounty_amount is not None:
            values["bounty_amount"] = float(bounty_amount)
        if bounty_currency is not None:
            values["bounty_currency"] = bounty_currency.upper().strip()
        if new_status == "submitted" and current.get("submitted_at") is None:
            values["submitted_at"] = now
        if new_status in {"resolved", "paid"} and current.get("resolved_at") is None:
            values["resolved_at"] = now
        columns = ", ".join(f"{column} = ?" for column in values)
        with self.database._connect() as conn:
            conn.execute(
                f"UPDATE submissions SET {columns} WHERE id = ?",
                (*values.values(), submission_id),
            )
        updated = self.get(submission_id)
        if updated is None:
            raise RuntimeError("updated submission disappeared")
        return updated

    def earnings(self) -> EarningsSummary:
        """Return paid bounty totals grouped by uppercase currency code."""
        with self.database._connect() as conn:
            rows = conn.execute(
                """
                SELECT UPPER(bounty_currency), COALESCE(SUM(bounty_amount), 0), COUNT(*)
                FROM submissions
                WHERE status = ? AND bounty_amount IS NOT NULL AND bounty_currency IS NOT NULL
                GROUP BY UPPER(bounty_currency)
                ORDER BY UPPER(bounty_currency)
                """,
                ("paid",),
            ).fetchall()
        totals = {str(currency): float(amount) for currency, amount, _ in rows}
        paid_count = sum(int(count) for _, _, count in rows)
        return EarningsSummary(by_currency=totals, paid_count=paid_count)

    def kanban(self) -> dict[str, list[dict[str, Any]]]:
        """Return submission cards grouped into every workflow column."""
        board = {status: [] for status in SUBMISSION_STATUSES}
        for submission in self.list(limit=5000):
            board[str(submission["status"])].append(submission)
        return board
