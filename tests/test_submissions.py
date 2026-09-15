"""Tests for Windeep submission tracking and earnings aggregation."""

from __future__ import annotations

import pytest

from app.database import Database
from app.migrations import MigrationManager
from app.submissions import SubmissionError, SubmissionTracker


def _tracker(tmp_path) -> tuple[Database, SubmissionTracker]:
    database = Database(tmp_path / "windeep.db")
    MigrationManager(database.path, "app/data/migrations", backup_dir=tmp_path / "backups").apply()
    return database, SubmissionTracker(database)


def test_create_starts_in_draft(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    submission_id = tracker.create(platform="HackerOne", program_name="Example")
    item = tracker.get(submission_id)
    assert item is not None
    assert item["status"] == "draft"


def test_valid_transition_records_submission_time(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    submission_id = tracker.create(platform="HackerOne", program_name="Example")
    item = tracker.transition(submission_id, "submitted", external_id="123")
    assert item["status"] == "submitted"
    assert item["submitted_at"] is not None
    assert item["external_id"] == "123"


def test_invalid_transition_is_rejected(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    submission_id = tracker.create(platform="HackerOne", program_name="Example")
    with pytest.raises(SubmissionError, match="invalid transition"):
        tracker.transition(submission_id, "paid")


def test_paid_earnings_are_grouped_by_currency(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    first = tracker.create(platform="HackerOne", program_name="One")
    second = tracker.create(platform="Bugcrowd", program_name="Two")
    for submission_id, amount in ((first, 100.0), (second, 250.0)):
        tracker.transition(submission_id, "submitted")
        tracker.transition(submission_id, "triaged")
        tracker.transition(submission_id, "accepted")
        tracker.transition(submission_id, "resolved", bounty_amount=amount, bounty_currency="usd")
        tracker.transition(submission_id, "paid")
    summary = tracker.earnings()
    assert summary.by_currency == {"USD": 350.0}
    assert summary.paid_count == 2


def test_kanban_contains_all_status_columns(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    submission_id = tracker.create(platform="Intigriti", program_name="Example")
    board = tracker.kanban()
    assert submission_id in [item["id"] for item in board["draft"]]
    assert "paid" in board
    assert "duplicate" in board


def test_negative_bounty_is_rejected(tmp_path) -> None:
    _, tracker = _tracker(tmp_path)
    submission_id = tracker.create(platform="HackerOne", program_name="Example")
    with pytest.raises(SubmissionError, match="cannot be negative"):
        tracker.transition(submission_id, "submitted", bounty_amount=-1, bounty_currency="USD")
