"""Tests for the tamper-evident Windeep audit log."""

from __future__ import annotations

import json

import pytest

from app.security.audit import AuditLog


def test_empty_log_is_valid(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    assert audit.verify_chain() == (True, 0)


def test_append_builds_valid_chain(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    first = audit.append("scan.created", {"id": 1})
    second = audit.append("scan.finished", {"id": 1})
    assert first != second
    assert audit.verify_chain() == (True, 2)


def test_tampering_is_detected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append("event", {"value": "original"})
    row = json.loads(path.read_text(encoding="utf-8"))
    row["data"]["value"] = "changed"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert audit.verify_chain()[0] is False


def test_corrupt_log_refuses_new_append(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        audit.append("event")


def test_empty_event_is_rejected(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError):
        audit.append("   ")
