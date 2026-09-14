"""Tests for Windeep SQLite persistence and CVSS helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.database import Database, cvss31_base_score, finding_fingerprint


def make_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "windeep.db")


def test_cvss31_known_critical_vector() -> None:
    score, severity = cvss31_base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert score == 9.8
    assert severity == "critical"


def test_cvss31_rejects_incomplete_vector() -> None:
    with pytest.raises(ValueError, match="missing CVSS metrics"):
        cvss31_base_score("CVSS:3.1/AV:N/AC:L")


def test_target_round_trip_decodes_json_fields(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    target_id = db.create_target(
        "Example",
        "web",
        "https://example.com",
        scope=["example.com", "*.example.com"],
        out_of_scope=["admin.example.com"],
        tags=["bounty", "staging"],
    )
    target = db.get_target(target_id)
    assert target is not None
    assert target["scope"] == ["example.com", "*.example.com"]
    assert target["out_of_scope"] == ["admin.example.com"]
    assert target["tags"] == ["bounty", "staging"]


def test_finding_deduplicates_by_fingerprint(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    target_id = db.create_target("Example", "web", "https://example.com")
    first_id, first_created = db.create_finding(
        target_id,
        "Reflected input",
        "medium",
        vuln_type="reflection",
        endpoint="https://example.com/search?q=x",
    )
    second_id, second_created = db.create_finding(
        target_id,
        "  reflected INPUT  ",
        "medium",
        vuln_type="REFLECTION",
        endpoint="HTTPS://EXAMPLE.COM/SEARCH?Q=X",
    )
    assert first_created is True
    assert second_created is False
    assert first_id == second_id


def test_finding_auto_scores_cvss(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    target_id = db.create_target("Example", "web", "https://example.com")
    finding_id, created = db.create_finding(
        target_id,
        "Impactful issue",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vuln_type="test",
        endpoint="https://example.com/",
    )
    assert created is True
    finding = db.get_finding(finding_id)
    assert finding is not None
    assert finding["cvss_score"] == 9.8
    assert finding["severity"] == "critical"


def test_insert_flow_persists_indexable_fields(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    flow_id = db.insert_flow(
        {
            "method": "GET",
            "url": "https://example.com/api/items?id=7",
            "scheme": "https",
            "host": "example.com",
            "path": "/api/items",
            "query": "id=7",
            "request_headers": {"accept": "application/json"},
            "status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_body": b"{}",
        }
    )
    with sqlite3.connect(db.path) as conn:
        row = conn.execute(
            "SELECT host, path, method, status FROM flows WHERE id = ?",
            (flow_id,),
        ).fetchone()
    assert row == ("example.com", "/api/items", "GET", 200)


def test_hypotheses_are_ordered_by_confidence(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    target_id = db.create_target("Example", "web", "https://example.com")
    db.create_hypothesis(
        {
            "id": "h-low",
            "test_class": "authorization",
            "endpoint": "/api/a",
            "parameters": {},
            "rationale": "lower-confidence signal",
            "confidence": 0.4,
            "severity_hint": "medium",
            "chain_hints": [],
        },
        target_id=target_id,
    )
    db.create_hypothesis(
        {
            "id": "h-high",
            "test_class": "session",
            "endpoint": "/api/b",
            "parameters": {"token": "present"},
            "rationale": "stronger evidence",
            "confidence": 0.9,
            "severity_hint": "high",
            "chain_hints": ["authorization"],
        },
        target_id=target_id,
    )
    rows = db.list_hypotheses(target_id=target_id)
    assert [row["id"] for row in rows] == ["h-high", "h-low"]
    assert rows[0]["parameters"] == {"token": "present"}


def test_chain_edge_upsert_is_idempotent(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    target_id = db.create_target("Example", "web", "https://example.com")
    left, _ = db.create_finding(target_id, "A", "low", vuln_type="info", endpoint="/a")
    right, _ = db.create_finding(target_id, "B", "high", vuln_type="auth", endpoint="/b")
    first = db.upsert_chain_edge(
        source_finding_id=left,
        target_finding_id=right,
        edge_type="enables",
        weight=0.6,
        rationale="initial",
        target_id=target_id,
    )
    second = db.upsert_chain_edge(
        source_finding_id=left,
        target_finding_id=right,
        edge_type="enables",
        weight=0.8,
        rationale="updated",
        target_id=target_id,
    )
    assert first == second
    with sqlite3.connect(db.path) as conn:
        row = conn.execute(
            "SELECT weight, rationale FROM chains WHERE id = ?",
            (first,),
        ).fetchone()
    assert row == (0.8, "updated")


def test_tool_run_and_learning_audit_records(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    run_id = db.create_tool_run(
        tool_name="example-tool",
        status="running",
        command=["example-tool", "--version"],
    )
    db.finish_tool_run(run_id, status="completed", exit_code=0, stdout_tail="ok")
    learning_id = db.add_learning(
        kind="rejection",
        content="Needs stronger reproduction evidence",
        metadata={"reason": "unverified"},
    )
    with sqlite3.connect(db.path) as conn:
        run = conn.execute(
            "SELECT status, exit_code, stdout_tail FROM tool_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        learning = conn.execute(
            "SELECT kind, content FROM learnings WHERE id = ?",
            (learning_id,),
        ).fetchone()
    assert run == ("completed", 0, "ok")
    assert learning == ("rejection", "Needs stronger reproduction evidence")


def test_fingerprint_is_stable_and_target_specific() -> None:
    first = finding_fingerprint(
        target_id=1,
        title="Issue",
        vuln_type="idor",
        endpoint="https://example.com/a",
    )
    second = finding_fingerprint(
        target_id=1,
        title=" issue ",
        vuln_type="IDOR",
        endpoint="HTTPS://EXAMPLE.COM/A",
    )
    other_target = finding_fingerprint(
        target_id=2,
        title="Issue",
        vuln_type="idor",
        endpoint="https://example.com/a",
    )
    assert first == second
    assert first != other_target
