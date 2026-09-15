"""V3-C final API, SSE and release-surface acceptance tests."""
from __future__ import annotations

import json
from pathlib import Path

from flask import Flask

from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.api import register_v3_api
from app.v3.contracts import V3_EVENT_TYPES
from app.v3.events import V3EventPublisher
from app.v3.release_migration import apply_v3_release_migration

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    apply_v3_release_migration(database.path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target_id = database.create_target("root", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v3:polish", ["fixture"])
    consent_id = "consent-v3-polish"
    encrypted = crypto.encrypt_text(consent_id, aad=f"windeep:scan_auth:{scan_id}".encode("utf-8"))
    with database._connect() as conn:
        conn.execute(
            "INSERT INTO scan_authorizations(scan_id, target_id, consent_ref, created_at) VALUES (?, ?, ?, ?)",
            (scan_id, target_id, encrypted, 1.0),
        )
    return crypto, database, audit, target_id, scan_id, consent_id


def _finding(database, target_id: int, scan_id: int | None, title: str, endpoint: str, severity: str = "medium") -> int:
    finding_id, _ = database.create_finding(
        target_id,
        title,
        severity,
        scan_id=scan_id,
        vuln_type="fixture",
        endpoint=endpoint,
        description=f"{title} detail",
        impact=f"{title} impact",
        remediation="Fix the observed condition.",
        confidence=0.8,
    )
    return finding_id


def _app(crypto, database, audit, preflight_for, publisher=None):
    app = Flask(__name__)
    register_v3_api(
        app,
        crypto=crypto,
        audit=audit,
        database=database,
        authenticated=lambda view: view,
        preflight_for=preflight_for,
        event_publisher=publisher or V3EventPublisher(database, crypto, audit, broadcast=lambda *_args: None),
    )
    return app


def test_v3_event_publisher_uses_frozen_schema_gap_free_replay_and_redaction(tmp_path: Path) -> None:
    crypto, database, audit, _target_id, scan_id, _consent = _fixture(tmp_path)
    broadcasts: list[tuple[str, int]] = []
    publisher = V3EventPublisher(database, crypto, audit, broadcast=lambda kind, _data, sid: broadcasts.append((kind, sid)))
    for event_type in V3_EVENT_TYPES:
        event = publisher.emit(scan_id, event_type, {"message": event_type, "authorization": "Bearer should-not-export"})
        assert event["schema"] == "windeep.sse.v1"
        assert event["type"] == event_type
        assert event["data"]["authorization"] == "[REDACTED]"
    replay = publisher.list_after(scan_id, 0)
    assert [row["seq"] for row in replay] == list(range(1, len(V3_EVENT_TYPES) + 1))
    assert [row["type"] for row in replay] == list(V3_EVENT_TYPES)
    assert broadcasts == [(kind, scan_id) for kind in V3_EVENT_TYPES]


def test_v3_api_reuses_scan_preflight_classifies_and_reports_every_finding(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id, consent_id = _fixture(tmp_path)
    actionable = _finding(database, target_id, scan_id, "Actionable HTTPS", "https://example.test/a", "high")
    unclassified = _finding(database, target_id, scan_id, "Unclassified HTTP", "http://example.test/b", "low")
    calls: list[tuple[int, str]] = []

    def preflight_for(target_row: dict, consent: str, **_kwargs):
        calls.append((int(target_row["id"]), consent))
        return object()

    publisher = V3EventPublisher(database, crypto, audit, broadcast=lambda *_args: None)
    client = _app(crypto, database, audit, preflight_for, publisher).test_client()

    status = client.get("/api/v3/status")
    assert status.status_code == 200
    assert status.get_json()["report_inclusion"] == "all-findings"
    assert status.get_json()["policy_required"] is False

    before = client.get(f"/api/v3/scans/{scan_id}/findings")
    assert before.status_code == 200
    rows = before.get_json()["findings"]
    assert {row["finding_id"] for row in rows} == {actionable, unclassified}
    assert next(row for row in rows if row["finding_id"] == unclassified)["disposition"] == "needs-review"

    response = client.post(
        f"/api/v3/findings/{actionable}/triage",
        json={
            "disposition": "actionable",
            "tester_priority": 95,
            "duplicate_risk": "low",
            "rationale": "Ready for tester review.",
        },
    )
    assert response.status_code == 200
    assert response.get_json()["classification"]["disposition"] == "actionable"
    replay = publisher.list_after(scan_id, 0)
    assert replay[-1]["type"] == "disposition"
    assert replay[-1]["data"]["finding_id"] == actionable

    report = client.get(f"/api/v3/scans/{scan_id}/report?format=markdown")
    assert report.status_code == 200
    text = report.get_data(as_text=True)
    assert "Actionable HTTPS" in text
    assert "Unclassified HTTP" in text
    assert "policy: unspecified" not in text.casefold()
    assert "handling rule" not in text.casefold()
    assert calls and all(call == (target_id, consent_id) for call in calls)


def test_v3_api_verification_state_formats_and_invalid_triage_are_explicit(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id, consent_id = _fixture(tmp_path)
    verified = _finding(database, target_id, scan_id, "Verification fixture", "https://example.test/verified", "high")
    with database._connect() as conn:
        cursor = conn.execute(
            "INSERT INTO verification_record(finding_id, scan_id, bundle_sha256, artifact_sha256, schema_version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (verified, scan_id, "b" * 64, "a" * 64, "windeep.verification.v1", 2.0),
        )
        record_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO verification_claim(record_id, claim_key, state, evidence_refs, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (record_id, "claim:1", "verified", "[]", "{}", 2.0),
        )
        conn.execute(
            "INSERT INTO verification_claim(record_id, claim_key, state, evidence_refs, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (record_id, "claim:2", "needs-review", "[]", "{}", 2.0),
        )

    calls: list[str] = []

    def preflight_for(_target, consent: str, **_kwargs):
        calls.append(consent)
        return object()

    client = _app(crypto, database, audit, preflight_for).test_client()
    listing = client.get(f"/api/v3/scans/{scan_id}/findings")
    assert listing.status_code == 200
    row = next(item for item in listing.get_json()["findings"] if item["finding_id"] == verified)
    assert row["verification_state"] == "needs-review"
    assert calls == [consent_id]

    invalid = client.post(
        f"/api/v3/findings/{verified}/triage",
        json={"disposition": "actionable", "tester_priority": 101, "duplicate_risk": "low", "rationale": "invalid priority"},
    )
    assert invalid.status_code == 400
    assert "tester_priority" in invalid.get_json()["error"]

    missing = client.post(
        "/api/v3/findings/999999/triage",
        json={"disposition": "actionable", "tester_priority": 50, "duplicate_risk": "low", "rationale": "missing"},
    )
    assert missing.status_code == 400
    assert "finding not found" in missing.get_json()["error"]

    detached = _finding(database, target_id, None, "Detached finding", "https://example.test/detached")
    denied = client.post(
        f"/api/v3/findings/{detached}/triage",
        json={"disposition": "needs-review", "tester_priority": 50, "duplicate_risk": "medium", "rationale": "detached"},
    )
    assert denied.status_code == 403
    assert "authorized scan context" in denied.get_json()["error"]


def test_v3_report_supports_html_json_and_rejects_unknown_format(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id, _consent_id = _fixture(tmp_path)
    finding_id = _finding(database, target_id, scan_id, "Format fixture", "https://example.test/format")
    client = _app(crypto, database, audit, lambda *_args, **_kwargs: object()).test_client()

    html = client.get(f"/api/v3/scans/{scan_id}/report?format=html")
    assert html.status_code == 200
    assert html.mimetype == "text/html"
    assert "Format fixture" in html.get_data(as_text=True)

    payload = client.get(f"/api/v3/scans/{scan_id}/report?format=json")
    assert payload.status_code == 200
    body = payload.get_json()
    assert body["scan_id"] == scan_id
    assert body["finding_ids"] == [finding_id]
    assert len(body["sha256"]) == 64
    assert "Format fixture" in body["markdown"]

    invalid = client.get(f"/api/v3/scans/{scan_id}/report?format=pdf")
    assert invalid.status_code == 400
    assert "markdown, html, or json" in invalid.get_json()["error"]


def test_v3_api_refuses_scan_without_stored_authorization(tmp_path: Path) -> None:
    crypto, database, audit, target_id, _scan_id, _consent_id = _fixture(tmp_path)
    unauthorized_scan = database.create_scan(target_id, "v3:no-auth", ["fixture"])
    response = _app(crypto, database, audit, lambda *_args, **_kwargs: object()).test_client().get(
        f"/api/v3/scans/{unauthorized_scan}/findings"
    )
    assert response.status_code == 403
    assert "authorization" in response.get_json()["error"].casefold()


def test_release_docs_and_ui_expose_simplified_v3_contract() -> None:
    glossary = (ROOT / "docs" / "glossary.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "operator_runbook.md").read_text(encoding="utf-8")
    checklist = (ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    ui = (ROOT / "app" / "static" / "v3.js").read_text(encoding="utf-8")
    for term in ("exploitability", "handling_disposition", "triage_readiness", "confidence", "verification_state"):
        assert term in glossary
    assert "Actionable" in ui and "Needs-review" in ui and "Not-actionable" in ui
    assert "why this rank" in ui.casefold()
    assert "verification" in ui.casefold()
    assert "all findings" in runbook.casefold()
    assert "release_audit.py --phase V3" in checklist
    assert "Last-Event-ID" in checklist
