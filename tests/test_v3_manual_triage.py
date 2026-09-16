"""V3-B simplified tester triage and report acceptance contract."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.release_migration import apply_v3_release_migration
from app.v3.reporting import V3ReportGenerator
from app.v3.triage import ManualTriage, TriageError

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    apply_v3_release_migration(database.path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target_id = database.create_target("root", "domain", "example.test", scope=["example.test", "198.51.100.7"])
    scan_id = database.create_scan(target_id, "v3:triage", ["fixture"])
    return crypto, database, audit, target_id, scan_id


def _finding(database, target_id: int, scan_id: int, title: str, severity: str, endpoint: str) -> int:
    finding_id, _created = database.create_finding(
        target_id,
        title,
        severity,
        scan_id=scan_id,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity in {"critical", "high"} else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        vuln_type="fixture",
        endpoint=endpoint,
        description=f"{title} description",
        impact=f"{title} impact",
        remediation=f"{title} remediation",
        confidence=0.9,
    )
    return finding_id


def test_0030_uses_manual_classification_not_imported_policy_tables(tmp_path: Path) -> None:
    _crypto, database, _audit, _target_id, _scan_id = _fixture(tmp_path)
    with database._connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        columns = {row[1] for row in conn.execute("PRAGMA table_info(handling_classification)").fetchall()}
    assert "handling_classification" in tables
    assert "handling_policy" not in tables
    assert "handling_rule" not in tables
    assert {"asset_class", "disposition", "tester_priority", "duplicate_risk", "rationale", "score"}.issubset(columns)


def test_tester_can_classify_only_http_https_ipv4_ipv6_and_rank_before_alignment(tmp_path: Path) -> None:
    _crypto, database, audit, target_id, scan_id = _fixture(tmp_path)
    high = _finding(database, target_id, scan_id, "High actionable", "high", "https://example.test/account")
    critical = _finding(database, target_id, scan_id, "Critical not actionable", "critical", "https://198.51.100.7:8443/")
    unclassified = _finding(database, target_id, scan_id, "Unclassified HTTP", "medium", "http://example.test/info")
    triage = ManualTriage(database, audit)

    a = triage.classify(
        high,
        disposition="actionable",
        tester_priority=92,
        duplicate_risk="low",
        rationale="Directly actionable from captured behavior.",
    )
    b = triage.classify(
        critical,
        disposition="not-actionable",
        tester_priority=100,
        duplicate_risk="low",
        rationale="Tester marked this as not actionable for this review pass.",
    )
    assert a["asset_class"] == "https"
    assert b["asset_class"] == "ipv4"

    ranked = triage.rank_scan(scan_id)
    assert {item["finding_id"] for item in ranked} == {high, critical, unclassified}
    assert ranked[0]["finding_id"] == high
    default = next(item for item in ranked if item["finding_id"] == unclassified)
    assert default["disposition"] == "needs-review"
    assert default["classified"] is False

    with pytest.raises(TriageError, match="asset_class"):
        triage.classify(high, disposition="actionable", tester_priority=50, duplicate_risk="low", rationale="x", asset_class="contract")


def test_manual_triage_validation_is_fail_closed_but_never_deletes_findings(tmp_path: Path) -> None:
    _crypto, database, audit, target_id, scan_id = _fixture(tmp_path)
    first = _finding(database, target_id, scan_id, "A", "low", "http://example.test/a")
    second = _finding(database, target_id, scan_id, "B", "info", "https://example.test/b")
    triage = ManualTriage(database, audit)
    with pytest.raises(TriageError, match="disposition"):
        triage.classify(first, disposition="forbidden", tester_priority=50, duplicate_risk="low", rationale="x")
    with pytest.raises(TriageError, match="tester_priority"):
        triage.classify(first, disposition="actionable", tester_priority=101, duplicate_risk="low", rationale="x")
    with pytest.raises(TriageError, match="duplicate_risk"):
        triage.classify(first, disposition="actionable", tester_priority=50, duplicate_risk="unknown", rationale="x")
    with pytest.raises(TriageError, match="rationale"):
        triage.classify(first, disposition="actionable", tester_priority=50, duplicate_risk="low", rationale="")
    triage.classify(first, disposition="informational", tester_priority=5, duplicate_risk="high", rationale="Keep visible as context.")
    ranked = triage.rank_scan(scan_id)
    assert len(ranked) == 2
    assert {item["finding_id"] for item in ranked} == {first, second}


def test_manual_triage_edge_paths_and_literal_ip_inference(tmp_path: Path) -> None:
    _crypto, database, audit, target_id, scan_id = _fixture(tmp_path)
    triage = ManualTriage(database, audit)
    with pytest.raises(TriageError, match="finding not found"):
        triage.classify(999999, disposition="actionable", tester_priority=50, duplicate_risk="low", rationale="x")
    with pytest.raises(KeyError, match="not found"):
        triage.get(999999)

    ipv4 = _finding(database, target_id, scan_id, "Bare IPv4", "medium", "198.51.100.7")
    ipv6 = _finding(database, target_id, scan_id, "Bare IPv6", "medium", "2001:db8::7")
    assert triage.classify(ipv4, disposition="actionable", tester_priority=55, duplicate_risk="low", rationale="IPv4 fixture")["asset_class"] == "ipv4"
    assert triage.classify(ipv6, disposition="needs-review", tester_priority=45, duplicate_risk="medium", rationale="IPv6 fixture")["asset_class"] == "ipv6"
    with pytest.raises(TriageError, match="numeric"):
        triage.classify(ipv4, disposition="actionable", tester_priority="not-a-number", duplicate_risk="low", rationale="x")

    orphan, _ = database.create_finding(target_id, "No scan", "low", vuln_type="fixture", endpoint="https://example.test/no-scan")
    with pytest.raises(TriageError, match="belong to a scan"):
        triage.classify(orphan, disposition="needs-review", tester_priority=10, duplicate_risk="low", rationale="orphan")


class _Renderer:
    def __init__(self, missing: set[int] | None = None) -> None:
        self.missing = missing or set()

    def render_finding(self, finding_id: int):
        if finding_id in self.missing:
            raise RuntimeError("bundle unavailable in fixture")
        return SimpleNamespace(
            markdown=f"# Evidence-backed finding {finding_id}\n\nDetailed redacted evidence for {finding_id}.\n",
            model={"bundle_sha256": f"bundle-{finding_id}", "flows": [{"replay_handle": f"flow:{finding_id}:hash"}], "provenance": {"nodes": [{"name": "fixture", "detector_id": "fixture.detector"}]}},
        )


def test_v3_report_contains_every_finding_without_policy_gate_and_is_deterministic(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id = _fixture(tmp_path)
    actionable = _finding(database, target_id, scan_id, "Actionable HTTPS", "high", "https://example.test/a")
    missing_bundle = _finding(database, target_id, scan_id, "Still reported", "medium", "http://example.test/b")
    unclassified = _finding(database, target_id, scan_id, "Unclassified IPv6", "low", "https://[2001:db8::7]:8443/")
    triage = ManualTriage(database, audit)
    triage.classify(actionable, disposition="actionable", tester_priority=90, duplicate_risk="low", rationale="Strong target-side signal.")
    triage.classify(missing_bundle, disposition="needs-review", tester_priority=70, duplicate_risk="medium", rationale="Needs deeper evidence review.")

    generator = V3ReportGenerator(database, crypto, triage=triage, finding_renderer=_Renderer({missing_bundle}))
    first = generator.render_scan(scan_id)
    second = generator.render_scan(scan_id)
    assert first.markdown == second.markdown
    assert first.sha256 == second.sha256
    assert set(first.finding_ids) == {actionable, missing_bundle, unclassified}
    for title in ("Actionable HTTPS", "Still reported", "Unclassified IPv6"):
        assert title in first.markdown
    lowered = first.markdown.casefold()
    assert "policy: unspecified" not in lowered
    assert "handling rule" not in lowered
    assert "excluded" not in lowered
    assert "bundle unavailable in fixture" in first.markdown
    assert "Tester has not classified this finding yet" in first.markdown


def test_v3_report_reads_encrypted_verification_rows_when_present(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id = _fixture(tmp_path)
    finding_id = _finding(database, target_id, scan_id, "Verified HTTPS", "high", "https://example.test/verified")
    triage = ManualTriage(database, audit)
    triage.classify(finding_id, disposition="actionable", tester_priority=95, duplicate_risk="low", rationale="Captured and reviewed.")
    enc = database._enc
    with database._connect() as conn:
        cursor = conn.execute(
            "INSERT INTO verification_record(finding_id, scan_id, bundle_sha256, artifact_sha256, schema_version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (finding_id, scan_id, "b" * 64, "a" * 64, "windeep.verification.v1", 1.0),
        )
        record_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO verification_claim(record_id, claim_key, state, evidence_refs, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record_id,
                "technical_detail",
                "verified",
                enc(json.dumps([{"kind": "flow", "ref": "flow:1:hash"}]), field="verification_claim.evidence_refs"),
                enc("[]", field="verification_claim.plan"),
                1.0,
            ),
        )
        conn.execute(
            "INSERT INTO verification_claim(record_id, claim_key, state, evidence_refs, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record_id,
                "impact",
                "partially_verified",
                enc(json.dumps([{"kind": "flow", "ref": "flow:1:hash"}]), field="verification_claim.evidence_refs"),
                enc("[]", field="verification_claim.plan"),
                1.0,
            ),
        )
    artifact = V3ReportGenerator(database, crypto, triage=triage, finding_renderer=_Renderer()).render_scan(scan_id)
    assert "Overall: `partially_verified`" in artifact.markdown
    assert f"Verification artifact: `{'a' * 64}`" in artifact.markdown
    assert "`technical_detail`: `verified`" in artifact.markdown
    assert "`impact`: `partially_verified`" in artifact.markdown
