"""P3 acceptance tests: evidence-only, deterministic, triager-ready reporting."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.evidence.bundles import EvidenceBundleStore
from app.migrations import MigrationManager
from app.reporting import (
    CVSS31_METRICS,
    ExportBundleBuilder,
    ReportGenerator,
    ReportingError,
    score_cvss31,
)
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.submissions import REPORT_SUBMISSION_STATUSES, ReportSubmissionError, ReportSubmissionTracker

ROOT = Path(__file__).resolve().parents[1]


def _provenance(detector_id: str) -> dict:
    return {
        "nodes": [
            {
                "id": f"detector:{detector_id}",
                "kind": "detector",
                "name": "fixture-engine",
                "version": "3.0.0",
                "detector_id": detector_id,
                "source": "fixture-pack",
                "source_digest": "a" * 64,
                "reference": "WDE-TEST-1",
            }
        ],
        "edges": [],
    }


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    run_id = database.create_tool_run(
        tool_name="fixture",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["fixture", "<scope-bound target>"],
    )
    finding_id, _ = database.create_finding(
        target_id,
        "Observed authorization inconsistency",
        "high",
        scan_id=scan_id,
        vuln_type="authorization",
        tool="fixture",
        endpoint="https://example.test/api/object/7",
        description="Read-only response differed from the authorized baseline.",
        evidence={"detector_id": "fixture.read.diff"},
        confidence=0.91,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        impact="Recorded cross-role read behavior exposes data from another authorized role context.",
        remediation="Enforce object authorization on every read using the server-side principal and object owner.",
    )
    flow_id = database.insert_flow(
        {
            "target_id": target_id,
            "scan_id": scan_id,
            "method": "GET",
            "url": "https://example.test/api/object/7",
            "scheme": "https",
            "host": "example.test",
            "port": 443,
            "path": "/api/object/7",
            "query": "",
            "request_headers": {"Accept": "application/json", "Authorization": "Bearer request-super-secret"},
            "request_body": b"",
            "status": 200,
            "response_headers": {"Content-Type": "application/json", "Set-Cookie": "session=response-cookie-secret"},
            "response_body": b'{"id":7,"owner":"fixture","token":"response-super-secret"}',
            "timing_ms": 12.5,
            "tls_info": {"sni": "example.test", "alpn": "h2"},
            "tags": ["fixture"],
            "created_at": 1_700_000_000.0,
        }
    )
    evidence = EvidenceBundleStore(database, crypto)
    raw = evidence.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"Observed authorization inconsistency\nAuthorization: Bearer artifact-super-secret\n",
    )
    finding = database.get_finding(finding_id)
    assert finding is not None
    evidence.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[flow_id],
        artifact_sha256=raw["sha256"],
        line_start=1,
        line_end=2,
        provenance=_provenance("fixture.read.diff"),
        exploitability="observed",
        close=True,
    )

    second_id, _ = database.create_finding(
        target_id,
        "Sensitive metadata disclosure",
        "medium",
        scan_id=scan_id,
        vuln_type="information_disclosure",
        tool="fixture",
        endpoint="https://example.test/api/object/7/meta",
        description="Captured response included metadata not present in the baseline response.",
        evidence={"detector_id": "fixture.meta.diff"},
        confidence=0.82,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        impact="Recorded metadata exposure reveals fields present in the captured response.",
        remediation="Return only metadata fields required by the authorized caller.",
    )
    second_flow = database.insert_flow(
        {
            "target_id": target_id,
            "scan_id": scan_id,
            "method": "GET",
            "url": "https://example.test/api/object/7/meta",
            "scheme": "https",
            "host": "example.test",
            "port": 443,
            "path": "/api/object/7/meta",
            "query": "",
            "request_headers": {"Accept": "application/json"},
            "request_body": b"",
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": b'{"classification":"internal"}',
            "timing_ms": 8.0,
            "tls_info": {"sni": "example.test", "alpn": "h2"},
            "tags": ["fixture"],
            "created_at": 1_700_000_001.0,
        }
    )
    second_artifact = evidence.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"Sensitive metadata disclosure\n",
    )
    second = database.get_finding(second_id)
    assert second is not None
    evidence.build(
        finding=second,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[second_flow],
        artifact_sha256=second_artifact["sha256"],
        line_start=1,
        line_end=1,
        provenance=_provenance("fixture.meta.diff"),
        exploitability="observed",
        close=True,
    )
    with database._connect() as conn:
        conn.execute(
            "INSERT INTO chains(target_id, scan_id, source_finding_id, target_finding_id, edge_type, weight, rationale, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (target_id, scan_id, finding_id, second_id, "amplifies", 0.8, "Captured authorization behavior amplifies the metadata exposure.", 1_700_000_002.0),
        )
    generator = ReportGenerator(database, crypto)
    return crypto, database, generator, target_id, scan_id, finding_id, second_id, flow_id, second_flow


def test_cvss31_metric_table_and_known_vectors() -> None:
    assert CVSS31_METRICS["AV"] == {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    assert CVSS31_METRICS["AC"] == {"L": 0.77, "H": 0.44}
    assert CVSS31_METRICS["UI"] == {"N": 0.85, "R": 0.62}
    assert CVSS31_METRICS["CIA"] == {"H": 0.56, "L": 0.22, "N": 0.0}
    assert CVSS31_METRICS["PR"]["U"] == {"N": 0.85, "L": 0.62, "H": 0.27}
    assert CVSS31_METRICS["PR"]["C"] == {"N": 0.85, "L": 0.68, "H": 0.50}
    assert score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "critical")
    assert score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") == (5.3, "medium")
    baseline = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
    option_table = {
        "AV": tuple(CVSS31_METRICS["AV"]),
        "AC": tuple(CVSS31_METRICS["AC"]),
        "PR": ("N", "L", "H"),
        "UI": tuple(CVSS31_METRICS["UI"]),
        "S": ("U", "C"),
        "C": tuple(CVSS31_METRICS["CIA"]),
        "I": tuple(CVSS31_METRICS["CIA"]),
        "A": tuple(CVSS31_METRICS["CIA"]),
    }
    order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    for metric, values in option_table.items():
        for value in values:
            current = dict(baseline)
            current[metric] = value
            vector = "CVSS:3.1/" + "/".join(f"{key}:{current[key]}" for key in order)
            score, severity = score_cvss31(vector)
            assert 0.0 <= score <= 10.0
            assert severity in {"info", "low", "medium", "high", "critical"}


def test_finding_report_is_deterministic_self_contained_and_secret_free(tmp_path: Path) -> None:
    _crypto, _database, generator, _target_id, _scan_id, finding_id, _second_id, flow_id, _second_flow = _fixture(tmp_path)
    first = generator.render_finding(finding_id)
    second = generator.render_finding(finding_id)
    assert first.markdown == second.markdown
    assert first.html == second.html
    assert first.sha256 == second.sha256
    assert first.cvss_score == 8.1
    assert first.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    assert f"flow:{flow_id}:" in first.markdown
    assert "fixture.read.diff" in first.markdown
    assert "## Technical evidence" in first.markdown
    assert "## Observation-only reproduction" in first.markdown
    assert "## Impact" in first.markdown
    assert "## Remediation" in first.markdown
    assert "request-super-secret" not in first.markdown
    assert "response-cookie-secret" not in first.markdown
    assert "response-super-secret" not in first.markdown
    assert "artifact-super-secret" not in first.markdown
    assert "[REDACTED]" in first.markdown
    assert all(word not in first.markdown.casefold() for word in ("possibly", " may ", "could be"))
    assert "Generated:" not in first.markdown
    assert "<style>" in first.html
    assert '<link ' not in first.html.casefold()
    assert 'src="http' not in first.html.casefold()
    assert 'href="http' not in first.html.casefold()


def test_chain_report_orders_hops_states_max_severity_rule_and_dedup_context(tmp_path: Path) -> None:
    _crypto, database, generator, target_id, scan_id, finding_id, second_id, _flow_id, _second_flow = _fixture(tmp_path)
    older_id, _ = database.create_finding(
        target_id,
        "Observed authorization behavior inconsistency",
        "high",
        scan_id=scan_id,
        vuln_type="authorization",
        tool="fixture-old",
        endpoint="https://example.test/api/object/7",
        description="Earlier related observation.",
        evidence={},
        confidence=0.7,
    )
    with database._connect() as conn:
        conn.execute("UPDATE findings SET created_at = ?, updated_at = ? WHERE id = ?", (1_600_000_000.0, 1_600_000_000.0, older_id))
    report = generator.render_chain([finding_id, second_id])
    assert report.severity == "high"
    assert "Chain severity rule: maximum severity across all evidence-backed hops" in report.markdown
    assert "amplifies" in report.markdown
    assert report.markdown.index("Observed authorization inconsistency") < report.markdown.index("Sensitive metadata disclosure")
    assert "## Duplicate context" in report.markdown
    assert "first-seen scan" in report.markdown
    assert "external duplicate check: not provided" in report.markdown.lower()


def test_export_bundle_has_redacted_har_real_flow_refs_and_sha256_manifest(tmp_path: Path) -> None:
    _crypto, _database, generator, _target_id, _scan_id, finding_id, _second_id, flow_id, _second_flow = _fixture(tmp_path)
    builder = ExportBundleBuilder(generator)
    for platform in ("hackerone", "jira", "github"):
        export = builder.build_finding(finding_id, platform=platform)
        assert export.platform == platform
        assert "report.md" in export.files
        assert "report.html" in export.files
        assert "evidence.har" in export.files
        assert "manifest.json" in export.files
        combined = b"\n".join(export.files.values()).decode("utf-8", errors="ignore")
        assert "request-super-secret" not in combined
        assert "response-cookie-secret" not in combined
        assert "response-super-secret" not in combined
        assert "artifact-super-secret" not in combined
        har = json.loads(export.files["evidence.har"])
        entries = har["log"]["entries"]
        assert any(entry["_windeep_flow_id"] == flow_id for entry in entries)
        manifest = json.loads(export.files["manifest.json"])
        for item in manifest["files"]:
            name = item["name"]
            if name == "manifest.json":
                continue
            assert hashlib.sha256(export.files[name]).hexdigest() == item["sha256"]
        assert export.payload["title"] == "Observed authorization inconsistency"


def test_report_requires_real_bundle_and_revalidates_integrity(tmp_path: Path) -> None:
    crypto, database, generator, target_id, scan_id, _finding_id, _second_id, flow_id, _second_flow = _fixture(tmp_path)
    orphan_id, _ = database.create_finding(
        target_id,
        "Unbundled candidate",
        "low",
        scan_id=scan_id,
        vuln_type="fixture",
        tool="fixture",
        endpoint="https://example.test/orphan",
        description="No bundle exists.",
        evidence={},
        confidence=0.4,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    )
    with pytest.raises(ReportingError, match="bundle"):
        generator.render_finding(orphan_id)
    with database._connect() as conn:
        conn.execute("UPDATE flows SET path = ? WHERE id = ?", ("/tampered", flow_id))
    with pytest.raises(ReportingError, match="integrity"):
        generator.render_finding(_finding_id)


def test_submission_lifecycle_is_audited_and_non_regressing(tmp_path: Path) -> None:
    crypto, database, generator, _target_id, _scan_id, finding_id, _second_id, _flow_id, _second_flow = _fixture(tmp_path)
    export = ExportBundleBuilder(generator).build_finding(finding_id, platform="github")
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    tracker = ReportSubmissionTracker(database, audit)
    assert REPORT_SUBMISSION_STATUSES == ("draft", "queued", "submitted", "acknowledged", "closed")
    submission_id = tracker.create(
        platform="github",
        report_sha256=export.report_sha256,
        finding_id=finding_id,
        payload=export.payload,
    )
    states = [tracker.get(submission_id)["status"]]
    for state in REPORT_SUBMISSION_STATUSES[1:]:
        states.append(tracker.transition(submission_id, state)["status"])
    assert states == list(REPORT_SUBMISSION_STATUSES)
    with pytest.raises(ReportSubmissionError, match="invalid transition"):
        tracker.transition(submission_id, "submitted")
    history = tracker.history(submission_id)
    assert [item["to_status"] for item in history] == list(REPORT_SUBMISSION_STATUSES)
    ok, count = audit.verify_chain()
    assert ok is True
    assert count == len(REPORT_SUBMISSION_STATUSES)
