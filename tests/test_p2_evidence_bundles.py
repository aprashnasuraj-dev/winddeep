"""P2 acceptance tests for deterministic self-proving evidence bundles."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.evidence.bundles import (
    BundleIncompleteError,
    EvidenceBundleStore,
    EvidenceIntegrityError,
)
from app.migrations import MigrationManager
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase

ROOT = Path(__file__).resolve().parents[1]


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
    finding_id, _created = database.create_finding(
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
            "request_headers": {"Accept": "application/json"},
            "request_body": b"",
            "status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": b'{"id":7,"owner":"fixture"}',
            "timing_ms": 12.5,
            "tls_info": {"sni": "example.test", "alpn": "h2"},
            "tags": ["fixture"],
            "created_at": 1_700_000_000.0,
        }
    )
    finding = database.get_finding(finding_id)
    assert finding is not None
    return crypto, database, target_id, scan_id, run_id, finding, flow_id


def _provenance() -> dict:
    return {
        "nodes": [
            {
                "id": "detector:fixture.read.diff",
                "kind": "detector",
                "name": "fixture",
                "version": "1.0.0",
                "detector_id": "fixture.read.diff",
                "source": "fixture-pack",
                "source_digest": "a" * 64,
            }
        ],
        "edges": [],
    }


def test_complete_high_bundle_is_deterministic_and_flow_bound(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    raw = b"header\nObserved authorization inconsistency\nfooter\n"
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=raw,
    )
    first = store.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"],
        line_start=2,
        line_end=2,
        provenance=_provenance(),
        exploitability="observed",
        close=True,
    )
    second = store.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"],
        line_start=2,
        line_end=2,
        provenance=_provenance(),
        exploitability="observed",
        close=True,
    )
    assert first["schema"] == "windeep.evidence-bundle.v1"
    assert first["bundle_sha256"] == second["bundle_sha256"]
    assert first["canonical_json"] == second["canonical_json"]
    assert first["completeness"]["closed"] is True
    assert first["completeness"]["score"] == 1.0
    assert first["flows"][0]["id"] == flow_id
    assert len(first["flows"][0]["sha256"]) == 64
    assert first["tool_output"]["line_start"] == 2
    assert first["tool_output"]["line_end"] == 2
    assert first["reproduction"]["steps"][0].startswith("Send the captured GET request")
    assert first["exploitability"] == "observed"
    assert first["confidence"]["band"] == "high"
    with database._connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM evidence_bundles").fetchone()["n"] == 1


def test_high_bundle_refuses_to_close_without_flow_and_provenance(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, _flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"Observed authorization inconsistency\n",
    )
    incomplete = store.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[],
        artifact_sha256=artifact["sha256"],
        line_start=1,
        line_end=1,
        provenance={"nodes": [], "edges": []},
        exploitability="observed",
        close=False,
    )
    assert incomplete["completeness"]["closed"] is False
    assert "flow" in incomplete["completeness"]["missing"]
    assert "provenance" in incomplete["completeness"]["missing"]
    with pytest.raises(BundleIncompleteError):
        store.build(
            finding=finding,
            scan_id=scan_id,
            tool_run_id=run_id,
            flow_ids=[],
            artifact_sha256=artifact["sha256"],
            line_start=1,
            line_end=1,
            provenance={"nodes": [], "edges": []},
            exploitability="observed",
            close=True,
        )


def test_artifact_corruption_and_invalid_slice_fail_closed(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"one\ntwo\n",
    )
    with pytest.raises(ValueError, match="line range"):
        store.build(
            finding=finding,
            scan_id=scan_id,
            tool_run_id=run_id,
            flow_ids=[flow_id],
            artifact_sha256=artifact["sha256"],
            line_start=3,
            line_end=3,
            provenance=_provenance(),
            exploitability="observed",
        )

    tampered = crypto.encrypt_text(
        base64.b64encode(b"changed\n").decode("ascii"),
        aad=f"windeep:evidence-blob:{artifact['sha256']}".encode("utf-8"),
    )
    with database._connect() as conn:
        conn.execute("UPDATE evidence_blobs SET payload = ? WHERE sha256 = ?", (tampered, artifact["sha256"]))
    with pytest.raises(EvidenceIntegrityError):
        store.read_artifact(artifact["sha256"])


def test_human_review_bundle_uses_observation_plan_and_closed_enum(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"candidate requires manual validation\n",
    )
    bundle = store.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"],
        line_start=1,
        line_end=1,
        provenance=_provenance(),
        exploitability="needs-human-review",
        human_plan=["Compare the two authorized read-only role responses manually."],
        close=True,
    )
    assert bundle["exploitability"] == "needs-human-review"
    assert bundle["reproduction"]["plan"] == ["Compare the two authorized read-only role responses manually."]
    assert "confirmed" not in bundle["canonical_json"]
    with pytest.raises(ValueError, match="exploitability"):
        store.build(
            finding=finding,
            scan_id=scan_id,
            tool_run_id=run_id,
            flow_ids=[flow_id],
            artifact_sha256=artifact["sha256"],
            line_start=1,
            line_end=1,
            provenance=_provenance(),
            exploitability="confirmed",
        )


def test_resolve_revalidates_artifact_and_flow_hashes(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"Observed authorization inconsistency\n",
    )
    built = store.build(
        finding=finding,
        scan_id=scan_id,
        tool_run_id=run_id,
        flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"],
        line_start=1,
        line_end=1,
        provenance=_provenance(),
        exploitability="observed",
        close=True,
    )
    resolved = store.resolve(int(finding["id"]))
    assert resolved["bundle_sha256"] == built["bundle_sha256"]
    assert json.loads(resolved["canonical_json"])["finding"]["fingerprint"] == finding["fingerprint"]

    with database._connect() as conn:
        conn.execute("UPDATE flows SET path = ? WHERE id = ?", ("/tampered", flow_id))
    with pytest.raises(EvidenceIntegrityError, match="flow"):
        store.resolve(int(finding["id"]))


def test_validation_branches_and_append_only_supersession(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"one\ntwo\n",
    )
    # Content addressing is stable and duplicate insertion verifies rather than rewrites.
    assert store.put_artifact(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="raw_tool_output",
        media_type="text/plain",
        content=b"one\ntwo\n",
    )["sha256"] == artifact["sha256"]
    with pytest.raises(KeyError):
        store.read_artifact("0" * 64)
    with pytest.raises(ValueError, match="line range"):
        store.build(
            finding=finding, scan_id=scan_id, tool_run_id=run_id,
            flow_ids=[flow_id], artifact_sha256=artifact["sha256"],
            line_start=None, line_end=1, provenance=_provenance(), exploitability="observed"
        )
    with pytest.raises(ValueError, match="nodes"):
        store.build(
            finding=finding, scan_id=scan_id, tool_run_id=run_id,
            flow_ids=[flow_id], artifact_sha256=artifact["sha256"],
            line_start=1, line_end=1, provenance={"nodes": "bad", "edges": []}, exploitability="observed"
        )
    with pytest.raises(ValueError, match="missing version"):
        store.build(
            finding=finding, scan_id=scan_id, tool_run_id=run_id,
            flow_ids=[flow_id], artifact_sha256=artifact["sha256"],
            line_start=1, line_end=1,
            provenance={"nodes": [{"id": "x", "kind": "detector", "name": "x", "detector_id": "x"}], "edges": []},
            exploitability="observed"
        )
    with pytest.raises(KeyError):
        store.resolve(999999)

    first = store.build(
        finding=finding, scan_id=scan_id, tool_run_id=run_id,
        flow_ids=[flow_id], artifact_sha256=artifact["sha256"],
        line_start=1, line_end=1, provenance=_provenance(), exploitability="observed", close=True
    )
    changed_provenance = _provenance()
    changed_provenance["nodes"][0]["source_digest"] = "b" * 64
    second = store.build(
        finding=finding, scan_id=scan_id, tool_run_id=run_id,
        flow_ids=[flow_id], artifact_sha256=artifact["sha256"],
        line_start=1, line_end=1, provenance=changed_provenance, exploitability="observed", close=True
    )
    assert first["bundle_sha256"] != second["bundle_sha256"]
    with database._connect() as conn:
        rows = conn.execute("SELECT id, supersedes_id FROM evidence_bundles ORDER BY id").fetchall()
    assert len(rows) == 2
    assert rows[1]["supersedes_id"] == rows[0]["id"]


def test_reflection_and_browser_require_specialized_evidence(tmp_path: Path) -> None:
    crypto, database, _target_id, scan_id, run_id, finding, flow_id = _fixture(tmp_path)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(
        scan_id=scan_id, tool_run_id=run_id, kind="raw_tool_output", media_type="text/plain", content=b"marker observed\n"
    )
    screenshot = store.put_artifact(
        scan_id=scan_id, tool_run_id=run_id, kind="screenshot", media_type="image/png", content=b"fake-png-fixture"
    )
    reflected = dict(finding)
    reflected["title"] = "Reflected marker observation"
    reflected["vuln_type"] = "reflected_marker"
    reflected["evidence"] = {"browser_observed": True}
    incomplete = store.build(
        finding=reflected, scan_id=scan_id, tool_run_id=run_id, flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"], line_start=1, line_end=1,
        provenance=_provenance(), exploitability="observed", close=False
    )
    assert {"reflected_marker", "browser_observation"}.issubset(incomplete["completeness"]["missing"])
    complete = store.build(
        finding=reflected, scan_id=scan_id, tool_run_id=run_id, flow_ids=[flow_id],
        artifact_sha256=artifact["sha256"], line_start=1, line_end=1,
        provenance=_provenance(), exploitability="observed",
        reflected_marker={"marker": "WINDEEP-INERT-1", "in_dom": True, "in_text": True},
        browser_observation={"screenshot_sha256": screenshot["sha256"], "final_url": "https://example.test/", "status": 200, "viewport": {"width": 1280, "height": 720}},
        close=True,
    )
    assert complete["completeness"]["score"] == 1.0
