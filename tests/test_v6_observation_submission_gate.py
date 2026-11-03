"""V6 hardening regressions for recon observations and submission proof gating."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.evidence.raw_store import RawArtifactStore
from app.reporting.submission import SubmissionDraftGenerator
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v2_pipeline import AssetObservationStore, FindingBatchWriter
from app.v3.triage import ManualTriage
from app.v3.verification import VerificationPass
from test_p3_reporting import ROOT, _fixture


def test_all_recon_integrations_are_observations_not_findings() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    recon = {
        name: cls
        for name, cls in classes.items()
        if cls.category in {"recon_passive", "recon_active"}
    }
    assert len(recon) == 45
    assert all(cls.result_role == "observation" for cls in recon.values())
    assert all(cls.scan_default for cls in recon.values())


def test_587_item_recon_noise_shape_creates_zero_findings(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    target_id = database.create_target("noise", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["gau", "getjs", "dig", "whois"])
    store = AssetObservationStore(database)
    store.ensure_schema()

    shapes = {
        "gau": [f"https://example.test/archive/{index}" for index in range(500)],
        "getjs": [f"https://cdn.example.test/app-{index}.js" for index in range(82)],
        "dig": [f"DNS record {index}" for index in range(4)],
        "whois": ["RDAP record for example.test"],
    }
    for tool_name, values in shapes.items():
        run_id = database.create_tool_run(
            tool_name=tool_name,
            status="completed",
            scan_id=scan_id,
            target_id=target_id,
            command=[tool_name, "<scope-bound target>"],
        )
        store.persist(
            scan_id=scan_id,
            tool_run_id=run_id,
            tool_name=tool_name,
            observations=[
                {
                    "title": value,
                    "endpoint": value if value.startswith("http") else "example.test",
                    "evidence": {"adapter": "wayback_cdx" if tool_name == "gau" else tool_name},
                }
                for value in values
            ],
        )

    rows = store.list_scan(scan_id)
    assert len(rows) == 587
    assert sum(item["temporal_scope"] == "historical" for item in rows) == 500
    assert all(item["submission_candidate"] is False for item in rows)
    assert all(item["result_role"] == "observation" for item in rows)
    assert database.list_findings(target_id=target_id, limit=5000) == []


def test_finding_writer_fails_closed_on_misrouted_observation(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    target_id = database.create_target("noise", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["gau"])
    run_id = database.create_tool_run(
        tool_name="gau",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["gau", "<scope-bound target>"],
    )
    writer = FindingBatchWriter(database)
    writer.ensure_schema()
    with pytest.raises(ValueError, match="observation reached FindingBatchWriter"):
        writer.persist(
            scan_id=scan_id,
            tool_run_id=run_id,
            target_id=target_id,
            tool_name="gau",
            findings=[
                {
                    "title": "https://example.test/archive",
                    "endpoint": "https://example.test/archive",
                    "result_role": "observation",
                    "submission_candidate": False,
                    "evidence": {"result_role": "observation", "submission_candidate": False},
                }
            ],
        )
    assert database.list_findings(target_id=target_id, limit=100) == []


def test_submission_candidate_requires_verification_and_actionable_triage(tmp_path: Path) -> None:
    crypto, database, generator, _target_id, scan_id, finding_id, _second_id, _flow_id, _second_flow = _fixture(tmp_path)
    database.update_scan(scan_id, status="completed")

    blocked = SubmissionDraftGenerator(generator).render_finding(
        finding_id,
        scan_id=scan_id,
        scan_status="completed",
    )
    blocked_readiness = blocked.model["submission_readiness"]
    assert blocked_readiness["submission_candidate"] is False
    assert "claim_verification_not_recorded" in blocked_readiness["blocking_reasons"]
    assert "tester_triage_not_recorded" in blocked_readiness["blocking_reasons"]

    finding = database.get_finding(finding_id)
    assert finding is not None
    with database._connect() as conn:
        conn.execute(
            "UPDATE findings SET steps = ? WHERE id = ?",
            (
                database._enc(
                    "1. Replay the captured authorized request.\n2. Compare the captured cross-role response with the expected owner-only result.",
                    field="finding.steps",
                ),
                finding_id,
            ),
        )

    audit = AuditLog(tmp_path / "audit" / "v6-proof-gate.jsonl")
    raw_store = RawArtifactStore(database, crypto, audit)
    bundle = generator.evidence.resolve(finding_id, scan_id=scan_id)
    record = VerificationPass(database, raw_store).verify_finding(
        finding_id=finding_id,
        scan_id=scan_id,
        bundle=bundle,
    )
    assert {claim["claim"]: claim["state"] for claim in record["claims"]}["reproduction"] == "verified"

    triage = ManualTriage(database, audit)
    triage.classify(
        finding_id,
        disposition="actionable",
        tester_priority=90,
        duplicate_risk="low",
        rationale="Controlled fixture demonstrates an authorization boundary difference with captured evidence.",
        asset_class="https",
    )

    candidate = SubmissionDraftGenerator(generator).render_finding(
        finding_id,
        scan_id=scan_id,
        scan_status="completed",
    )
    readiness = candidate.model["submission_readiness"]
    assert readiness["state"] == "candidate_for_human_approval"
    assert readiness["submission_candidate"] is True
    assert readiness["human_approval_required"] is True
    assert readiness["blocking_reasons"] == []
    assert readiness["verification"]["claims"]["impact"] in {"verified", "partially_verified"}

    # A legacy/misclassified reconnaissance record must remain non-submittable
    # even after claim verification and actionable tester triage.
    with database._connect() as conn:
        conn.execute(
            "UPDATE findings SET vuln_type = ?, evidence = ? WHERE id = ?",
            (
                "builtin_fallback",
                database._enc(
                    json.dumps(
                        {"result_role": "observation", "submission_candidate": False},
                        sort_keys=True,
                    ),
                    field="finding.evidence",
                ),
                finding_id,
            ),
        )
    legacy_recon = SubmissionDraftGenerator(generator).render_finding(
        finding_id,
        scan_id=scan_id,
        scan_status="completed",
    )
    recon_readiness = legacy_recon.model["submission_readiness"]
    assert recon_readiness["submission_candidate"] is False
    assert "source_is_reconnaissance_observation" in recon_readiness["blocking_reasons"]
    assert "source_explicitly_not_submission_candidate" in recon_readiness["blocking_reasons"]
    assert "source_type_builtin_fallback_is_not_vulnerability_proof" in recon_readiness["blocking_reasons"]
