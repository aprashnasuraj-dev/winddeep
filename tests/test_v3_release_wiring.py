"""V3 R1-R5 acceptance contract: freeze, migration, pipeline, verification."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.contracts import PUBLIC_CONTRACTS, V3_EVENT_TYPES, frozen_contract_manifest
from app.v3.pipeline import V3PipelineCoordinator, V3_STAGE_ORDER
from app.v3.release_migration import apply_v3_release_migration, revert_v3_release_migration
from app.v3.verification import VerificationError, VerificationPass

ROOT = Path(__file__).resolve().parents[1]


def _db(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    result = apply_v3_release_migration(database.path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    artifacts = RawArtifactStore(database, crypto, audit)
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v3:fixture", ["fixture"])
    return crypto, database, audit, artifacts, target_id, scan_id, result


def test_public_contracts_are_frozen_for_v3() -> None:
    assert PUBLIC_CONTRACTS == {
        "sse": "windeep.sse.v1",
        "har_extension": "windeep.har-extension.v1",
        "evidence_bundle": "windeep.evidence-bundle.v1",
        "artifact": "windeep.artifact.v1",
        "report": "windeep.report.v1",
        "verification": "windeep.verification.v1",
    }
    assert V3_EVENT_TYPES == (
        "finding",
        "progress",
        "log",
        "evidence",
        "chain",
        "ranked",
        "verification",
        "disposition",
        "target",
    )
    first = frozen_contract_manifest()
    second = frozen_contract_manifest()
    assert first == second
    assert first["release"] == "3.0.0"
    assert len(first["manifest_sha256"]) == 64


def test_0030_python_migration_up_down_preserves_evidence(tmp_path: Path) -> None:
    _crypto, database, _audit, artifacts, _target_id, scan_id, result = _db(tmp_path)
    assert result.version == 30
    assert result.direction == "up"
    with database._connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    required = {
        "v3_contract_freeze",
        "v3_pipeline_checkpoint",
        "v3_scan_transitions",
        "verification_record",
        "verification_claim",
        "v3_targets",
        "handling_policy",
        "handling_rule",
        "handling_classification",
    }
    assert required.issubset(tables)
    evidence = artifacts.put(
        scan_id=scan_id,
        tool_run_id=None,
        kind="verification.fixture",
        media_type="application/json",
        content=b'{"proof":"retained"}',
        reason="v3 migration rollback fixture",
    )
    with database._connect() as conn:
        conn.execute(
            "INSERT INTO verification_record(finding_id, scan_id, bundle_sha256, artifact_sha256, schema_version, created_at) VALUES (NULL, ?, ?, ?, ?, ?)",
            (scan_id, "a" * 64, evidence.sha256, "windeep.verification.v1", 1.0),
        )
    down = revert_v3_release_migration(database.path)
    assert down.direction == "down"
    with database._connect() as conn:
        record = conn.execute("SELECT artifact_sha256 FROM verification_record WHERE scan_id = ?", (scan_id,)).fetchone()
        marker = conn.execute("SELECT COUNT(*) FROM v3_release_migrations WHERE version = 30 AND active = 1").fetchone()[0]
    assert record["artifact_sha256"] == evidence.sha256
    assert marker == 0
    reup = apply_v3_release_migration(database.path)
    assert reup.direction == "up"


def test_v3_pipeline_emits_every_transition_and_resumes_committed_stage(tmp_path: Path) -> None:
    _crypto, database, audit, _artifacts, _target_id, scan_id, _result = _db(tmp_path)
    events: list[tuple[str, str, str]] = []
    calls: list[str] = []

    def event_sink(event_type: str, payload: dict) -> None:
        events.append((event_type, payload["stage"], payload["status"]))

    coordinator = V3PipelineCoordinator(database=database, audit=audit, event_sink=event_sink)
    callbacks = {}
    for stage in V3_STAGE_ORDER:
        def callback(stage=stage):
            calls.append(stage)
            return {"stage": stage, "ok": True}
        callbacks[stage] = callback

    result = coordinator.run(scan_id=scan_id, stages=callbacks, cancel_check=lambda: False)
    assert result["status"] == "completed"
    assert calls == list(V3_STAGE_ORDER)
    expected = [("progress", stage, status) for stage in V3_STAGE_ORDER for status in ("started", "completed")]
    assert events == expected

    calls.clear()
    events.clear()
    resumed = coordinator.run(scan_id=scan_id, stages=callbacks, cancel_check=lambda: False)
    assert resumed["status"] == "completed"
    assert calls == []
    assert events == [("progress", stage, "resumed") for stage in V3_STAGE_ORDER]
    with database._connect() as conn:
        transitions = conn.execute("SELECT stage, status FROM v3_scan_transitions WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    assert transitions
    assert {row["status"] for row in transitions}.issubset({"started", "completed", "resumed"})


def test_v3_pipeline_refuses_missing_callbacks_and_supports_cancellation_and_budget(tmp_path: Path) -> None:
    _crypto, database, audit, _artifacts, _target_id, scan_id, _result = _db(tmp_path)
    events: list[tuple[str, str]] = []
    coordinator = V3PipelineCoordinator(
        database=database,
        audit=audit,
        event_sink=lambda _kind, payload: events.append((payload["stage"], payload["status"])),
    )
    with pytest.raises(ValueError, match="missing v3 pipeline stage"):
        coordinator.run(scan_id=scan_id, stages={}, cancel_check=lambda: False)

    callbacks = {stage: (lambda stage=stage: {"stage": stage}) for stage in V3_STAGE_ORDER}
    cancelled = coordinator.run(scan_id=scan_id, stages=callbacks, cancel_check=lambda: True)
    assert cancelled["status"] == "cancelled"
    assert events[-1] == ("scope_consent", "cancelled")

    class Budget:
        def __init__(self) -> None:
            self.calls = 0

        def check_wall_clock(self) -> None:
            self.calls += 1

    with database._connect() as conn:
        target_id = int(conn.execute("SELECT target_id FROM scans WHERE id = ?", (scan_id,)).fetchone()["target_id"])
    scan2 = database.create_scan(target_id, "v3:fixture", ["fixture"])
    budget = Budget()
    completed = coordinator.run(scan_id=scan2, stages=callbacks, cancel_check=lambda: False, budget=budget)
    assert completed["status"] == "completed"
    assert budget.calls == len(V3_STAGE_ORDER)


def test_verification_pass_writes_hash_addressed_record_for_every_claim(tmp_path: Path) -> None:
    _crypto, database, _audit, artifacts, target_id, scan_id, _result = _db(tmp_path)
    finding_id, _ = database.create_finding(
        target_id,
        "Observed authorization inconsistency",
        "high",
        scan_id=scan_id,
        vuln_type="authorization",
        tool="fixture",
        endpoint="https://example.test/api/7",
        description="Captured response differs between authorized roles.",
        evidence={},
        confidence=0.9,
        impact="Recorded data from another authorized role was visible.",
        steps="Replay the captured read-only request and compare the recorded response.",
    )
    bundle = {
        "bundle_sha256": "b" * 64,
        "exploitability": "observed",
        "flows": [{"id": 11, "sha256": "c" * 64, "method": "GET", "url": "https://example.test/api/7", "status": 200}],
        "tool_output": {"artifact_sha256": "d" * 64, "line_start": 4, "line_end": 5, "slice_sha256": "e" * 64},
        "reproduction": {"replay_handle": f"flow:11:{'c' * 64}", "steps": ["Replay captured GET request."], "plan": []},
        "provenance": {"nodes": [{"id": "detector:x", "kind": "detector", "name": "fixture", "version": "1", "detector_id": "x"}], "edges": []},
        "completeness": {"closed": True, "score": 1.0, "missing": []},
    }
    verifier = VerificationPass(database, artifacts)
    first = verifier.verify_finding(finding_id=finding_id, scan_id=scan_id, bundle=bundle)
    second = verifier.verify_finding(finding_id=finding_id, scan_id=scan_id, bundle=bundle)
    assert first["artifact_sha256"] == second["artifact_sha256"]
    assert first["schema"] == "windeep.verification.v1"
    assert [claim["claim"] for claim in first["claims"]] == ["title", "affected_asset", "technical_detail", "impact", "reproduction"]
    assert all(claim["state"] in {"verified", "partially_verified", "needs-review"} for claim in first["claims"])
    assert all(claim["evidence_refs"] or claim["state"] == "needs-review" for claim in first["claims"])
    resolved = verifier.resolve(finding_id)
    assert resolved["artifact_sha256"] == first["artifact_sha256"]
    assert resolved["record_sha256"] == first["record_sha256"]


def test_verification_refuses_missing_bundle_and_unplanned_needs_review(tmp_path: Path) -> None:
    _crypto, database, _audit, artifacts, target_id, scan_id, _result = _db(tmp_path)
    finding_id, _ = database.create_finding(target_id, "candidate", "medium", scan_id=scan_id, evidence={})
    verifier = VerificationPass(database, artifacts)
    with pytest.raises(VerificationError, match="closed evidence bundle"):
        verifier.verify_finding(finding_id=finding_id, scan_id=scan_id, bundle={})
    bad_bundle = {
        "bundle_sha256": "f" * 64,
        "exploitability": "needs-human-review",
        "flows": [],
        "tool_output": None,
        "reproduction": {"steps": [], "plan": []},
        "provenance": {"nodes": [], "edges": []},
        "completeness": {"closed": True},
    }
    with pytest.raises(VerificationError, match="human-review plan"):
        verifier.verify_finding(finding_id=finding_id, scan_id=scan_id, bundle=bad_bundle)


def test_changelog_has_v3_breaking_changes_and_phase_map() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [3.0.0]" in text
    assert "### Breaking changes" in text
    for phase in range(9):
        assert f"P{phase}" in text
