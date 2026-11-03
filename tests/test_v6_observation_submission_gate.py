"""V6 hardening regressions for recon observations and submission proof gating."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.reporting.submission import SubmissionDraftGenerator
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.security.scope import ScopeEnforcer
from app.tools import builtin_fallbacks
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


def test_root_target_tools_continue_after_upstream_recon_failure_contract() -> None:
    source = (ROOT / "app" / "v2_pipeline.py").read_text(encoding="utf-8")
    start = source.index("async def run_tool(scan_context")
    end = source.index("run_id = database.create_tool_run", start)
    runner_prefix = source[start:end]
    assert "_dependency_failures(dependencies)" in runner_prefix
    assert "_successful_dependencies(dependencies)" not in runner_prefix
    assert "Continuing" in runner_prefix and "authorized root" in runner_prefix

    dedup_start = source.index("async def dedup_stage")
    dedup_end = source.index("async def chain_stage", dedup_start)
    dedup_source = source[dedup_start:dedup_end]
    assert "_successful_dependencies(dependencies)" not in dedup_source


@pytest.mark.asyncio
async def test_wayback_inventory_paginates_until_resume_key_is_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str]] = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return self._payload

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, _url, *, params, headers):
            del headers
            snapshot = {str(key): str(value) for key, value in params.items()}
            calls.append(snapshot)
            if "resumeKey" not in snapshot:
                return FakeResponse(
                    [
                        ["original", "statuscode", "timestamp"],
                        ["https://example.test/a", "200", "20200101000000"],
                        [],
                        ["next-page"],
                    ]
                )
            assert snapshot["resumeKey"] == "next-page"
            return FakeResponse(
                [
                    ["original", "statuscode", "timestamp"],
                    ["https://example.test/b", "200", "20210101000000"],
                ]
            )

    monkeypatch.setattr(builtin_fallbacks.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(builtin_fallbacks.asyncio, "sleep", lambda *_args, **_kwargs: _noop_async())
    rows = await builtin_fallbacks.run_adapter("wayback_cdx", "example.test", requested_name="gau")
    assert [row["endpoint"] for row in rows] == [
        "https://example.test/a",
        "https://example.test/b",
    ]
    assert len(calls) == 2
    assert calls[0]["limit"] == "5000"
    assert calls[0]["showResumeKey"] == "true"


async def _noop_async() -> None:
    return None


def test_discovered_scope_relation_is_classification_only_and_never_filters_observations(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    target_id = database.create_target(
        "scope-fixture",
        "domain",
        "example.test",
        scope=["example.test", "*.example.test"],
        out_of_scope=["blocked.example.test"],
    )
    before = database.get_target(target_id)
    assert before is not None
    scan_id = database.create_scan(target_id, "v2:selected", ["gau"])
    run_id = database.create_tool_run(
        tool_name="gau",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["gau", "<scope-bound target>"],
    )
    scope = ScopeEnforcer(
        target="example.test",
        allow=["example.test", "*.example.test"],
        deny=["blocked.example.test"],
    )
    store = AssetObservationStore(database)
    store.ensure_schema()
    rows = store.persist(
        scan_id=scan_id,
        tool_run_id=run_id,
        tool_name="gau",
        scope_check=scope.is_allowed,
        observations=[
            {"title": "root", "endpoint": "https://example.test/a", "evidence": {"adapter": "wayback_cdx"}},
            {"title": "subdomain", "endpoint": "https://api.example.test/a", "evidence": {"adapter": "wayback_cdx"}},
            {"title": "explicit deny", "endpoint": "https://blocked.example.test/a", "evidence": {"adapter": "wayback_cdx"}},
            {"title": "external", "endpoint": "https://third-party.invalid/a", "evidence": {"adapter": "wayback_cdx"}},
        ],
    )
    assert len(rows) == 4
    assert [row["authorization_relation"] for row in rows].count("in_scope") == 2
    assert [row["authorization_relation"] for row in rows].count("out_of_scope") == 2
    assert all(row["temporal_scope"] == "historical" for row in rows)
    assert all(row["submission_candidate"] is False for row in rows)
    assert database.list_findings(target_id=target_id, limit=100) == []

    # Recon discoveries are inventory only: they must not rewrite the operator's
    # allow/deny configuration or turn an external archive URL into scan scope.
    after = database.get_target(target_id)
    assert after is not None
    assert after["scope"] == before["scope"]
    assert after["out_of_scope"] == before["out_of_scope"]

    # Line-parser observations bind endpoint to the invocation root.  The scope
    # classifier must use the discovered raw/title value instead, without
    # filtering either record.
    line_run = database.create_tool_run(
        tool_name="subfinder",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["subfinder", "<scope-bound target>"],
    )
    line_rows = store.persist(
        scan_id=scan_id,
        tool_run_id=line_run,
        tool_name="subfinder",
        scope_check=scope.is_allowed,
        observations=[
            {
                "title": "api.example.test",
                "endpoint": "example.test",
                "evidence": {"raw": "api.example.test"},
            },
            {
                "title": "external.invalid",
                "endpoint": "example.test",
                "evidence": {"raw": "external.invalid"},
            },
        ],
    )
    by_candidate = {row["observed_candidate"]: row for row in line_rows}
    assert by_candidate["api.example.test"]["authorization_relation"] == "in_scope"
    assert by_candidate["external.invalid"]["authorization_relation"] == "out_of_scope"


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

def test_v6_observation_inventory_migration_and_rollback_preserve_evidence(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto-migration" / "dek.bin")
    database = SecureDatabase(tmp_path / "migration.db", crypto=crypto)
    manager = MigrationManager(
        database.path,
        ROOT / "app" / "data" / "migrations",
        backup_dir=tmp_path / "backups",
        down_migrations_dir=ROOT / "app" / "data" / "migrations_down",
    )
    applied = manager.apply()
    assert applied.target_version == 9

    target_id = database.create_target("migration", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["gau"])
    run_id = database.create_tool_run(
        tool_name="gau",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["gau", "<scope-bound target>"],
    )
    store = AssetObservationStore(database)
    store.persist(
        scan_id=scan_id,
        tool_run_id=run_id,
        tool_name="gau",
        observations=[{"title": "historical URL", "endpoint": "https://example.test/old", "evidence": {"adapter": "wayback_cdx"}}],
    )

    rolled = manager.rollback(target_version=8)
    assert rolled.reverted_versions == (9,)
    with database._connect() as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_asset_observations'"
        ).fetchone()
        count = conn.execute("SELECT COUNT(*) AS n FROM scan_asset_observations").fetchone()["n"]
    assert table is not None
    assert count == 1

