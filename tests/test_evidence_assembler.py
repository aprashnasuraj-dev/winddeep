"""Fail-closed acceptance checks for automatic evidence assembly."""
from __future__ import annotations

from pathlib import Path

from app.evidence.assembler import EvidenceAssembler
from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v2_pipeline import FindingBatchWriter

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(
        database.path,
        ROOT / "app" / "data" / "migrations",
        backup_dir=tmp_path / "backups",
        down_migrations_dir=ROOT / "app" / "data" / "migrations_down",
    ).apply()
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target_id = database.create_target("fixture", "repo", "fixtures/source.txt", scope=["fixtures/source.txt"])
    scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    run_id = database.create_tool_run(
        tool_name="fixture",
        status="completed",
        scan_id=scan_id,
        target_id=target_id,
        command=["fixture", "<scope-bound target>"],
    )
    return crypto, database, audit, target_id, scan_id, run_id


def test_assembler_never_guesses_slice_for_custom_parser_without_line_attribution(tmp_path: Path) -> None:
    crypto, database, audit, target_id, scan_id, run_id = _fixture(tmp_path)
    raw_store = RawArtifactStore(database, crypto, audit, chunk_size=32)
    stdout = raw_store.put(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="tool.stdout",
        media_type="text/plain; charset=utf-8",
        content=b"first candidate\nsecond candidate\n",
        reason="ambiguous custom-parser fixture",
    )
    writer = FindingBatchWriter(database)
    writer.ensure_schema()
    persisted = writer.persist(
        scan_id=scan_id,
        tool_run_id=run_id,
        target_id=target_id,
        tool_name="fixture",
        findings=[
            {
                "title": "Custom parser candidate",
                "severity": "medium",
                "vuln_type": "source_observation",
                "endpoint": "fixtures/source.txt",
                "description": "The custom parser did not provide an exact stdout line.",
                "confidence": 0.7,
                "evidence": {
                    "_windeep_execution": {
                        "tool_run_id": run_id,
                        "backend": "fixture",
                        "backend_tier": "fixture",
                        "parser": "custom_parser_without_line_attribution",
                        "stdout_sha256": stdout.sha256,
                        "stderr_sha256": "0" * 64,
                    }
                },
            }
        ],
    )
    finding_id = int(persisted[0]["finding_id"])

    result = EvidenceAssembler(database, crypto, audit).assemble_scan(scan_id)
    item = next(row for row in result if row["finding_id"] == finding_id)
    assert item["state"] == "incomplete"
    assert item["line_number"] is None
    assert "tool_output" in item["missing"]
    assert "reproduction" in item["missing"]
    assert item["stdout_sha256"] == stdout.sha256

    with database._connect() as conn:
        row = conn.execute(
            "SELECT state, completeness_score FROM evidence_bundles WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
    assert row is not None
    assert row["state"] == "incomplete"
    assert float(row["completeness_score"]) < 1.0
