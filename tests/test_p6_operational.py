"""P6 acceptance tests for observability, recovery, budgets, backpressure, and cleanup."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.migrations import MigrationManager
from app.ops.runtime import (
    BackpressureChannel,
    BudgetExceeded,
    BudgetLedger,
    CleanupError,
    CleanupSweeper,
    ScanResumeCoordinator,
    StructuredEventLogger,
)
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase

ROOT = Path(__file__).resolve().parents[1]


def _db(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    return crypto, database, scan_id


def test_resume_uses_committed_stage_boundary_after_restart(tmp_path: Path) -> None:
    _crypto, database, scan_id = _db(tmp_path)
    first = ScanResumeCoordinator(database)
    first.commit(scan_id, "capture", payload={"artifact_count": 3})
    first.commit(scan_id, "dedup", payload={"finding_count": 2})

    restarted = ScanResumeCoordinator(database)
    state = restarted.state(scan_id)
    assert state["last_stage"] == "dedup"
    assert state["next_stage"] == "chain"
    assert state["payload"] == {"finding_count": 2}


def test_budget_exceed_is_fail_closed_audited_and_marks_incomplete(tmp_path: Path) -> None:
    _crypto, database, scan_id = _db(tmp_path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    ledger = BudgetLedger(database, audit, scan_id=scan_id, wall_clock_seconds=60, artifact_bytes=10, llm_tokens=5)
    ledger.consume_artifact(6)
    ledger.consume_llm(3)
    with pytest.raises(BudgetExceeded):
        ledger.consume_artifact(5)
    assert ledger.snapshot()["status"] == "incomplete"
    ok, count = audit.verify_chain()
    assert ok and count >= 1


def test_backpressure_channel_never_blocks_scan_producer() -> None:
    async def scenario():
        channel = BackpressureChannel(max_items=2)
        assert channel.publish({"seq": 1}) is True
        assert channel.publish({"seq": 2}) is True
        assert channel.publish({"seq": 3}) is False
        first = await channel.receive()
        second = await channel.receive()
        return channel.stats(), first, second

    stats, first, second = asyncio.run(scenario())
    assert [first["seq"], second["seq"]] == [1, 2]
    assert stats == {"queued": 0, "dropped": 1, "capacity": 2}


def test_structured_logger_redacts_before_encrypted_persistence(tmp_path: Path) -> None:
    _crypto, database, scan_id = _db(tmp_path)
    logger = StructuredEventLogger(database)
    logger.log(scan_id=scan_id, task_id="task-1", actor="operator", event="tool.end", payload={"Authorization": "Bearer top-secret", "message": "token=abc123"})
    row = logger.list(scan_id)[0]
    assert row["payload"]["Authorization"] == "[REDACTED]"
    assert "abc123" not in str(row["payload"])
    with database._connect() as conn:
        raw = conn.execute("SELECT payload FROM structured_logs WHERE scan_id = ?", (scan_id,)).fetchone()["payload"]
    assert "abc123" not in raw


def test_cleanup_sweeper_asserts_plaintext_and_process_cleanup(tmp_path: Path) -> None:
    encrypted_tmp = tmp_path / "encrypted-tmp"
    encrypted_tmp.mkdir()
    sweeper = CleanupSweeper(encrypted_tmp)
    leaked = encrypted_tmp / "leaked.tmp"
    leaked.write_text("plaintext", encoding="utf-8")
    sweeper.register_temp(leaked)
    with pytest.raises(CleanupError):
        sweeper.assert_clean()
    leaked.unlink()

    class Proc:
        returncode = None
    proc = Proc()
    sweeper.register_process(proc)
    with pytest.raises(CleanupError):
        sweeper.assert_clean()
    proc.returncode = 0
    sweeper.assert_clean()
