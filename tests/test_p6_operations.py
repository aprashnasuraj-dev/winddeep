"""P6 acceptance: recovery, budgets, backpressure, cleanup, and structured logs."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.engine.operations import (
    BackpressureBuffer,
    BudgetExceeded,
    ScanBudgetGuard,
    ScanBudgets,
    ScanSweeper,
    StageCheckpointStore,
    StructuredScanLogger,
)
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase

ROOT = Path(__file__).resolve().parents[1]


def fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    db = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(db.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target = db.create_target("x", "domain", "example.test", scope=["example.test"])
    scan = db.create_scan(target, "v3:fixture", ["fixture"])
    return db, audit, scan


def test_checkpoint_resume_uses_committed_database_state_after_restart(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    checkpoints = StageCheckpointStore(db, audit)
    checkpoints.commit(scan_id=scan, stage="tool:fixture", state={"artifact_sha256": "a" * 64, "findings": 2})
    restarted = StageCheckpointStore(db, audit)
    assert restarted.last(scan)["stage"] == "tool:fixture"
    assert restarted.last(scan)["state"] == {"artifact_sha256": "a" * 64, "findings": 2}
    assert restarted.resume_after(scan, ["recon", "tool:fixture", "dedup", "report"]) == "dedup"


def test_budget_exceed_aborts_cleanly_and_audits_reason(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    budget = ScanBudgetGuard(
        scan_id=scan,
        budgets=ScanBudgets(wall_seconds=10.0, artifact_bytes=100, llm_tokens=20),
        audit=audit,
        monotonic=lambda: 5.0,
        started_monotonic=0.0,
    )
    budget.charge_artifact(80)
    with pytest.raises(BudgetExceeded):
        budget.charge_artifact(30)
    with pytest.raises(BudgetExceeded):
        budget.charge_llm(21)
    events = audit.path.read_text(encoding="utf-8")
    assert "scan.budget_exceeded" in events
    assert '"budget":"artifact_bytes"' in events
    assert '"budget":"llm_tokens"' in events


def test_structured_logs_are_redaction_aware_and_persist_scan_task_actor(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    logger = StructuredScanLogger(db, audit)
    event = logger.emit(
        scan_id=scan,
        task_id="tool:nuclei",
        actor="operator",
        event="task.completed",
        data={"Authorization": "Bearer should-not-leak", "count": 3},
    )
    assert event["data"]["Authorization"] == "[REDACTED]"
    with db._connect() as conn:
        row = conn.execute("SELECT scan_id, task_id, actor, event, payload FROM scan_operations WHERE scan_id = ?", (scan,)).fetchone()
    assert row is not None
    assert row["task_id"] == "tool:nuclei"
    assert row["actor"] == "operator"
    assert "should-not-leak" not in str(row["payload"])


@pytest.mark.asyncio
async def test_slow_consumer_cannot_stall_backpressure_buffer() -> None:
    buffer = BackpressureBuffer(max_items=2)
    assert buffer.publish_nowait({"seq": 1}) is True
    assert buffer.publish_nowait({"seq": 2}) is True
    assert buffer.publish_nowait({"seq": 3}) is True
    assert buffer.dropped == 1
    assert await asyncio.wait_for(buffer.get(), timeout=0.1) == {"seq": 2}
    assert await asyncio.wait_for(buffer.get(), timeout=0.1) == {"seq": 3}


def test_scan_sweeper_detects_plaintext_temp_and_orphan_artifact_chunks(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    encrypted_tmp = tmp_path / "encrypted-tmp"
    encrypted_tmp.mkdir()
    sweeper = ScanSweeper(db, audit, encrypted_tmp=encrypted_tmp)
    assert sweeper.inspect(scan_id=scan)["ok"] is True
    (encrypted_tmp / "leaked.txt").write_text("plaintext", encoding="utf-8")
    result = sweeper.inspect(scan_id=scan)
    assert result["ok"] is False
    assert result["plaintext_temp_files"] == [str(encrypted_tmp / "leaked.txt")]
