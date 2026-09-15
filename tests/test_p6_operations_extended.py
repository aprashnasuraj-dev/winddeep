"""Additional P6 operational edge-case acceptance."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.operations import BudgetExceeded, ScanBudgetGuard, ScanBudgets, StageCheckpointStore, StructuredScanLogger
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


def test_wall_budget_fails_closed_without_mutating_other_counters(tmp_path: Path) -> None:
    _db, audit, scan = fixture(tmp_path)
    ticks = iter([0.0, 0.5, 2.0])
    guard = ScanBudgetGuard(
        scan_id=scan,
        budgets=ScanBudgets(wall_seconds=1.0, artifact_bytes=10, llm_tokens=10),
        audit=audit,
        monotonic=lambda: next(ticks),
        started_monotonic=0.0,
    )
    assert guard.charge_artifact(5) == 5
    with pytest.raises(BudgetExceeded):
        guard.charge_llm(1)
    assert guard.artifact_bytes == 5
    assert guard.llm_tokens == 0


def test_checkpoint_unknown_stage_refuses_ambiguous_resume(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    store = StageCheckpointStore(db, audit)
    store.commit(scan_id=scan, stage="legacy-stage", state={"ok": True})
    with pytest.raises(ValueError):
        store.resume_after(scan, ["recon", "report"])


def test_structured_logger_redacts_nested_secret_keys(tmp_path: Path) -> None:
    db, audit, scan = fixture(tmp_path)
    logger = StructuredScanLogger(db, audit)
    record = logger.emit(
        scan_id=scan,
        task_id="tool:fixture",
        actor="scheduler",
        event="task.output",
        data={"nested": {"api_key": "secret", "safe": 1}, "items": [{"token": "secret-2"}]},
    )
    assert record["data"]["nested"]["api_key"] == "[REDACTED]"
    assert record["data"]["items"][0]["token"] == "[REDACTED]"
