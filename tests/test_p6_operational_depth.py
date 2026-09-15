"""Deeper P6 contracts for restart safety, budgets, durable fanout, and cleanup."""
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
    DurableFanout,
    ScanResumeCoordinator,
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
    return database, scan_id


def test_run_stage_skips_committed_work_and_commits_only_after_success(tmp_path: Path) -> None:
    database, scan_id = _db(tmp_path)
    resume = ScanResumeCoordinator(database)
    calls: list[str] = []

    def capture():
        calls.append("capture")
        return {"artifacts": 4}

    first = resume.run_stage(scan_id, "capture", capture)
    second = resume.run_stage(scan_id, "capture", lambda: (_ for _ in ()).throw(AssertionError("must not rerun")))
    assert first == {"artifacts": 4}
    assert second == {"artifacts": 4}
    assert calls == ["capture"]

    with pytest.raises(RuntimeError, match="boom"):
        resume.run_stage(scan_id, "dedup", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert resume.state(scan_id)["last_stage"] == "capture"
    assert resume.state(scan_id)["next_stage"] == "dedup"


def test_budget_enforces_per_tool_and_marks_complete_only_when_active(tmp_path: Path) -> None:
    database, scan_id = _db(tmp_path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    ledger = BudgetLedger(
        database,
        audit,
        scan_id=scan_id,
        wall_clock_seconds=60,
        artifact_bytes=100,
        llm_tokens=100,
        per_tool_seconds=5,
    )
    ledger.consume_tool_time(tool_run_id=7, elapsed_seconds=2.5)
    ledger.consume_tool_time(tool_run_id=7, elapsed_seconds=2.4)
    assert ledger.tool_snapshot(7)["elapsed_seconds"] == pytest.approx(4.9)
    with pytest.raises(BudgetExceeded, match="tool_wall_clock"):
        ledger.consume_tool_time(tool_run_id=7, elapsed_seconds=0.2)
    assert ledger.snapshot()["status"] == "incomplete"
    with pytest.raises(BudgetExceeded, match="not active"):
        ledger.mark_complete()

    second_scan = database.create_scan(database.get_scan(scan_id)["target_id"], "v2:selected", ["fixture"])
    second = BudgetLedger(database, audit, scan_id=second_scan, wall_clock_seconds=60, artifact_bytes=100, llm_tokens=100, per_tool_seconds=5)
    second.mark_complete()
    assert second.snapshot()["status"] == "complete"


def test_budget_negative_and_wall_clock_fail_closed(tmp_path: Path) -> None:
    database, scan_id = _db(tmp_path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    ledger = BudgetLedger(database, audit, scan_id=scan_id, wall_clock_seconds=0.01, artifact_bytes=1, llm_tokens=1, per_tool_seconds=1)
    with pytest.raises(ValueError):
        ledger.consume_artifact(-1)
    with pytest.raises(ValueError):
        ledger.consume_llm(-1)
    with pytest.raises(ValueError):
        ledger.consume_tool_time(tool_run_id=1, elapsed_seconds=-1)
    with database._connect() as conn:
        conn.execute("UPDATE scan_budgets SET started_at = started_at - 10 WHERE scan_id = ?", (scan_id,))
    with pytest.raises(BudgetExceeded, match="wall_clock_seconds"):
        ledger.check_wall_clock()


def test_durable_fanout_persists_before_nonblocking_ui_drop() -> None:
    persisted: list[dict] = []
    channel = BackpressureChannel(max_items=1)
    fanout = DurableFanout(persist=lambda event: persisted.append(dict(event)) or len(persisted), channel=channel)
    first = fanout.publish({"kind": "finding", "id": 1})
    second = fanout.publish({"kind": "finding", "id": 2})
    assert first == {"durable_id": 1, "ui_queued": True}
    assert second == {"durable_id": 2, "ui_queued": False}
    assert [item["id"] for item in persisted] == [1, 2]
    assert channel.stats()["dropped"] == 1


def test_cleanup_sweep_unlinks_temps_terminates_processes_and_sweeps_chunks(tmp_path: Path) -> None:
    encrypted_tmp = tmp_path / "encrypted-tmp"
    encrypted_tmp.mkdir()
    leaked = encrypted_tmp / "scan.tmp"
    leaked.write_text("sensitive", encoding="utf-8")
    orphan_chunks = ["chunk-a"]

    class Proc:
        returncode = None
        terminated = False
        killed = False

        def terminate(self):
            self.terminated = True
            self.returncode = 0

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    proc = Proc()
    sweeper = CleanupSweeper(
        encrypted_tmp,
        orphan_chunk_check=lambda: list(orphan_chunks),
        orphan_chunk_sweep=lambda: orphan_chunks.clear(),
    )
    sweeper.register_temp(leaked)
    sweeper.register_process(proc)
    result = sweeper.sweep(process_timeout=0.1)
    assert leaked.exists() is False
    assert proc.terminated is True
    assert result == {"temp_files_removed": 1, "processes_stopped": 1, "orphan_chunks_removed": 1}
    sweeper.assert_clean()
    with pytest.raises(CleanupError, match="outside encrypted-tmp"):
        sweeper.register_temp(tmp_path / "outside.tmp")


def test_cleanup_kills_process_that_ignores_terminate(tmp_path: Path) -> None:
    encrypted_tmp = tmp_path / "encrypted-tmp"
    encrypted_tmp.mkdir()

    class Stubborn:
        returncode = None
        killed = False

        def terminate(self):
            return None

        def wait(self, timeout=None):
            if not self.killed:
                raise TimeoutError("still running")
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    proc = Stubborn()
    sweeper = CleanupSweeper(encrypted_tmp)
    sweeper.register_process(proc)
    result = sweeper.sweep(process_timeout=0.01)
    assert proc.killed is True
    assert result["processes_stopped"] == 1


def test_backpressure_validation_and_receive() -> None:
    with pytest.raises(ValueError):
        BackpressureChannel(max_items=0)

    async def scenario():
        channel = BackpressureChannel(max_items=1)
        channel.publish("x")
        return await channel.receive()

    assert asyncio.run(scenario()) == "x"
