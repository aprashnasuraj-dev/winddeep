"""V6 regression contracts for progress visibility, UI backpressure, and release blocking."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v2_api import recover_interrupted_scans
from app.v2_pipeline import _process_memory_bytes


ROOT = Path(__file__).resolve().parents[1]


def test_v6_pipeline_bridges_scheduler_progress_into_durable_scan_state() -> None:
    source = (ROOT / "app" / "v2_pipeline.py").read_text(encoding="utf-8")
    assert 'bridge_scheduler_events("scan.progress")' in source
    assert 'bridge_scheduler_events("tool.*")' in source
    assert 'results_summary={"runtime": runtime_summary}' in source
    assert '"source": "scheduler"' in source
    assert 'progress = max(0.0, min(99.0, progress))' in source
    assert 'payload.get("phase") == "_bridge_flush"' in source
    assert '"tool.bridge_flush"' in source
    assert "progress_bridge_drained.wait()" in source


def test_v6_ui_coalesces_event_refreshes_and_blocks_unrunnable_tools() -> None:
    source = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "UI_REFRESH_DELAY_MS=750" in source
    assert "MAX_RENDERED_FINDINGS=500" in source
    assert "DURABLE_RECONCILE_MS=5000" in source
    assert "ACTIVE_SCAN_STATES" in source
    assert 'if(x.type==="finding")scheduleUiRefresh' in source
    assert 'else if(x.type==="progress")scheduleUiRefresh' in source
    assert 'if(x.type==="finding")loadFindings()' not in source
    assert 'disabled aria-disabled="true"' in source
    assert 'runnable=Boolean(t.compatible&&t.ready)' in source
    assert 'data-tool-probe=' in source
    assert 'probeTool(p.dataset.toolProbe)' in source
    assert 'active=(runtime.running_tasks||[])[0]' in source
    assert 'scheduleUiRefresh({scans:true,findings:true,overview:true})' in source
    assert 'globalStreamConnected=false' in source
    assert 'setInterval(()=>{if(scans.some' in source
    assert 'terminalTransition' in source


def test_v6_runtime_telemetry_contract_is_present_and_memory_probe_is_safe() -> None:
    source = (ROOT / "app" / "v2_pipeline.py").read_text(encoding="utf-8")
    assert '"runtime_metrics": runtime_metrics' in source
    assert '"correlation_id": correlation_id' in source
    assert '"event_bus": event_bus_stats' in source
    assert '"backends": backend_summary' in source
    assert '"cpu_seconds"' in source
    assert '"memory_delta_bytes"' in source
    snapshot = _process_memory_bytes()
    assert snapshot is None or snapshot > 0


def test_v6_tool_probe_is_separate_from_run_and_cached_server_side() -> None:
    api_source = (ROOT / "app" / "v2_api.py").read_text(encoding="utf-8")
    ui_source = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert '@app.post("/api/v2/tools/<string:tool_name>/probe")' in api_source
    assert "active_probe=True" in api_source
    assert "tool_probe_cache" in api_source
    assert "tool_probe_ttl_seconds = 45.0" in api_source
    assert 'readiness_state==="probe-required"' in ui_source
    assert "runnable=Boolean(t.compatible&&t.ready)" in ui_source
    assert "Probe runtime" in ui_source


def test_v6_dashboard_javascript_is_syntax_valid_when_node_is_available() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed on this test host")
    completed = subprocess.run(
        [node, "--check", str(ROOT / "app" / "static" / "app.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_v6_release_checklist_has_exactly_ten_open_critical_blockers() -> None:
    checklist = (ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    blockers = re.findall(r"^- \[ \] \*\*V6-(\d{2})\b", checklist, flags=re.MULTILINE)
    assert blockers == [f"{index:02d}" for index in range(1, 11)]
    assert "Status: **BLOCKED / DRAFT**" in checklist
    assert "0 submission-ready findings" in checklist

def test_v6_restart_recovery_fails_stale_active_scans_without_touching_terminal_or_pending(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    audit = AuditLog(tmp_path / "audit" / "restart.jsonl")
    target_id = database.create_target("restart", "domain", "example.test", scope=["example.test"])

    active_ids: list[int] = []
    for status in ("queued", "running", "cancelling"):
        scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
        database.update_scan(
            scan_id,
            status=status,
            results_summary={"runtime": {"phase": "heartbeat"}, "errors": []},
        )
        active_ids.append(scan_id)

    completed_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    database.update_scan(completed_id, status="completed", progress=100.0)
    pending_id = database.create_scan(target_id, "v2:selected", ["fixture"])

    recovered = recover_interrupted_scans(database, audit)
    assert recovered == active_ids

    with database._connect() as conn:
        rows = {
            int(row["id"]): dict(row)
            for row in conn.execute(
                "SELECT id, status, results_summary, finished_at FROM scans ORDER BY id"
            ).fetchall()
        }
        recovery_logs = conn.execute(
            "SELECT scan_id, module, message FROM scan_logs WHERE module = 'runtime-recovery' ORDER BY scan_id"
        ).fetchall()

    for scan_id in active_ids:
        assert rows[scan_id]["status"] == "failed"
        assert rows[scan_id]["finished_at"] is not None
        summary = __import__("json").loads(rows[scan_id]["results_summary"])
        assert summary["runtime"]["phase"] == "heartbeat"
        assert summary["restart_recovery"]["previous_status"] in {"queued", "running", "cancelling"}
        assert summary["restart_recovery"]["resumable"] is False
        assert summary["errors"][-1]["code"] == "V6_RESTART_INTERRUPTED"

    assert rows[completed_id]["status"] == "completed"
    assert rows[pending_id]["status"] == "pending"
    assert [int(row["scan_id"]) for row in recovery_logs] == active_ids

