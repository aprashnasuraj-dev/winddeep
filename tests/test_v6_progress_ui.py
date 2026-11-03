"""V6 regression contracts for progress visibility, UI backpressure, and release blocking."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_v6_pipeline_bridges_scheduler_progress_into_durable_scan_state() -> None:
    source = (ROOT / "app" / "v2_pipeline.py").read_text(encoding="utf-8")
    assert 'bridge_scheduler_events("scan.progress")' in source
    assert 'bridge_scheduler_events("tool.*")' in source
    assert 'results_summary={"runtime": runtime_summary}' in source
    assert '"source": "scheduler"' in source
    assert 'progress = max(0.0, min(99.0, progress))' in source


def test_v6_ui_coalesces_event_refreshes_and_blocks_unrunnable_tools() -> None:
    source = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "UI_REFRESH_DELAY_MS=750" in source
    assert "MAX_RENDERED_FINDINGS=500" in source
    assert 'if(x.type==="finding")scheduleUiRefresh' in source
    assert 'else if(x.type==="progress")scheduleUiRefresh' in source
    assert 'if(x.type==="finding")loadFindings()' not in source
    assert 'disabled aria-disabled="true"' in source
    assert 't.ready&&t.compatible?"":"disabled"' in source
    assert 'active=(runtime.running_tasks||[])[0]' in source


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
