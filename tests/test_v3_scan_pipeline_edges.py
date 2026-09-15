"""Focused edge-case coverage for the v3 scan orchestrator."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

from app.database import Database
from app.engine.v3_scan_pipeline import V3ScanPipeline


def _pipeline(tmp_path: Path) -> V3ScanPipeline:
    return V3ScanPipeline(
        database=Database(tmp_path / "windeep.db"),
        wrapper_classes={},
        tools_dir=tmp_path / "tools",
        target_scope=lambda row: None,
        preflight_for=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("preflight should not be reached")),
        runtime_environment=lambda: {},
        broadcast=lambda event_type, payload, scan_id: None,
    )


@pytest.mark.asyncio
async def test_empty_plan_fails_before_preflight_or_tool_access(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    with pytest.raises(ValueError, match="no runnable integrations"):
        await pipeline.run(
            scan_id=1,
            target_row={"id": 1, "target": "https://example.com", "scope": ["example.com"]},
            selected=[],
            consent_id="fixture-consent",
            tool_options={},
            cancel_event=threading.Event(),
            mode="selected",
            skipped=[],
        )


def test_safe_finding_event_is_metadata_only(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    safe = pipeline._safe_finding_event(
        {
            "id": 7,
            "title": "fixture",
            "severity": "high",
            "vuln_type": "reflection",
            "tool": "fixture-tool",
            "endpoint": "https://example.com/x",
            "confidence": 0.9,
            "finding_fingerprint": "abc",
            "tool_run_id": 3,
            "evidence": {"authorization": "secret"},
            "request": "must-not-export",
            "response": "must-not-export",
        }
    )
    assert safe == {
        "id": 7,
        "title": "fixture",
        "severity": "high",
        "vuln_type": "reflection",
        "tool": "fixture-tool",
        "endpoint": "https://example.com/x",
        "confidence": 0.9,
        "finding_fingerprint": "abc",
        "tool_run_id": 3,
    }
