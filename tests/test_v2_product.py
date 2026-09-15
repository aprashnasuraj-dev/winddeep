"""Windeep v2 product regression coverage."""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.server import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def v2_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client(), tmp_path


def session(client):
    response = client.post("/api/handshake", json={})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.get_json()["csrf_token"]}


def target_and_consent(client, headers, *, target: str, target_type: str = "domain"):
    created = client.post(
        "/api/targets",
        json={"name": "v2 fixture", "type": target_type, "target": target, "scope": [target], "out_of_scope": []},
        headers=headers,
    )
    assert created.status_code == 201
    row = created.get_json()
    consent = client.post(
        "/api/consent",
        json={"target": target, "scope": [target], "out_of_scope": [], "authorized_by": "v2-qa", "purpose": "authorized v2 regression", "ttl_seconds": 600},
        headers=headers,
    )
    assert consent.status_code == 201
    return row, consent.get_json()


def wait_scan(client, scan_id: int, statuses: set[str], timeout: float = 8.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        last = response.get_json()
        if last["status"] in statuses:
            return last
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not reach {statuses}; last={last}")


def test_catalog_is_fully_runtime_addressable_and_target_aligned() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    assert len(classes) == 137
    assert all(cls.requires_scope for cls in classes.values())
    assert all(tuple(cls.target_types) for cls in classes.values())
    assert all(isinstance(cls.scan_default, bool) for cls in classes.values())
    assert {cls.category for cls in classes.values()} >= {"recon_passive", "recon_active", "web_vulns", "mobile", "web3", "secrets", "network", "utilities"}


def test_v2_status_tools_settings_and_plan(v2_client) -> None:
    client, _tmp = v2_client
    headers = session(client)
    target, _consent = target_and_consent(client, headers, target="example.test", target_type="domain")

    status = client.get("/api/v2/status").get_json()
    assert status["catalog"] == 137
    assert status["raw_proof_exports"] is True
    assert status["cancellable_processes"] is True
    assert status["target_aware_planning"] is True

    tools = client.get("/api/v2/tools?target_type=domain").get_json()
    assert tools["total"] == 137
    assert len(tools["tools"]) == 137
    assert all("target_types" in row and "blocked_reason" in row for row in tools["tools"])
    assert any(row["compatible"] for row in tools["tools"])

    saved = client.put(
        "/api/v2/settings",
        json={
            "global_rps": 4.5,
            "scan_speed": "fast",
            "proxy": "http://127.0.0.1:8080",
            "shodan_api_key": "qa-key",
            "censys_api_id": "qa-id",
            "censys_api_secret": "qa-secret",
        },
        headers=headers,
    )
    assert saved.status_code == 200
    settings = client.get("/api/v2/settings").get_json()
    assert settings["global_rps"] == 4.5
    assert settings["shodan_api_key"] == "configured"
    assert settings["censys_api_id"] == "configured"

    configured_tools = client.get("/api/v2/tools?target_type=domain").get_json()["tools"]
    shodan = next(row for row in configured_tools if row["name"] == "shodan")
    assert shodan["configured"] is True
    assert shodan["ready"] is True

    plan = client.get(f"/api/v2/scan-plan?target_id={target['id']}&mode=smart").get_json()
    assert plan["catalog_count"] == 137
    assert plan["target_type"] == "domain"
    assert plan["selected_count"] >= 1
    assert all(isinstance(name, str) for name in plan["selected"])


def test_v2_builtin_scan_creates_raw_proof_and_report_exports(v2_client) -> None:
    client, tmp_path = v2_client
    headers = session(client)
    fixture = tmp_path / "authorized-source.txt"
    fixture.write_text("api_key = abcdefghijklmnopqrstuvwxyz012345\n", encoding="utf-8")
    target, consent = target_and_consent(client, headers, target=str(fixture), target_type="repo")

    started = client.post(
        "/api/v2/scans",
        json={"target_id": target["id"], "consent_id": consent["id"], "mode": "selected", "tools": ["custom_regex"], "modules": []},
        headers=headers,
    )
    assert started.status_code == 202
    scan_id = started.get_json()["scan_id"]
    completed = wait_scan(client, scan_id, {"completed", "failed"})
    assert completed["status"] == "completed"

    findings = client.get(f"/api/findings?target_id={target['id']}").get_json()
    assert findings
    finding = findings[0]
    assert finding["tool"] == "custom_regex"
    assert finding["steps"]
    assert finding["evidence"]
    assert "abcdefghijklmnopqrstuvwxyz012345" not in json.dumps(finding["evidence"])

    generated = client.post(
        "/api/v2/reports/generate",
        json={"target_id": target["id"], "title": "v2 proof fixture"},
        headers=headers,
    )
    assert generated.status_code == 201
    report = generated.get_json()
    assert report["encrypted_at_rest"] is True
    assert report["plaintext_export"] is True
    assert "Raw evidence" in report["content"]
    assert "Proof of concept / reproduction" in report["content"]

    markdown = client.get(f"/api/v2/reports/{report['id']}/download?format=markdown")
    assert markdown.status_code == 200
    assert markdown.mimetype == "text/markdown"
    assert b"Raw evidence" in markdown.data
    evidence_json = client.get(f"/api/v2/reports/{report['id']}/download?format=json")
    assert evidence_json.status_code == 200
    payload = json.loads(evidence_json.data)
    assert payload["findings"][0]["tool"] == "custom_regex"

    intelligence = client.get(f"/api/v2/intelligence?target_id={target['id']}")
    assert intelligence.status_code == 200
    intel = intelligence.get_json()
    assert intel["finding_count"] >= 1
    assert intel["top_findings"]


def test_v2_stop_terminates_active_child_process(v2_client) -> None:
    client, _tmp = v2_client
    headers = session(client)
    target, consent = target_and_consent(client, headers, target="example.test", target_type="domain")

    tools_dir = ROOT / "tools"
    tools_dir.mkdir(exist_ok=True)
    binary = tools_dir / "assetfinder"
    previous = binary.read_bytes() if binary.exists() else None
    previous_mode = binary.stat().st_mode if binary.exists() else None
    try:
        binary.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(20)\nprint('late.example.test')\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        started = client.post(
            "/api/v2/scans",
            json={"target_id": target["id"], "consent_id": consent["id"], "mode": "selected", "tools": ["assetfinder"], "modules": []},
            headers=headers,
        )
        assert started.status_code == 202
        scan_id = started.get_json()["scan_id"]
        wait_scan(client, scan_id, {"running"}, timeout=3.0)
        stop = client.post(f"/api/v2/scans/{scan_id}/stop", json={}, headers=headers)
        assert stop.status_code == 202
        final = wait_scan(client, scan_id, {"cancelled", "failed", "completed"}, timeout=4.0)
        assert final["status"] == "cancelled"
    finally:
        if previous is None:
            binary.unlink(missing_ok=True)
        else:
            binary.write_bytes(previous)
            if previous_mode is not None:
                binary.chmod(previous_mode)


def test_v2_dashboard_has_no_idle_primary_navigation() -> None:
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    for section in ("overview", "targets", "scans", "tools", "testpacks", "findings", "reports", "intelligence", "settings"):
        assert f'id="{section}"' in html
        assert f'data-view="{section}"' in html
    for control in (
        "addTarget", "previewPlan", "startScan", "stopAllScans", "refreshTools", "runPack",
        "refreshFindings", "generateReport", "refreshIntelligence", "saveSettings",
    ):
        assert f'id="{control}"' in html
        assert f'$("{control}")' in js
    for endpoint in (
        "/api/v2/tools", "/api/v2/scan-plan", "/api/v2/scans", "/api/v2/reports/generate",
        "/api/v2/intelligence", "/api/v2/settings", "/api/v2/status",
    ):
        assert endpoint in js
    assert "137 Integration Matrix" in html
    assert "raw proof" in html.lower()
    assert "Stop all running scans" in html
