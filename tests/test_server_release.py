"""Release-facing API regression coverage for Windeep v0.1.0."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.server import create_app

CERTIFIED = {"subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei"}
CATALOG_COUNT = 137


@pytest.fixture
def release_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _session(client):
    handshake = client.post("/api/handshake", json={})
    assert handshake.status_code == 200
    payload = handshake.get_json()
    assert payload["session"] == "established"
    return {"X-CSRF-Token": payload["csrf_token"]}


def _authorized_target(client, headers):
    response = client.post(
        "/api/targets",
        json={
            "name": "Example Program",
            "type": "web",
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "tags": ["release-test"],
            "notes": "authorized QA fixture",
        },
        headers=headers,
    )
    assert response.status_code == 201
    target = response.get_json()
    consent = client.post(
        "/api/consent",
        json={
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "authorized_by": "release-qa",
            "purpose": "authorized release regression",
            "ttl_seconds": 600,
        },
        headers=headers,
    )
    assert consent.status_code == 201
    return target, consent.get_json()


def test_health_local_auth_and_static_surface(release_client) -> None:
    client = release_client
    health = client.get("/api/health")
    assert health.status_code == 200
    health_json = health.get_json()
    assert health_json["status"] == "ok"
    assert health_json["localhost_only"] is True
    assert health_json["integrations_total"] == CATALOG_COUNT
    assert health_json["windows_certified_tools"] == len(CERTIFIED)
    assert health_json["test_count"] == 160

    assert client.get("/api/targets").status_code == 401
    blocked = client.get("/api/health", environ_base={"REMOTE_ADDR": "198.51.100.44"})
    assert blocked.status_code == 403

    headers = _session(client)
    assert client.get("/api/session").status_code == 200
    assert client.put("/api/settings", json={"global_rps": 4}).status_code == 401
    assert client.get("/").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200

    integrations = client.get("/api/integrations").get_json()
    assert integrations["database"]["encrypted"] is True
    assert integrations["tools"]["all_scope_bound"] is True
    assert integrations["tools"]["active"] == CATALOG_COUNT
    assert integrations["tools"]["catalog"] == CATALOG_COUNT
    assert integrations["tools"]["windows_certified"] == len(CERTIFIED)
    assert integrations["test_packs"]["network_actions"] == 0

    tools = client.get("/api/tools").get_json()
    assert len(tools) == CATALOG_COUNT
    assert CERTIFIED.issubset({entry["name"] for entry in tools})

    packs = client.get("/api/test-packs").get_json()
    assert packs["total"] == 160
    assert client.get("/api/test-packs/browser_fidelity/status").status_code == 200
    assert client.get("/api/test-packs/nope/status").status_code == 404


def test_target_consent_findings_reports_settings_and_assessment(release_client) -> None:
    client = release_client
    headers = _session(client)
    target, consent = _authorized_target(client, headers)
    target_id = target["id"]

    listed = client.get("/api/targets").get_json()
    assert [row["id"] for row in listed] == [target_id]
    assert client.get(f"/api/targets/{target_id}").get_json()["name"] == "Example Program"
    assert client.get("/api/targets/999999").status_code == 404

    updated = client.put(
        f"/api/targets/{target_id}",
        json={"name": "Example Program QA", "notes": "updated", "tags": ["qa", "v0.1.0"]},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.get_json()["name"] == "Example Program QA"
    assert client.put("/api/targets/999999", json={"name": "x"}, headers=headers).status_code == 404

    preflight = client.post(
        "/api/preflight/check",
        json={
            "target": "https://api.example.com/path",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "consent_id": consent["id"],
            "global_rps": 5,
            "global_burst": 5,
        },
        headers=headers,
    )
    assert preflight.status_code == 200
    assert preflight.get_json()["authorized"] is True

    denied = client.post(
        "/api/preflight/check",
        json={
            "target": "https://outside.invalid/",
            "scope": ["example.com"],
            "consent_id": consent["id"],
        },
        headers=headers,
    )
    assert denied.status_code == 403

    created_finding = client.post(
        "/api/findings",
        json={
            "target_id": target_id,
            "title": "Release QA finding",
            "severity": "medium",
            "vuln_type": "configuration",
            "tool": "release-test",
            "endpoint": "https://example.com/account",
            "description": "Synthetic release regression only.",
            "evidence": {"marker": "qa-only"},
            "request": "GET /account",
            "response": "HTTP/1.1 200 OK",
            "steps": "Synthetic test",
            "impact": "None",
            "remediation": "None",
            "confidence": 0.9,
        },
        headers=headers,
    )
    assert created_finding.status_code == 201
    finding = created_finding.get_json()["finding"]
    finding_id = finding["id"]
    assert finding["evidence"]["marker"] == "qa-only"
    assert client.get(f"/api/findings/{finding_id}").status_code == 200
    assert client.get("/api/findings/999999").status_code == 404
    assert client.get(f"/api/findings?target_id={target_id}&severity=medium").get_json()[0]["id"] == finding_id
    assert client.get(f"/api/findings/summary?target_id={target_id}").get_json()["medium"] == 1

    modified = client.put(
        f"/api/findings/{finding_id}",
        json={"status": "triaged", "severity": "low", "confidence": 0.95},
        headers=headers,
    )
    assert modified.status_code == 200
    assert modified.get_json()["status"] == "triaged"
    assert client.put("/api/findings/999999", json={"status": "new"}, headers=headers).status_code == 404

    report = client.post(
        "/api/reports/generate",
        json={"target_id": target_id, "title": "Release QA report", "template": "generic"},
        headers=headers,
    )
    assert report.status_code == 201
    assert "Release QA finding" in report.get_json()["content"]
    reports = client.get(f"/api/reports?target_id={target_id}").get_json()
    assert reports[0]["title"] == "Release QA report"
    assert client.post("/api/reports/generate", json={"target_id": 999999}, headers=headers).status_code == 404

    initial_settings = client.get("/api/settings").get_json()
    assert initial_settings["secrets_stored_encrypted"] is True
    saved = client.put(
        "/api/settings",
        json={"global_rps": 3.5, "proxy": "http://127.0.0.1:8080", "api_key": "not-real"},
        headers=headers,
    )
    assert saved.status_code == 200
    settings = client.get("/api/settings").get_json()
    assert settings["global_rps"] == 3.5
    assert settings["api_key"] == "configured"

    assessment = client.post(
        "/api/test-packs/run",
        json={
            "target_id": target_id,
            "consent_id": consent["id"],
            "pack": "browser_fidelity",
            "tests": [],
            "observations": {},
        },
        headers=headers,
    )
    assert assessment.status_code == 200
    assessment_json = assessment.get_json()
    assert len(assessment_json["results"]) == 20
    assert assessment_json["network_actions"] == 0
    assert all(row["status"] == "not_assessed" for row in assessment_json["results"])

    bad_tool = client.post(
        "/api/tools/run",
        json={"target_id": target_id, "consent_id": consent["id"], "tool": "not-a-tool"},
        headers=headers,
    )
    assert bad_tool.status_code == 400

    assert client.delete(f"/api/findings/{finding_id}", headers=headers).status_code == 200
    assert client.delete("/api/findings/999999", headers=headers).status_code == 404


def test_scan_lifecycle_fails_closed_without_matching_certified_tool(release_client) -> None:
    client = release_client
    headers = _session(client)
    target, consent = _authorized_target(client, headers)
    target_id = target["id"]

    started = client.post(
        "/api/scans",
        json={
            "target_id": target_id,
            "consent_id": consent["id"],
            "scan_type": "module",
            "modules": ["does_not_exist"],
        },
        headers=headers,
    )
    assert started.status_code == 202
    scan_id = started.get_json()["id"]

    deadline = time.time() + 2
    row = None
    while time.time() < deadline:
        row = client.get(f"/api/scans/{scan_id}").get_json()
        if row["status"] == "failed":
            break
        time.sleep(0.02)
    assert row is not None and row["status"] == "failed"
    assert row["results_summary"]["errors"][0]["tool"] == "orchestrator"
    assert client.get(f"/api/scans?target_id={target_id}").get_json()[0]["id"] == scan_id
    assert client.get(f"/api/scans/{scan_id}/logs").status_code == 200
    assert client.get("/api/scans/999999").status_code == 404
    assert client.post(f"/api/scans/{scan_id}/cancel", headers=headers).status_code == 202
    assert client.post("/api/scans/999999/cancel", headers=headers).status_code == 404

    assert client.delete(f"/api/targets/{target_id}", headers=headers).status_code == 200
    assert client.delete(f"/api/targets/{target_id}", headers=headers).status_code == 404
