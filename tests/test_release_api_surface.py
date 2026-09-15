"""End-to-end coverage for the production dashboard API and guarded runtime."""

from __future__ import annotations

import time

import pytest

import app.api as api_module
from app.server import create_app


@pytest.fixture
def release_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    app.config.update(TESTING=True)
    try:
        yield app
    finally:
        app.extensions["windeep.capture"].stop()
        app.extensions["windeep.runtime"].close()


def _session(client) -> dict[str, str]:
    response = client.post("/api/handshake")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.get_json()["csrf_token"]}


def _target_and_consent(client, headers: dict[str, str]) -> tuple[int, str]:
    created = client.post(
        "/api/targets",
        headers=headers,
        json={
            "name": "Example Program",
            "type": "web",
            "target": "https://example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "tags": ["release", "test"],
        },
    )
    assert created.status_code == 201, created.get_data(as_text=True)
    target_id = int(created.get_json()["id"])
    consent = client.post(
        "/api/consent",
        headers=headers,
        json={
            "target": "https://example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "authorized_by": "release-test-owner",
            "purpose": "authorized local release verification",
            "ttl_seconds": 600,
        },
    )
    assert consent.status_code == 201, consent.get_data(as_text=True)
    return target_id, str(consent.get_json()["id"])


def test_release_api_crud_flows_findings_reports_and_submissions(release_app) -> None:
    client = release_app.test_client()
    runtime = release_app.extensions["windeep.runtime"]
    headers = _session(client)
    target_id, _consent_id = _target_and_consent(client, headers)

    assert client.get("/api/session").status_code == 200
    assert client.get("/api/dashboard/summary").get_json()["targets"] == 1
    assert client.get("/api/targets").status_code == 200
    assert client.get(f"/api/targets/{target_id}").status_code == 200
    updated = client.put(
        f"/api/targets/{target_id}",
        headers=headers,
        json={"notes": "verified release target", "tags": ["release", "verified"]},
    )
    assert updated.status_code == 200
    assert updated.get_json()["notes"] == "verified release target"
    assert client.put(f"/api/targets/{target_id}", headers=headers, json={}).status_code == 200
    assert client.get("/api/targets/999999").status_code == 404

    finding_id, created = runtime.database.create_finding(
        target_id,
        "Release evidence finding",
        "medium",
        vuln_type="headers",
        tool="release-test",
        endpoint="https://example.com/api/items",
        description="Evidence is encrypted at rest and exposed only through the local authenticated API.",
        evidence={"marker": "release-evidence"},
        request="GET /api/items HTTP/1.1",
        response="HTTP/1.1 200 OK",
        confidence=0.9,
    )
    assert created is True
    assert client.get(f"/api/findings/{finding_id}").status_code == 200
    assert len(client.get(f"/api/findings?target_id={target_id}&severity=medium").get_json()) == 1
    assert client.get(f"/api/findings/summary?target_id={target_id}").get_json()["medium"] == 1
    assert client.put(f"/api/findings/{finding_id}", headers=headers, json={"status": "triaged"}).status_code == 200
    assert client.put(f"/api/findings/{finding_id}", headers=headers, json={"status": "invalid"}).status_code == 400
    assert client.get("/api/findings/999999").status_code == 404

    flow_id = runtime.database.insert_flow(
        {
            "target_id": target_id,
            "method": "POST",
            "url": "https://example.com/api/items?id=7",
            "scheme": "https",
            "host": "example.com",
            "port": 443,
            "path": "/api/items",
            "query": "id=7",
            "request_headers": {"Content-Type": "application/json"},
            "request_body": b'{"name":"marker"}',
            "status": 201,
            "response_headers": {"Content-Type": "application/octet-stream", "Server": "Example/1.2"},
            "response_body": b"\xff\x00release",
            "timing_ms": 9.5,
            "tls_info": {"version": "TLSv1.3"},
            "client_ip": "127.0.0.1",
            "tags": ["api"],
        }
    )
    assert client.get("/api/flows").status_code == 400
    listed = client.get(f"/api/flows?target_id={target_id}")
    assert listed.status_code == 200
    assert listed.get_json()[0]["response_body"]["encoding"] == "base64"
    assert client.get(f"/api/flows?target_id={target_id}&q=marker").status_code == 200
    assert client.get(f"/api/flows/{flow_id}").status_code == 200
    assert client.get("/api/flows/999999").status_code == 404
    assert "POST /api/items" in client.get(f"/api/flows/{flow_id}/export?format=raw").get_data(as_text=True)
    assert client.get(f"/api/flows/{flow_id}/export?format=xml").status_code == 400

    generated = client.post(
        "/api/reports/generate",
        headers=headers,
        json={"target_id": target_id, "title": "Release Audit", "template": "generic"},
    )
    assert generated.status_code == 201
    assert "Release evidence finding" in generated.get_json()["content"]
    reports = client.get(f"/api/reports?target_id={target_id}").get_json()
    assert reports[0]["format"] == "markdown"
    assert "Release evidence finding" in reports[0]["content"]

    submission = client.post(
        "/api/submissions",
        headers=headers,
        json={
            "platform": "HackerOne",
            "program_name": "Example",
            "finding_id": finding_id,
            "target_id": target_id,
            "notes": "release verification",
        },
    )
    assert submission.status_code == 201
    submission_id = int(submission.get_json()["id"])
    assert client.get(f"/api/submissions?target_id={target_id}").status_code == 200
    transitioned = client.post(
        f"/api/submissions/{submission_id}/transition",
        headers=headers,
        json={"status": "submitted", "external_id": "REL-1"},
    )
    assert transitioned.status_code == 200
    assert transitioned.get_json()["status"] == "submitted"
    assert client.get("/api/submissions/earnings").status_code == 200
    assert "draft" in client.get("/api/submissions/kanban").get_json()

    summary = client.get("/api/dashboard/summary").get_json()
    assert summary["findings"]["medium"] == 1
    assert summary["test_packs"] == 160


def test_release_api_guarded_execution_testpacks_capture_and_streams(release_app, monkeypatch) -> None:
    client = release_app.test_client()
    runtime = release_app.extensions["windeep.runtime"]
    capture = release_app.extensions["windeep.capture"]
    headers = _session(client)
    target_id, consent_id = _target_and_consent(client, headers)

    tools = client.get("/api/tools")
    assert tools.status_code == 200
    assert len(tools.get_json()) == 137
    assert client.get("/api/scans?limit=invalid").status_code == 200
    assert client.get("/api/scans/999999").status_code == 404
    assert client.get("/api/scans/999999/logs?limit=0").status_code == 200
    assert client.post("/api/scans/999999/cancel", headers=headers).status_code == 409
    assert client.post("/api/tools/run", headers=headers, json={"target_id": target_id}).status_code == 400

    run = client.post(
        "/api/tools/run",
        headers=headers,
        json={"target_id": target_id, "consent_id": consent_id, "tool": "custom_regex", "global_rps": 2},
    )
    assert run.status_code == 202, run.get_data(as_text=True)
    scan_id = int(run.get_json()["scan_id"])
    deadline = time.time() + 5
    scan = runtime.get_scan(scan_id)
    while scan and scan["status"] in {"pending", "running"} and time.time() < deadline:
        time.sleep(0.02)
        scan = runtime.get_scan(scan_id)
    assert scan is not None and scan["status"] == "completed"
    assert client.get(f"/api/scans/{scan_id}").status_code == 200
    assert client.get(f"/api/scans?target_id={target_id}").get_json()[0]["id"] == scan_id

    flow_id = runtime.database.insert_flow(
        {
            "target_id": target_id,
            "method": "GET",
            "url": "https://example.com/",
            "host": "example.com",
            "path": "/",
            "response_headers": {"Server": "Example/2.0", "Access-Control-Allow-Origin": "*", "Set-Cookie": "sid=x"},
            "response_body": b"Traceback: example exception",
        }
    )
    assert flow_id > 0
    packs = client.get("/api/test-packs").get_json()
    assert packs["count"] == 160
    executed = client.post(
        "/api/test-packs/run",
        headers=headers,
        json={
            "target_id": target_id,
            "consent_id": consent_id,
            "packs": ["browser_fidelity", "wild_cards"],
            "authenticated": True,
            "account_count": 2,
            "mobile_artifact": True,
            "signals": ["missing_csp"],
        },
    )
    assert executed.status_code == 200, executed.get_data(as_text=True)
    assert executed.get_json()["count"] == 30
    assert any(item["status"] in {"observed", "review"} for item in executed.get_json()["results"])

    # Brain/chains execute only local deterministic logic in this release gate.
    assert client.get(f"/api/brain/hypotheses?target_id={target_id}").status_code == 200
    generated = client.post(
        "/api/brain/hypotheses",
        headers=headers,
        json={"target_id": target_id, "consent_id": consent_id},
    )
    assert generated.status_code == 200
    assert client.get(f"/api/chains?target_id={target_id}").status_code == 200
    rebuilt = client.post(
        "/api/chains/rebuild",
        headers=headers,
        json={"target_id": target_id, "consent_id": consent_id},
    )
    assert rebuilt.status_code == 200
    assert client.get("/api/memory?q=").get_json() == {"count": 0, "items": []}

    monkeypatch.setattr(capture, "start", lambda **_kwargs: None)
    monkeypatch.setattr(capture, "stop", lambda **_kwargs: None)
    monkeypatch.setattr(capture, "is_running", lambda: True)
    monkeypatch.setattr(capture, "status", lambda: {"running": True, "host": "127.0.0.1", "port": 8080, "runtime_present": True, "pid": 42})
    assert client.get("/api/capture/status").get_json()["running"] is True
    assert client.post("/api/capture/start", headers=headers).status_code == 200
    assert client.post("/api/capture/stop", headers=headers).status_code == 200
    assert client.post("/api/capture/resolve", json={"url": "https://example.com"}).status_code == 401
    cap_headers = {"X-Windeep-Capture-Token": runtime.capture_token}
    assert client.post("/api/capture/resolve", headers=cap_headers, json={"url": "not-a-url"}).get_json() == {"scan_id": None, "target_id": None}
    assert client.post("/api/capture/events", headers=cap_headers, json={"topic": "tool.bad", "payload": {}}).status_code == 400
    assert client.post("/api/capture/events", headers=cap_headers, json={"topic": "log.capture", "payload": {"message": "ok"}}).status_code == 200

    class FakeBrowser:
        def __init__(self, **_kwargs):
            pass

        async def reflected_marker_check(self, url, *, parameter, marker):
            return {"url": url, "status": 200, "marker_in_dom": True, "marker_in_text": True, "parameter": parameter, "marker": marker}

        async def close(self):
            return None

    monkeypatch.setattr(api_module, "BrowserAutomationEngine", FakeBrowser)
    marker = client.post(
        "/api/browser/marker-check",
        headers=headers,
        json={"target_id": target_id, "consent_id": consent_id, "url": "https://example.com/?a=1", "parameter": "q", "marker": "SAFE-MARKER"},
    )
    assert marker.status_code == 200
    assert marker.get_json()["marker_in_dom"] is True
    assert client.post(
        "/api/browser/marker-check",
        headers=headers,
        json={"target_id": target_id, "consent_id": consent_id, "parameter": ""},
    ).status_code == 400

    settings = client.get("/api/settings").get_json()
    assert settings["tool_count"] == 137 and settings["test_count"] == 160

    response = client.get("/api/stream/global", buffered=False)
    assert next(response.response).startswith(b": windeep-event-stream")
    response.close()
    response = client.get(f"/api/stream/{scan_id}", buffered=False)
    assert next(response.response).startswith(b": windeep-scan-stream")
    response.close()
