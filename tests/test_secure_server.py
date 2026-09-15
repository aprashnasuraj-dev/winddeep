"""Tests for Windeep's localhost dashboard handshake, CSRF, and consent APIs."""

from __future__ import annotations

from app.server import create_app


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _handshake(client) -> str:
    response = client.post("/api/handshake")
    assert response.status_code == 200
    return response.get_json()["csrf_token"]


def test_health_reports_local_security_controls(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["localhost_only"] is True
    assert payload["controls"]["crypto"]["ok"] is True
    assert payload["controls"]["audit"]["ok"] is True


def test_handshake_sets_http_only_same_site_cookie(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post("/api/handshake")
    cookie = response.headers["Set-Cookie"]
    assert response.status_code == 200
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert response.get_json()["csrf_token"]


def test_mutation_requires_csrf_after_handshake(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    _handshake(client)
    response = client.post(
        "/api/consent",
        json={"target": "example.com", "authorized_by": "owner", "purpose": "authorized test"},
    )
    assert response.status_code == 401
    assert "CSRF" in response.get_json()["error"]


def test_consent_and_preflight_work_with_csrf(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    csrf = _handshake(client)
    consent_response = client.post(
        "/api/consent",
        headers={"X-CSRF-Token": csrf},
        json={
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "authorized_by": "owner",
            "purpose": "authorized bug bounty",
            "ttl_seconds": 600,
        },
    )
    assert consent_response.status_code == 201
    consent_id = consent_response.get_json()["id"]
    check = client.post(
        "/api/preflight/check",
        headers={"X-CSRF-Token": csrf},
        json={
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": ["admin.example.com"],
            "consent_id": consent_id,
        },
    )
    assert check.status_code == 200
    assert check.get_json()["authorized"] is True


def test_non_loopback_request_is_blocked(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
    assert response.status_code == 403
    assert "local-only" in response.get_json()["error"]
