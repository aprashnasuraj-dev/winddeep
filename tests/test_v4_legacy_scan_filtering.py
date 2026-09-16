"""Regression coverage for resolver filtering on the legacy async scan API."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

import app.server as server
from app.engine.tool_wrapper import ToolWrapperBase
from app.v4.api import filter_resolver_tools


class _ReadyWrapper:
    target_types = ("web",)
    provision = None
    requires_host = ""
    category = "test"
    description = "ready"
    execution_name = "ready"
    alias_to = ""
    runtime_strategy = "auto"
    execution_preference = ("builtin_fallback",)
    scan_default = True
    builtin_fallback = "ready"
    container_image = ""
    probe = ()
    release_support = "resolver-managed"

    def __init__(self, **_kwargs: Any) -> None:
        pass

    def runtime_status(self) -> dict[str, Any]:
        return {"tier": "builtin-fallback", "backend": "builtin_fallback", "chain": ["builtin_fallback"]}

    def missing_environment(self) -> tuple[str, ...]:
        return ()


class _UnavailableWrapper(_ReadyWrapper):
    execution_name = "unavailable"
    builtin_fallback = ""

    def runtime_status(self) -> dict[str, Any]:
        return {"tier": "unavailable", "backend": None, "chain": []}


def _session(client):
    response = client.post("/api/handshake", json={})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.get_json()["csrf_token"]}


def _authorized_target(client, headers):
    target_response = client.post(
        "/api/targets",
        json={
            "name": "Legacy resolver regression",
            "type": "web",
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": [],
            "tags": ["v4-runtime"],
            "notes": "authorized regression fixture",
        },
        headers=headers,
    )
    assert target_response.status_code == 201
    target = target_response.get_json()
    consent_response = client.post(
        "/api/consent",
        json={
            "target": "example.com",
            "scope": ["example.com", "*.example.com"],
            "out_of_scope": [],
            "authorized_by": "v4-runtime-test",
            "purpose": "authorized regression fixture",
            "ttl_seconds": 600,
        },
        headers=headers,
    )
    assert consent_response.status_code == 201
    return target, consent_response.get_json()


def _poll(client, scan_id: int, terminal: set[str], timeout: float = 3.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    row: dict[str, Any] = {}
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        row = response.get_json()
        if row["status"] in terminal:
            return row
        time.sleep(0.02)
    pytest.fail(f"scan {scan_id} did not reach {sorted(terminal)}; last={row}")


def _client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))

    async def no_network_run(self, target: str, *args: Any, **kwargs: Any):  # noqa: ARG001
        return []

    monkeypatch.setattr(ToolWrapperBase, "run", no_network_run)
    app = server.create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_shared_v4_filter_selects_ready_and_reports_filtered_out(tmp_path: Path) -> None:
    selected, skipped = filter_resolver_tools(
        {"ready": _ReadyWrapper, "blocked": _UnavailableWrapper},
        tools_dir=tmp_path / "tools",
        target_type="web",
        candidate_names=["blocked", "ready"],
        environment={},
    )
    assert selected == ["ready"]
    assert skipped == [{
        "tool": "blocked",
        "reason": "No execution backend currently resolves this integration.",
        "tier": "unavailable",
        "provisionable": False,
        "code": "TOOL_NOT_RESOLVER_READY",
    }]


def test_legacy_scan_filters_candidates_inside_worker_and_completes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def resolver_filter(_classes, *, tools_dir, target_type, candidate_names, environment):  # noqa: ARG001
        seen.append(list(candidate_names))
        return ["whois"], [{"tool": "nmap", "reason": "not resolver-ready", "tier": "unavailable", "provisionable": False, "code": "TOOL_NOT_RESOLVER_READY"}]

    monkeypatch.setattr(server, "filter_resolver_tools", resolver_filter)
    client = _client(monkeypatch, tmp_path)
    headers = _session(client)
    target, consent = _authorized_target(client, headers)

    started = client.post(
        "/api/scans",
        json={"target_id": target["id"], "consent_id": consent["id"], "scan_type": "module", "modules": ["whois", "nmap"]},
        headers=headers,
    )
    assert started.status_code == 202
    row = _poll(client, int(started.get_json()["id"]), {"completed", "failed"})
    assert row["status"] == "completed"
    assert row["results_summary"]["tools"] == 1
    assert row["results_summary"]["errors"] == []
    assert seen and set(seen[0]) == {"whois", "nmap"}


def test_legacy_scan_no_resolver_match_returns_202_then_fails_job(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def resolver_filter(_classes, *, tools_dir, target_type, candidate_names, environment):  # noqa: ARG001
        return [], [{"tool": name, "reason": "not resolver-ready", "tier": "unavailable", "provisionable": False, "code": "TOOL_NOT_RESOLVER_READY"} for name in candidate_names]

    monkeypatch.setattr(server, "filter_resolver_tools", resolver_filter)
    client = _client(monkeypatch, tmp_path)
    headers = _session(client)
    target, consent = _authorized_target(client, headers)

    started = client.post(
        "/api/scans",
        json={"target_id": target["id"], "consent_id": consent["id"], "scan_type": "module", "modules": ["whois"]},
        headers=headers,
    )
    assert started.status_code == 202
    row = _poll(client, int(started.get_json()["id"]), {"failed"})
    error = row["results_summary"]["errors"][0]
    assert error["tool"] == "orchestrator"
    assert "no resolver-ready tool integrations matched" in error["error"]


def test_legacy_scan_preserves_immediate_202_then_poll_complete(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def delayed_filter(_classes, *, tools_dir, target_type, candidate_names, environment):  # noqa: ARG001
        entered.set()
        assert release.wait(2.0)
        return ["whois"], []

    monkeypatch.setattr(server, "filter_resolver_tools", delayed_filter)
    client = _client(monkeypatch, tmp_path)
    headers = _session(client)
    target, consent = _authorized_target(client, headers)

    started = client.post(
        "/api/scans",
        json={"target_id": target["id"], "consent_id": consent["id"], "scan_type": "module", "modules": ["whois"]},
        headers=headers,
    )
    assert started.status_code == 202
    assert entered.wait(1.0)
    # Preserve the compatibility API's established response snapshot exactly:
    # create_scan returns pending even if the worker has already started.
    assert started.get_json()["status"] == "pending"
    release.set()
    row = _poll(client, int(started.get_json()["id"]), {"completed", "failed"})
    assert row["status"] == "completed"
    assert row["progress"] == 100.0
