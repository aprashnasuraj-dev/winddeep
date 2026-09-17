"""Compatibility/security regression coverage kept by the v3 gate during v4 work."""
from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import app.security.crypto as crypto_module
import app.server as server
from app.engine.tool_wrapper import ToolWrapperBase
from app.security.crypto import CryptoManager, DPAPIProtector, FileProtector, SecretProtectionError


@pytest.fixture
def compatibility_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))

    async def no_network_run(self, target: str, *args: Any, **kwargs: Any):  # noqa: ARG001
        return []

    monkeypatch.setattr(ToolWrapperBase, "run", no_network_run)
    app = server.create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _session(client):
    response = client.post("/api/handshake", json={})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.get_json()["csrf_token"]}


def _target_and_consent(client, headers, target: str = "example.com"):
    created = client.post(
        "/api/targets",
        json={"name": "compatibility fixture", "type": "domain", "target": target, "scope": [target], "out_of_scope": []},
        headers=headers,
    )
    assert created.status_code == 201
    row = created.get_json()
    consent = client.post(
        "/api/consent",
        json={"target": target, "scope": [target], "out_of_scope": [], "authorized_by": "compat-qa", "purpose": "authorized compatibility regression", "ttl_seconds": 600},
        headers=headers,
    )
    assert consent.status_code == 201
    return row, consent.get_json()


def test_legacy_api_crud_errors_settings_and_inventory_remain_compatible(compatibility_client) -> None:
    client = compatibility_client
    assert client.get("/api/targets").status_code == 401
    headers = _session(client)
    assert client.get("/api/session").status_code == 200

    assert client.get("/api/targets/999999").status_code == 404
    assert client.post("/api/targets", json={"name": "missing target"}, headers=headers).status_code == 400
    target, consent = _target_and_consent(client, headers)
    target_id = int(target["id"])

    listed = client.get("/api/targets").get_json()
    assert any(int(row["id"]) == target_id for row in listed)
    updated = client.put(f"/api/targets/{target_id}", json={"name": "renamed", "notes": "covered", "tags": ["compat"]}, headers=headers)
    assert updated.status_code == 200
    assert updated.get_json()["name"] == "renamed"
    assert client.put("/api/targets/999999", json={"name": "x"}, headers=headers).status_code == 404
    assert client.delete("/api/targets/999999", headers=headers).status_code == 404

    denied = client.post(
        "/api/preflight/check",
        json={"target": "example.com", "scope": ["example.com"], "out_of_scope": [], "consent_id": "not-a-consent"},
        headers=headers,
    )
    assert denied.status_code == 403

    assert client.get(f"/api/scans?target_id={target_id}").get_json() == []
    assert client.get("/api/scans/999999").status_code == 404
    assert client.get("/api/scans/999999/logs").status_code == 200
    assert client.post("/api/scans/999999/cancel", json={}, headers=headers).status_code == 404
    assert client.post("/api/scans", json={"target_id": 999999, "consent_id": consent["id"]}, headers=headers).status_code == 404

    created_finding = client.post(
        "/api/findings",
        json={"target_id": target_id, "title": "Manual compatibility finding", "severity": "medium", "vuln_type": "manual", "tool": "manual", "evidence": {"source": "qa"}},
        headers=headers,
    )
    assert created_finding.status_code == 201
    finding_id = int(created_finding.get_json()["finding"]["id"])
    assert client.get(f"/api/findings/{finding_id}").status_code == 200
    summary = client.get(f"/api/findings/summary?target_id={target_id}").get_json()
    assert summary["medium"] == 1
    changed = client.put(f"/api/findings/{finding_id}", json={"severity": "high", "status": "triaged", "confidence": 0.9}, headers=headers)
    assert changed.status_code == 200
    assert changed.get_json()["severity"] == "high"
    assert client.put("/api/findings/999999", json={"status": "closed"}, headers=headers).status_code == 404
    assert client.post("/api/findings", json={"target_id": target_id}, headers=headers).status_code == 400

    report = client.post("/api/reports/generate", json={"target_id": target_id, "title": "Compatibility report"}, headers=headers)
    assert report.status_code == 201
    reports = client.get(f"/api/reports?target_id={target_id}").get_json()
    assert reports and reports[0]["title"] == "Compatibility report"
    assert client.post("/api/reports/generate", json={"target_id": 999999}, headers=headers).status_code == 404

    default_settings = client.get("/api/settings").get_json()
    assert default_settings["secrets_stored_encrypted"] is True
    saved = client.put("/api/settings", json={"scan_speed": "slow", "api_token": "secret-value"}, headers=headers)
    assert saved.status_code == 200
    masked = client.get("/api/settings").get_json()
    assert masked["api_token"] == "configured"

    tools = client.get("/api/tools").get_json()
    assert len(tools) == 137
    assert client.post("/api/tools/run", json={"target_id": 999999, "tool": "whois", "consent_id": consent["id"]}, headers=headers).status_code == 404
    unknown_tool = client.post("/api/tools/run", json={"target_id": target_id, "tool": "definitely-not-a-tool", "consent_id": consent["id"]}, headers=headers)
    assert unknown_tool.status_code == 400

    packs = client.get("/api/test-packs").get_json()
    assert packs["total"] > 0
    assert client.get("/api/test-packs/not-a-pack/status").status_code == 404
    integrations = client.get("/api/integrations").get_json()
    assert integrations["tools"]["active"] == 137

    assert client.delete(f"/api/findings/{finding_id}", headers=headers).status_code == 200
    assert client.get(f"/api/findings/{finding_id}").status_code == 404

    disposable = client.post(
        "/api/targets",
        json={"name": "disposable", "type": "domain", "target": "delete.example", "scope": ["delete.example"], "out_of_scope": []},
        headers=headers,
    ).get_json()
    assert client.delete(f"/api/targets/{disposable['id']}", headers=headers).status_code == 200


def test_v2_error_paths_and_target_alignment_stay_stable(compatibility_client) -> None:
    client = compatibility_client
    headers = _session(client)
    target, _consent = _target_and_consent(client, headers, "v2-errors.example")
    target_id = int(target["id"])

    assert client.get("/api/v2/scan-plan").status_code == 400
    assert client.get("/api/v2/scan-plan?target_id=999999&mode=smart").status_code == 404
    unknown_mode = client.get(f"/api/v2/scan-plan?target_id={target_id}&mode=definitely-unknown")
    assert unknown_mode.status_code == 400

    mobile_tools = client.get("/api/v2/tools?target_type=apk")
    assert mobile_tools.status_code == 200
    rows = mobile_tools.get_json()["tools"]
    assert len(rows) == 137
    assert any(row["compatible"] is False for row in rows)

    assert client.post("/api/v2/scans", json={}, headers=headers).status_code == 400
    assert client.post("/api/v2/scans/999999/stop", json={}, headers=headers).status_code == 403
    assert client.get("/api/v2/scans/999999/events").status_code in {400, 403, 404}
    assert client.post("/api/v2/reports/generate", json={}, headers=headers).status_code == 400
    assert client.get("/api/v2/intelligence").status_code == 400
    assert client.get("/api/v2/status").status_code == 200

    saved = client.put("/api/v2/settings", json={"global_rps": 7.0, "scan_speed": "balanced", "unknown": "ignored"}, headers=headers)
    assert saved.status_code == 200
    settings = client.get("/api/v2/settings").get_json()
    assert settings["global_rps"] == 7.0


class _MemoryProtector:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key
        self.protected: list[bytes] = []

    def protect(self, plaintext: bytes) -> bytes:
        self.protected.append(plaintext)
        self.key = plaintext
        return b"wrapped:" + plaintext

    def unprotect(self, protected: bytes) -> bytes:
        assert protected.startswith(b"wrapped:")
        return protected[len(b"wrapped:") :]


def test_crypto_portable_reload_errors_and_legacy_plaintext(tmp_path: Path) -> None:
    master = tmp_path / "portable.key"
    protector = FileProtector(master)
    protected = protector.protect(b"secret")
    assert FileProtector(master).unprotect(protected) == b"secret"
    with pytest.raises(SecretProtectionError, match="too short"):
        protector.unprotect(b"short")

    bad_master = tmp_path / "bad.key"
    bad_master.write_bytes(b"not-32-bytes")
    with pytest.raises(SecretProtectionError, match="32 bytes"):
        FileProtector(bad_master)

    wrapped = tmp_path / "dek.bin"
    memory = _MemoryProtector()
    manager = CryptoManager(wrapped_key_path=wrapped, protector=memory)
    cipher = manager.encrypt_text("hello", aad=b"compat")
    assert manager.decrypt_text(cipher, aad=b"compat") == "hello"
    assert manager.decrypt_text("legacy-plaintext") == "legacy-plaintext"
    assert CryptoManager(wrapped_key_path=wrapped, protector=_MemoryProtector()).healthcheck()["ok"] is True
    with pytest.raises(ValueError, match="too short"):
        manager.decrypt_bytes(b"tiny")

    bad_dek_path = tmp_path / "bad-dek.bin"
    bad_dek_path.write_bytes(b"wrapped:bad")
    with pytest.raises(SecretProtectionError, match="data-encryption key"):
        CryptoManager(wrapped_key_path=bad_dek_path, protector=_MemoryProtector())


def test_dpapi_contract_rejects_non_windows_and_handles_fake_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto_module.os, "name", "posix")
    with pytest.raises(OSError, match="only available on Windows"):
        DPAPIProtector()

    buffers: list[Any] = []

    class FakeCrypt32:
        def __init__(self) -> None:
            self.fail = False

        def _write(self, out_ref, payload: bytes) -> int:
            if self.fail:
                return 0
            buffer = ctypes.create_string_buffer(payload)
            buffers.append(buffer)
            out = out_ref._obj
            out.cbData = len(payload)
            out.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))
            return 1

        def CryptProtectData(self, in_blob, description, entropy, reserved, prompt, flags, out_ref):  # noqa: N802, ARG002
            return self._write(out_ref, b"wrapped")

        def CryptUnprotectData(self, in_blob, description, entropy, reserved, prompt, flags, out_ref):  # noqa: N802, ARG002
            return self._write(out_ref, b"plain")

    class FakeKernel32:
        def __init__(self) -> None:
            self.freed = 0

        def LocalFree(self, pointer):  # noqa: N802, ARG002
            self.freed += 1
            return 0

    crypt32 = FakeCrypt32()
    kernel32 = FakeKernel32()
    monkeypatch.setattr(crypto_module.os, "name", "nt")
    monkeypatch.setattr(crypto_module.ctypes, "windll", SimpleNamespace(crypt32=crypt32, kernel32=kernel32), raising=False)
    monkeypatch.setattr(crypto_module.ctypes, "GetLastError", lambda: 5, raising=False)
    protector = DPAPIProtector(entropy=b"qa")
    assert protector.protect(b"input") == b"wrapped"
    assert protector.unprotect(b"cipher") == b"plain"
    assert kernel32.freed == 2
    with pytest.raises(ValueError, match="must not be empty"):
        protector.protect(b"")
    with pytest.raises(ValueError, match="must not be empty"):
        protector.unprotect(b"")
    crypt32.fail = True
    with pytest.raises(SecretProtectionError, match="CryptProtectData failed"):
        protector.protect(b"input")
    with pytest.raises(SecretProtectionError, match="CryptUnprotectData failed"):
        protector.unprotect(b"cipher")
