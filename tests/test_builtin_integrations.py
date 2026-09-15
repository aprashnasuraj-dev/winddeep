"""Regression coverage for non-CLI Windeep catalog integrations."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.tools import builtin_integrations as bi


class FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> Any:
        return self.payload


class FakeClient:
    def __init__(self, responses: list[FakeResponse], calls: list[tuple[str, str, dict[str, Any]]]) -> None:
        self.responses = responses
        self.calls = calls

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    async def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)


def install_fake_http(monkeypatch: pytest.MonkeyPatch, payloads: list[Any]) -> list[tuple[str, str, dict[str, Any]]]:
    calls: list[tuple[str, str, dict[str, Any]]] = []
    responses = [item if isinstance(item, FakeResponse) else FakeResponse(item) for item in payloads]

    def factory(*args: Any, **kwargs: Any) -> FakeClient:
        del args, kwargs
        return FakeClient(responses, calls)

    monkeypatch.setattr(bi.httpx, "AsyncClient", factory)
    return calls


def run(name: str, target: str, env: dict[str, str] | None = None):
    return asyncio.run(bi.run(name, target, environment=env or {}))


def test_metadata_helpers_and_missing_environment() -> None:
    assert bi.supports("crtsh") is True
    assert bi.supports("not_real") is False
    assert bi.required_env("shodan") == ("SHODAN_API_KEY",)
    assert bi.required_env("crtsh") == ()
    assert bi._env({"TOKEN": "abc"}, "TOKEN") == "abc"
    with pytest.raises(RuntimeError, match="TOKEN is required"):
        bi._env({}, "TOKEN")
    assert bi._redact("short") == "*****"
    assert bi._redact("abcdefghijk") == "abcd…hijk"
    finding = bi._finding("demo", "example.test", "title", evidence={"ok": True})
    assert finding["tool"] == "demo"
    assert finding["endpoint"] == "example.test"
    assert finding["evidence"] == {"ok": True}
    with pytest.raises(KeyError, match="no built-in integration handler"):
        run("not_real", "example.test")


def test_crtsh_adapter_normalizes_unique_names(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install_fake_http(
        monkeypatch,
        [[
            {"name_value": "a.example.test\n*.b.example.test"},
            {"name_value": "a.example.test\nc.example.test"},
        ]],
    )
    rows = run("crtsh", "example.test")
    assert [row["title"] for row in rows] == ["a.example.test", "b.example.test", "c.example.test"]
    assert rows[0]["evidence"]["source"] == "crt.sh"
    assert calls[0][0] == "GET"
    assert "crt.sh" in calls[0][1]


def test_shodan_adapter_supports_ip_and_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install_fake_http(
        monkeypatch,
        [
            {"ip_str": "203.0.113.10", "ports": [443], "org": "Example Org", "hostnames": ["example.test"]},
            {"matches": [{"ip_str": "203.0.113.11", "port": 8443, "org": "Example Org", "hostnames": ["api.example.test"]}]},
        ],
    )
    ip_rows = run("shodan", "203.0.113.10", {"SHODAN_API_KEY": "test-key"})
    host_rows = run("shodan", "example.test", {"SHODAN_API_KEY": "test-key"})
    assert ip_rows[0]["evidence"]["ports"] == [443]
    assert host_rows[0]["endpoint"] == "203.0.113.11"
    assert calls[0][2]["params"]["key"] == "test-key"
    assert calls[1][2]["params"]["query"] == "hostname:example.test"


def test_censys_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install_fake_http(
        monkeypatch,
        [{"result": {"hits": [{"ip": "203.0.113.20", "name": "edge.example.test", "services": [{"port": 443}]}]}}],
    )
    rows = run(
        "censys",
        "example.test",
        {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"},
    )
    assert rows[0]["title"] == "Censys host 203.0.113.20"
    assert rows[0]["evidence"]["name"] == "edge.example.test"
    assert calls[0][2]["params"]["q"] == "example.test"


def test_etherscan_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    address = "0x0000000000000000000000000000000000000001"
    calls = install_fake_http(
        monkeypatch,
        [{"status": "1", "message": "OK", "result": [{"ContractName": "Example", "CompilerVersion": "v0.8.30", "OptimizationUsed": "1", "Proxy": "0", "Implementation": ""}]}],
    )
    rows = run("etherscan", address, {"ETHERSCAN_API_KEY": "key"})
    assert rows[0]["title"] == "Etherscan contract Example"
    assert rows[0]["evidence"]["compiler"] == "v0.8.30"
    assert calls[0][2]["params"]["address"] == address


def test_etherscan_rejects_malformed_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_http(monkeypatch, [{"unexpected": True}])
    with pytest.raises(RuntimeError, match="unexpected Etherscan"):
        run("etherscan", "0x1", {"ETHERSCAN_API_KEY": "key"})


def test_corellium_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install_fake_http(monkeypatch, [[{"id": "p1", "name": "Authorized Project"}]])
    rows = run(
        "corellium",
        "device-fixture",
        {"CORELLIUM_BASE_URL": "https://corellium.example", "CORELLIUM_API_TOKEN": "token"},
    )
    assert rows[0]["title"] == "Corellium project Authorized Project"
    assert calls[0][1] == "https://corellium.example/api/v1/projects"


def test_mobsf_upload_and_scan_adapter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"PK\x03\x04test")
    calls = install_fake_http(
        monkeypatch,
        [
            {"hash": "abc123", "scan_type": "apk", "file_name": "fixture.apk"},
            {"app_name": "Fixture", "package_name": "test.fixture", "security_score": 71, "high": 1, "warning": 2, "info": 3},
        ],
    )
    rows = run(
        "mobsf",
        str(apk),
        {"MOBSF_URL": "http://127.0.0.1:8000", "MOBSF_API_KEY": "token"},
    )
    assert rows[0]["title"] == "MobSF analysis fixture.apk"
    assert rows[0]["evidence"]["security_score"] == 71
    assert [call[0] for call in calls] == ["POST", "POST"]
    assert calls[0][1].endswith("/api/v1/upload")
    assert calls[1][1].endswith("/api/v1/scan")


def test_mobsf_requires_local_file() -> None:
    with pytest.raises(FileNotFoundError, match="local APK/IPA"):
        run(
            "mobsf",
            "/definitely/missing.apk",
            {"MOBSF_URL": "http://127.0.0.1:8000", "MOBSF_API_KEY": "token"},
        )


def test_remix_link_adapter() -> None:
    rows = run("remix", "contract.sol")
    assert rows == [
        {
            "title": "Remix IDE integration ready",
            "severity": "info",
            "vuln_type": "integration_result",
            "tool": "remix",
            "endpoint": "https://remix.ethereum.org/",
            "description": "Open the official Remix IDE and import the authorized contract/source.",
            "evidence": {"url": "https://remix.ethereum.org/", "target": "contract.sol"},
            "confidence": 1.0,
        }
    ]


def test_custom_regex_scans_local_text_and_redacts_values(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.txt").write_text(
        "github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
        "api_key = abcdefghijklmnopqrstuvwxyz012345\n",
        encoding="utf-8",
    )
    (repo / "binary.bin").write_bytes(b"\x00\x01\x02")
    rows = run("custom_regex", str(repo))
    assert rows
    assert {row["tool"] for row in rows} == {"custom_regex"}
    assert all("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in str(row["evidence"]) for row in rows)
    assert all("abcdefghijklmnopqrstuvwxyz012345" not in str(row["evidence"]) for row in rows)


def test_custom_regex_can_assess_literal_text() -> None:
    rows = run("custom_regex", "token=abcdefghijklmnop1234567890")
    assert rows
    assert rows[0]["evidence"]["source"] == "<target>"


def test_operational_factory_exposes_137_and_builtin_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The branch migration runs before this suite and expands the runtime includes
    # to the complete eight-file catalog while preserving the six certified
    # Windows payloads as a separate packaging concern.
    from app.engine.tool_wrapper import ToolWrapperFactory

    root = Path(__file__).resolve().parents[1]
    classes = ToolWrapperFactory(root / "tools_config.json").load()
    assert len(classes) == 137
    assert {"crtsh", "shodan", "censys", "etherscan", "mobsf", "remix", "custom_regex"}.issubset(classes)

    async def fake_run(name: str, target: str, *, environment=None):
        del environment
        return [{"title": "ok", "severity": "info", "vuln_type": "integration_result", "tool": name, "endpoint": target, "description": "", "evidence": {}, "confidence": 1.0}]

    monkeypatch.setattr(bi, "run", fake_run)
    wrapper = classes["remix"](tools_dir=tmp_path, scope_validator=lambda value: value == "contract.sol")
    assert wrapper.validate_installed() is True
    findings = asyncio.run(wrapper.run("contract.sol"))
    assert findings[0].tool == "remix"
    assert findings[0].title == "ok"
