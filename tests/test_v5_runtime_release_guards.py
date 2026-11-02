"""Exercise runtime management and desktop guardrails used by release builds."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import launcher
from app import desktop
from app.tools import cli, doctor as diagnostics, provisioning, remote_worker
from app.tools.backends import BackendUnavailableError


def test_launcher_selects_modes_and_configures_local_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "runtime" / "playwright-browsers").mkdir(parents=True)
    monkeypatch.setattr(launcher, "_application_root", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", launcher.os.environ.get("PATH", ""))
    monkeypatch.delenv("WINDEEP_APP_ROOT", raising=False)
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.delenv("PLAYWRIGHT_SKIP_BROWSER_GC", raising=False)
    monkeypatch.delenv("WINDEEP_NO_BROWSER", raising=False)
    monkeypatch.delenv("WINDEEP_STATE_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    launcher._configure_packaged_environment()
    assert Path(launcher.os.environ["WINDEEP_APP_ROOT"]) == tmp_path
    assert launcher.os.environ["PATH"].split(launcher.os.pathsep)[0] == str(tmp_path / "tools")
    assert Path(launcher.os.environ["PLAYWRIGHT_BROWSERS_PATH"]).name == "playwright-browsers"
    monkeypatch.setattr(launcher, "_configure_packaged_environment", lambda: None)
    monkeypatch.setattr(launcher, "_resolve_main", lambda: lambda: 7)
    monkeypatch.setattr(sys, "argv", ["windeep", "server"])
    assert launcher.main() == 7
    assert launcher.os.environ["WINDEEP_NO_BROWSER"] == "1"
    monkeypatch.setattr(sys, "argv", ["windeep", "browser"])
    assert launcher.main() == 7
    monkeypatch.setattr(desktop, "run_desktop", lambda: 4)
    monkeypatch.setattr(sys, "argv", ["windeep", "desktop"])
    assert launcher.main() == 4
    monkeypatch.setattr(cli, "main", lambda argv: 3)
    monkeypatch.setattr(sys, "argv", ["windeep", "doctor", "--json"])
    assert launcher.main() == 3


def test_launcher_missing_entry_point_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launcher.importlib, "import_module", lambda name: SimpleNamespace(main=None))
    with pytest.raises(RuntimeError, match="callable main"):
        launcher._resolve_main()


def test_desktop_launch_and_fallback_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setenv("WINDEEP_PORT", "7331")
    monkeypatch.setattr(desktop, "_serve_in_background", lambda port: calls.append(("serve", port)))
    monkeypatch.setattr(desktop, "_wait_until_ready", lambda port: True)
    monkeypatch.setattr(desktop, "_icon_path", lambda: "icon.ico")
    fake_webview = SimpleNamespace(create_window=lambda *a, **kw: calls.append(("window", a, kw)),
                                   start=lambda **kw: calls.append(("start", kw)))
    monkeypatch.setitem(sys.modules, "webview", fake_webview)
    assert desktop.run_desktop() == 0
    assert sum(item[0] == "window" for item in calls) == 1
    assert ("start", {"icon": "icon.ico"}) in calls
    monkeypatch.setattr(desktop, "_wait_until_ready", lambda port: False)
    monkeypatch.setattr(desktop, "_open_browser_fallback", lambda port, force_browser=False: 6)
    assert desktop.run_desktop() == 6
    monkeypatch.setenv("WINDEEP_PORT", "99999")
    with pytest.raises(ValueError):
        desktop._port()


def test_runtime_cli_requires_healing_consent_and_dispatches(monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path) -> None:
    monkeypatch.setenv("WINDEEP_APP_ROOT", str(tmp_path))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli.main(["doctor", "--heal"]) == 2
    assert "consent" in capsys.readouterr().err
    calls = []
    monkeypatch.setattr(cli, "doctor", lambda *a, **kw: calls.append(kw) or {"unavailable": 1, "tools": [], "catalog": 0})
    assert cli.main(["doctor", "--heal", "--yes", "--no-probe", "--json"]) == 3
    assert calls[0]["consent"] is True and calls[0]["probe"] is False
    capsys.readouterr()
    monkeypatch.setattr(cli, "backend_capabilities", lambda: {"native": True})
    assert cli.main(["doctor", "--backends", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["native"] is True
    monkeypatch.setattr(cli, "export_bundle", lambda *a, **kw: {"exported": True})
    assert cli.main(["bundle", "export", str(tmp_path / "bundle")]) == 0
    monkeypatch.setattr(cli, "import_bundle", lambda *a, **kw: {"imported": True, "load": kw["load_container"]})
    assert cli.main(["bundle", "import", "bundle", "--no-container"]) == 0
    monkeypatch.delenv("WINDEEP_REMOTE_WORKER_TOKEN", raising=False)
    assert cli.main(["remote-worker"]) == 2
    worker_calls = []
    monkeypatch.setattr(cli, "run_worker", lambda *a, **kw: worker_calls.append(kw))
    assert cli.main(["remote-worker", "--token", "test-token"]) == 0
    assert worker_calls[0]["host"] == "127.0.0.1"


def test_doctor_contracts_and_container_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cls = SimpleNamespace(required_env=("API_TOKEN",))
    assert diagnostics._skip_heal_reason("x", cls, {"release_support": "unsupported", "unsupported_reason": "no"}, {}, {}) == "catalog-unsupported:no"
    assert diagnostics._skip_heal_reason("x", cls, {}, {"x": {"kind": "host", "reason": "required"}}, {}) == "host:required"
    assert diagnostics._skip_heal_reason("x", cls, {}, {}, {}) == "credentials:API_TOKEN"
    assert diagnostics._skip_heal_reason("x", cls, {}, {}, {"API_TOKEN": "set"}) is None
    assert diagnostics._load_release_contracts(tmp_path) == {}
    contract = tmp_path / "app/tools/config/v4_release_contracts.json"
    contract.parent.mkdir(parents=True)
    contract.write_text('{"contract_only":{"x":{"kind":"host","reason":"required"}}}')
    assert diagnostics._load_release_contracts(tmp_path)["x"]["kind"] == "host"
    contract.write_text("bad json")
    assert diagnostics._load_release_contracts(tmp_path) == {}
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)
    assert diagnostics._build_container("fixture", tmp_path)["status"] == "skipped"
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/docker")
    assert diagnostics._build_container("fixture", tmp_path)["status"] == "failed"
    dockerfile = tmp_path / "docker/tools.Dockerfile"
    dockerfile.parent.mkdir()
    dockerfile.write_text("FROM scratch\n")
    monkeypatch.setattr(diagnostics.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="built"))
    assert diagnostics._build_container("fixture", tmp_path)["status"] == "built"


@pytest.mark.asyncio
async def test_doctor_probe_distinguishes_unavailable_builtin_failure_and_success() -> None:
    class Resolver:
        def __init__(self, backend=None): self.backend = backend
        def resolve(self, wrapper):
            if self.backend is None: raise BackendUnavailableError("missing")
            return self.backend
    wrapper = SimpleNamespace(resolver=Resolver(), probe=())
    assert (await diagnostics._probe(wrapper))["status"] == "unavailable"
    backend = SimpleNamespace(key="builtin_fallback", tier="builtin")
    wrapper.resolver = Resolver(backend)
    assert (await diagnostics._probe(wrapper))["probe"] == "adapter-registration"
    backend = SimpleNamespace(key="process", tier="native")
    wrapper.resolver = Resolver(backend)
    assert (await diagnostics._probe(wrapper))["status"] == "resolved"
    async def probe(*args, **kwargs): return "okay", "", 1
    backend.probe = probe
    wrapper.probe = ("--version",)
    assert (await diagnostics._probe(wrapper))["status"] == "pass"
    async def fail(*args, **kwargs): raise OSError("probe failed")
    backend.probe = fail
    assert (await diagnostics._probe(wrapper))["status"] == "failed"


def test_doctor_reports_catalog_and_failed_healing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Wrapper:
        execution_name = "demo"
        alias_to = ""
        provision = {"ecosystem": "test"}
        container_image = ""
        builtin_fallback = ""
        requires_host = ""
        required_env = ()
        def __init__(self, **kwargs): pass
        def runtime_status(self): return {"tier": "unavailable", "backend": None, "runtime_strategy": "auto"}
    monkeypatch.setattr(diagnostics, "ToolWrapperFactory", lambda path: SimpleNamespace(load=lambda: {"demo": Wrapper}))
    monkeypatch.setattr(diagnostics, "effective_definitions", lambda path: {"demo": {}})
    monkeypatch.setattr(diagnostics, "backend_capabilities", lambda env: {"native": True})
    class FakeProvisioner:
        def __init__(self, *args, **kwargs): pass
        def provision(self, *args, **kwargs): raise diagnostics.ProvisioningError("blocked")
    monkeypatch.setattr(diagnostics, "Provisioner", FakeProvisioner)
    def unavailable_wsl(*args, **kwargs):
        raise diagnostics.WslProvisioningError("fixture: WSL unavailable")
    monkeypatch.setattr(diagnostics, "provision_wsl", unavailable_wsl)
    result = diagnostics.doctor(tmp_path / "tools.json", tools_dir=tmp_path, heal=True, consent=True)
    assert result["catalog"] == 1 and result["unavailable"] == 1
    assert result["tools"][0]["actions"][0]["status"] == "failed"
    assert "demo: unavailable" in diagnostics.render_text(result)


@pytest.fixture
def worker_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    class Wrapper:
        requires_host = ""
        def __init__(self, **kwargs): self.environment = {}
        def resolve_local_binary(self): return tmp_path / "tool"
        def resolve_provisioned_binary(self): return None
    monkeypatch.setattr(remote_worker, "ToolWrapperFactory", lambda path: SimpleNamespace(load=lambda: {"demo": Wrapper}))
    app = remote_worker.create_worker_app(tmp_path / "tools.json", tmp_path, "secret-token")
    app.config["TESTING"] = True
    return app.test_client(), Wrapper


def test_remote_worker_authenticates_and_rejects_invalid_requests(worker_client) -> None:
    client, wrapper = worker_client
    assert client.get("/v1/health").status_code == 401
    headers = {"Authorization": "Bearer secret-token"}
    assert client.get("/v1/health", headers=headers).get_json()["catalog"] == 1
    assert client.post("/v1/exec", headers=headers, json={"tool": "unknown"}).status_code == 404
    assert client.post("/v1/exec", headers=headers, json={"tool": "demo", "argv": "bad"}).status_code == 400
    assert client.post("/v1/exec", headers=headers, json={"tool": "demo", "stdin_b64": "!!"}).status_code == 400
    wrapper.requires_host = "not-this-host"
    assert client.post("/v1/exec", headers=headers, json={"tool": "demo"}).status_code == 409


def test_remote_worker_runs_only_catalog_binary_and_handles_timeout(worker_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _wrapper = worker_client
    headers = {"Authorization": "Bearer secret-token"}
    seen = []
    async def run(argv, stdin, timeout, env):
        seen.append((argv, stdin, timeout))
        return "okay", "", 0
    monkeypatch.setattr(remote_worker, "_exec_process", run)
    response = client.post("/v1/exec", headers=headers, json={"tool": "demo", "argv": ["--help"], "stdin_b64": "YQ=="})
    assert response.status_code == 200 and response.get_json()["stdout"] == "okay"
    assert seen[0][0][-1] == "--help" and seen[0][1] == b"a"
    async def timeout(*args, **kwargs): raise asyncio.TimeoutError()
    monkeypatch.setattr(remote_worker, "_exec_process", timeout)
    assert client.post("/v1/exec", headers=headers, json={"tool": "demo"}).status_code == 504


def test_remote_worker_requires_tls_off_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    app = SimpleNamespace(run=lambda **kwargs: None)
    monkeypatch.setattr(remote_worker, "create_worker_app", lambda *a, **kw: app)
    monkeypatch.delenv("WINDEEP_WORKER_TLS_CERT", raising=False)
    monkeypatch.delenv("WINDEEP_WORKER_TLS_KEY", raising=False)
    with pytest.raises(RuntimeError, match="requires"):
        remote_worker.run_worker("registry", "tools", token="x", host="0.0.0.0")
    remote_worker.run_worker("registry", "tools", token="x", host="127.0.0.1")


def test_provisioner_requires_consent_and_restores_verified_cache(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    binary = tools / "provisioned" / "bin" / ("demo.exe" if os.name == "nt" else "demo")
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"owned fixture binary")
    tool = SimpleNamespace(tool_name="demo", execution_name="demo", binary="demo", tools_dir=tools,
                           provision={"ecosystem": "go", "package": "example.test/demo", "version": "v1", "binary": "demo"})
    manager = provisioning.Provisioner(tools)
    with pytest.raises(PermissionError, match="consent"):
        manager.provision(tool, consent=False)
    result = manager.provision(tool, consent=True)
    assert result.status == "provisioned" and result.command == ("<already-present>",)
    assert result.sha256 and result.cache_record
    binary.unlink()
    assert provisioning.restore_cached_binary(tool) == binary.resolve()
    assert binary.read_bytes() == b"owned fixture binary"
    record = json.loads(Path(result.cache_record).read_text())
    (tools / record["object"]).write_bytes(b"tampered")
    binary.unlink()
    assert provisioning.restore_cached_binary(tool) is None


@pytest.mark.parametrize("ecosystem", ["go", "cargo", "pipx", "npm"])
def test_provisioner_builds_bounded_package_commands_without_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ecosystem: str) -> None:
    tools = tmp_path / "tools"
    manager = provisioning.Provisioner(tools)
    binary = tools / "result"
    binary.write_bytes(b"fixture")
    tool = SimpleNamespace(tool_name="demo", execution_name="demo", binary="demo", tools_dir=tools,
                           provision={"ecosystem": ecosystem, "package": "demo-package", "version": "1.2.3", "binary": "demo"})
    answers = iter([None, binary])
    monkeypatch.setattr(manager, "_resolved_binary", lambda _tool: next(answers))
    monkeypatch.setattr(provisioning.shutil, "which", lambda name: f"/stub/{name}")
    calls = []
    monkeypatch.setattr(manager, "_run", lambda argv, **kw: calls.append((argv, kw)))
    result = manager.provision(tool, consent=True)
    assert result.status == "provisioned" and calls[0][0][0] == f"/stub/{ecosystem}"
    assert all(isinstance(arg, str) for arg in calls[0][0])
    assert "demo-package" in " ".join(calls[0][0])


def test_provisioner_rejects_failed_commands_and_missing_toolchains(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = provisioning.Provisioner(tmp_path)
    monkeypatch.setattr(provisioning.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout="failed"))
    with pytest.raises(provisioning.ProvisioningError, match="failed"):
        manager._run(["stub", "install"])
    monkeypatch.setattr(manager, "_resolved_binary", lambda _tool: None)
    monkeypatch.setattr(provisioning.shutil, "which", lambda name: None)
    tool = SimpleNamespace(tool_name="demo", execution_name="demo", binary="demo", tools_dir=tmp_path,
                           provision={"ecosystem": "go", "package": "demo"})
    with pytest.raises(provisioning.ProvisioningError, match="Go toolchain"):
        manager.provision(tool, consent=True)
