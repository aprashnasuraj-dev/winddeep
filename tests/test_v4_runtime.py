from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Sequence

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_fallbacks, builtin_integrations
from app.tools.backends import ExecutionBackend, ExecutionResolver
from app.tools.bundle import export_bundle, import_bundle
from app.tools.provisioning import Provisioner
from app.tools.release_metadata import effective_definitions
from app.tools.wsl_provisioning import provision_wsl

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools_config.json"
TOOLS = ROOT / "tools"
ALLOWED_STRATEGIES = {"process", "builtin", "container", "wsl", "remote", "auto"}


class FakeBackend(ExecutionBackend):
    key = "local_binary"
    tier = "native"

    def __init__(self, available: bool = True, *, key: str | None = None, tier: str | None = None) -> None:
        self.available = available
        self.calls = 0
        if key is not None:
            self.key = key
        if tier is not None:
            self.tier = tier

    def can_run(self, tool: Any) -> bool:
        return self.available

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float):
        self.calls += 1
        return "fake result\n", "", 0


def test_v4_factory_keeps_complete_catalog_and_runtime_strategy() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    assert len(classes) == 137
    assert all(cls.runtime_strategy in ALLOWED_STRATEGIES for cls in classes.values())
    assert all(cls.requires_scope for cls in classes.values())


def test_aliases_preserve_historical_names_but_route_to_maintained_contracts() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    expected = {
        "aquatone": "gowitness",
        "jsparser": "linkfinder",
        "waffw00f": "wafw00f",
        "sublist3r": "subfinder",
        "remix": "hardhat",
    }
    for alias, target in expected.items():
        if alias not in classes:
            continue
        assert classes[alias].alias_to == target
        assert classes[alias].execution_name == target


def _launch_excluded(definition: dict[str, Any]) -> bool:
    release_support = str(definition.get("release_support") or "")
    catalog_support = str(definition.get("catalog_release_support") or "")
    return release_support in {"deprecated", "legacy"} or (
        release_support == "unsupported" and catalog_support == "unsupported"
    )


def test_active_launch_entries_declare_a_v4_runnable_route() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    effective = effective_definitions(REGISTRY)
    missing: list[str] = []
    excluded: list[str] = []
    for name, cls in classes.items():
        if _launch_excluded(effective[name]):
            excluded.append(name)
            assert effective[name].get("unsupported_reason")
            continue
        release_support = str(effective[name].get("release_support") or "")
        has_route = bool(
            getattr(cls, "provision", None)
            or getattr(cls, "container_image", "")
            or getattr(cls, "builtin_fallback", "")
            or getattr(cls, "alias_to", "")
            or getattr(cls, "requires_host", "")
            or builtin_integrations.supports(name)
            or release_support in {"bundled", "external-service"}
        )
        if not has_route:
            missing.append(name)
    assert not missing, "catalog entries without a v4 execution route: " + ", ".join(sorted(missing))
    assert len(excluded) == 28


def test_passive_resolver_defers_external_backend_without_active_probe() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    wrapper = classes["whois"](tools_dir=TOOLS, scope_validator=lambda _value: True)

    class DeferredWsl(FakeBackend):
        key = "wsl"
        tier = "wsl"

        def can_run(self, tool: Any) -> bool:
            raise AssertionError("passive status must not launch an active WSL probe")

        def passive_can_run(self, tool: Any) -> bool | None:
            return None

    resolver = ExecutionResolver([DeferredWsl()])
    status = resolver.status(wrapper, active_probe=False)
    assert status["tier"] == "deferred"
    assert status["backend"] == "wsl"
    assert status["verified"] is False
    assert status["deferred"] is True
    assert status["chain"][0]["deferred"] is True


def test_resolver_uses_first_available_backend_in_declared_order() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    wrapper = classes["whois"](tools_dir=TOOLS, scope_validator=lambda _value: True)
    native = FakeBackend(False, key="local_binary", tier="native")
    provisioned = FakeBackend(True, key="provisioned_binary", tier="provisioned")
    container = FakeBackend(True, key="container", tier="container")
    resolver = ExecutionResolver([native, provisioned, container])
    assert resolver.resolve(wrapper) is provisioned
    assert resolver.status(wrapper)["backend"] == "provisioned_binary"
    assert resolver.status(wrapper)["tier"] == "provisioned"


def test_resolver_records_backend_evidence_without_real_tool_execution(tmp_path: Path) -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    cls = classes["whois"]
    backend = FakeBackend()
    resolver = ExecutionResolver([backend])
    wrapper = cls(tools_dir=tmp_path, scope_validator=lambda value: value == "example.com", resolver=resolver)
    findings = asyncio.run(wrapper.run("example.com"))
    assert backend.calls == 1
    assert findings
    assert findings[0].evidence["backend"] == "local_binary"
    assert findings[0].evidence["backend_tier"] == "native"


def test_alias_execution_records_served_by_and_deprecation_notice(tmp_path: Path) -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    cls = classes["aquatone"]
    backend = FakeBackend()
    wrapper = cls(tools_dir=tmp_path, scope_validator=lambda _value: True, resolver=ExecutionResolver([backend]))
    findings = asyncio.run(wrapper.run("example.com"))
    assert findings
    assert findings[0].evidence["served_by"] == "gowitness"
    assert findings[0].evidence["deprecated_alias"] is True
    assert "aquatone" in findings[0].evidence["deprecation_notice"]
    assert "gowitness" in findings[0].evidence["deprecation_notice"]


def test_provisioner_refuses_install_without_explicit_consent(tmp_path: Path) -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    cls = classes["subfinder"]
    wrapper = cls(tools_dir=tmp_path, scope_validator=lambda _value: True)
    assert wrapper.provision
    with pytest.raises(PermissionError, match="explicit operator consent"):
        Provisioner(tmp_path).provision(wrapper, consent=False)


def test_wsl_provisioning_refuses_install_without_explicit_consent(tmp_path: Path) -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    wrapper = classes["subfinder"](tools_dir=tmp_path, scope_validator=lambda _value: True)
    with pytest.raises(PermissionError, match="explicit operator consent"):
        provision_wsl(wrapper, consent=False)


def test_builtin_fallback_catalog_covers_dead_and_api_shaped_cli_routes() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    expected = {
        "waybackrobots": "wayback_cdx",
        "whois": "rdap",
        "dig": "dns_query",
        "crtsh": "crtsh",
        "linkfinder": "js_analysis",
        "git_secrets": "repo_secret_scan",
    }
    for name, adapter in expected.items():
        assert classes[name].builtin_fallback == adapter
        assert builtin_fallbacks.supports(adapter)


def test_scan_planner_has_no_selected_or_catalog_readiness_bypass() -> None:
    source = (ROOT / "app" / "v2_api.py").read_text(encoding="utf-8")
    assert "runtime_state = wrapper.runtime_status(active_probe=active_probe)" in source
    assert "all_descriptors(normalized_target_type, active_probe=True)" in source
    assert 'runtime_tier != "unavailable"' in source
    assert "require_ready = False" not in source
    assert 'if not item["ready"]:' in source


def test_v4_ui_blocks_run_buttons_when_runtime_or_target_is_not_runnable() -> None:
    index = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    ui = (ROOT / "app" / "static" / "v4_runtime_ui.js").read_text(encoding="utf-8")
    assert "/static/v4_runtime_ui.js" in index
    assert "Windeep v4" in index
    assert "t.ready && t.compatible" in ui
    assert "disabled aria-disabled" in ui
    assert "runtime_tier" in ui


def test_offline_bundle_round_trip_preserves_and_verifies_cached_runtime(tmp_path: Path) -> None:
    source = tmp_path / "source-tools"
    source.mkdir()
    payload = source / "example-tool"
    payload.write_bytes(b"windeep-v4-offline-fixture\n")
    archive = tmp_path / "runtime.tar.zst"
    exported = export_bundle(source, archive, container_image="windeep/nonexistent:test")
    assert Path(exported["output"]).is_file()
    assert exported["sha256"]
    restored = tmp_path / "restored-tools"
    imported = import_bundle(archive, restored, load_container=False)
    assert imported["verified"] is True
    assert imported["verified_files"] >= 1
    assert (restored / "example-tool").read_bytes() == payload.read_bytes()


def test_v4_runtime_overlay_is_registered_from_root_config() -> None:
    root = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert root["schema_version"] == 4
    assert root["registered_tool_count"] == 137
    assert root["active_tool_count"] == 109
    overlay = ROOT / root["runtime_overlays"]
    assert overlay.is_file()
    data = json.loads(overlay.read_text(encoding="utf-8"))
    assert data["schema_version"] == 4
    assert data["defaults"]["runtime_strategy"] == "auto"


def test_v4_contract_matrix_runs_runtime_regressions_on_windows_and_linux() -> None:
    workflow = (ROOT / ".github" / "workflows" / "v4-runtime-gate.yml").read_text(encoding="utf-8")
    assert "tests/test_v4_runtime_regressions.py" in workflow
