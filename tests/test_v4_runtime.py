from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Sequence

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_integrations
from app.tools.backends import ExecutionBackend, ExecutionResolver
from app.tools.provisioning import Provisioner
from app.tools.release_metadata import effective_definitions

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools_config.json"
TOOLS = ROOT / "tools"
ALLOWED_STRATEGIES = {"process", "builtin", "container", "wsl", "remote", "auto"}


class FakeBackend(ExecutionBackend):
    key = "local_binary"
    tier = "native"

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.calls = 0

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


def test_every_catalog_entry_declares_a_v4_runnable_route() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    effective = effective_definitions(REGISTRY)
    missing: list[str] = []
    for name, cls in classes.items():
        release_support = str(effective[name].get("release_support") or "")
        has_route = bool(
            getattr(cls, "provision", None)
            or getattr(cls, "container_image", "")
            or getattr(cls, "builtin_fallback", "")
            or getattr(cls, "alias_to", "")
            or getattr(cls, "requires_host", "")
            or builtin_integrations.supports(name)
            or release_support == "bundled"
        )
        if not has_route:
            missing.append(name)
    assert not missing, "catalog entries without a v4 execution route: " + ", ".join(sorted(missing))


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


def test_provisioner_refuses_install_without_explicit_consent(tmp_path: Path) -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    cls = classes["subfinder"]
    wrapper = cls(tools_dir=tmp_path, scope_validator=lambda _value: True)
    assert wrapper.provision
    with pytest.raises(PermissionError, match="explicit operator consent"):
        Provisioner(tmp_path).provision(wrapper, consent=False)


def test_v4_runtime_overlay_is_registered_from_root_config() -> None:
    root = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert root["schema_version"] == 4
    overlay = ROOT / root["runtime_overlays"]
    assert overlay.is_file()
    data = json.loads(overlay.read_text(encoding="utf-8"))
    assert data["schema_version"] == 4
    assert data["defaults"]["runtime_strategy"] == "auto"
