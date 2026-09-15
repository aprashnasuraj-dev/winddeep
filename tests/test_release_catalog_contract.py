"""Regression tests for the v0.1.0 catalog/runtime/installer separation."""
from __future__ import annotations

import json
from pathlib import Path

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools.release_metadata import apply_release_metadata, effective_definitions, load_definitions

ROOT = Path(__file__).resolve().parents[1]
CERTIFIED = {"subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei"}


def test_complete_catalog_contains_exactly_137_unique_definitions() -> None:
    definitions = load_definitions(ROOT / "tools_config.json")
    assert len(definitions) == 137
    assert len(set(definitions)) == 137
    assert all(definition.get("requires_scope") is True for definition in definitions.values())


def test_release_policy_certifies_only_reviewed_bundled_tools() -> None:
    effective = effective_definitions(ROOT / "tools_config.json")
    assert len(effective) == 137
    bundled = {name for name, definition in effective.items() if definition.get("release_support") == "bundled"}
    assert bundled == CERTIFIED
    assert all(
        definition.get("release_support") in {
            "bundled", "runtime", "internal", "external-service", "unsupported", "deprecated", "legacy"
        }
        for definition in effective.values()
    )


def test_runtime_registry_is_exact_certified_subset() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    assert set(classes) == CERTIFIED
    assert all(wrapper.requires_scope is True for wrapper in classes.values())


def test_release_metadata_annotates_only_the_runtime_subset() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    effective = apply_release_metadata(classes, ROOT / "tools_config.json")
    assert len(effective) == 137
    assert set(classes) == CERTIFIED
    for name, wrapper in classes.items():
        assert wrapper.release_support == "bundled"
        assert wrapper.license == "MIT"
        assert wrapper.homepage.startswith("https://github.com/projectdiscovery/")
        assert effective[name]["release_support"] == "bundled"


def test_manifest_exactly_covers_certified_bundled_tools() -> None:
    manifest = json.loads((ROOT / "installer" / "tools-manifest.json").read_text(encoding="utf-8"))
    provided = {alias for entry in manifest["tools"] for alias in entry["provides"]}
    assert provided == CERTIFIED
    assert len(manifest["tools"]) == len(CERTIFIED)
    for entry in manifest["tools"]:
        assert entry["url"].startswith("https://")
        assert len(entry["sha256"]) == 64
        assert entry["license"]
        assert entry["redistribution_review"]
        assert entry["probe"]
