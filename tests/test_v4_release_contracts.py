from __future__ import annotations

import json
from pathlib import Path

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_fallbacks
from app.tools.release_metadata import effective_definitions

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools_config.json"
CONTRACTS = ROOT / "app" / "tools" / "config" / "v4_release_contracts.json"
ALLOWED_KINDS = {"bundle-required", "provisioning-route-pending", "upstream-packaging"}


def test_release_contract_manifest_is_narrow_and_catalog_bound() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    raw = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    assert raw["schema_version"] == 1
    contracts = raw["contract_only"]
    assert contracts
    assert set(contracts) <= set(classes)
    for name, item in contracts.items():
        assert item["kind"] in ALLOWED_KINDS, name
        assert len(str(item["reason"]).strip()) >= 20, name


def test_catalog_unsupported_entries_explain_why() -> None:
    definitions = effective_definitions(REGISTRY)
    for name, definition in definitions.items():
        if str(definition.get("release_support") or "").lower() == "unsupported":
            assert str(definition.get("unsupported_reason") or "").strip(), name


def test_bundled_secret_scanners_have_working_builtin_fallback() -> None:
    classes = ToolWrapperFactory(REGISTRY).load()
    for name in ("gitleaks", "trufflehog"):
        assert classes[name].builtin_fallback == "repo_secret_scan"
        assert builtin_fallbacks.supports(classes[name].builtin_fallback)
        assert classes[name].runtime_strategy == "auto"
