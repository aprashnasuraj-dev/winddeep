"""Release-surface regression tests for the certified Windows build."""
from __future__ import annotations

import json
from pathlib import Path

from app.engine.tool_wrapper import ToolWrapperFactory
from app.modules.test_packs import PACK_COUNTS, TOTAL_TESTS, list_tests

ROOT = Path(__file__).resolve().parents[1]


def test_release_test_catalog_is_exactly_160() -> None:
    assert TOTAL_TESTS == 160
    assert PACK_COUNTS == {
        "browser_fidelity": 20,
        "human_multistage": 25,
        "auth_session": 35,
        "idor_bola_mass_assignment": 20,
        "business_logic": 20,
        "mobile_deep_dive": 20,
        "ai_automation": 10,
        "wild_cards": 10,
    }
    assert len(list_tests()) == 160


def test_release_registry_is_scope_bound_and_manifest_complete() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    assert set(classes) == {"subfinder", "httpx", "nuclei"}
    assert all(cls.requires_scope for cls in classes.values())
    manifest = json.loads((ROOT / "installer" / "tools-manifest.json").read_text(encoding="utf-8"))
    provided = {alias for entry in manifest["tools"] for alias in entry["provides"]}
    assert provided == set(classes)
    assert all(len(entry["sha256"]) == 64 for entry in manifest["tools"])
    assert all(entry["url"].startswith("https://") for entry in manifest["tools"])


def test_dashboard_is_external_script_csp_compatible() -> None:
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert len(html) > 1000
    assert '<script src="/static/app.js"></script>' in html
    assert "<script>" not in html
    for section in ("targets", "scans", "testpacks", "findings", "reports", "tools", "settings"):
        assert f'id="{section}"' in html
