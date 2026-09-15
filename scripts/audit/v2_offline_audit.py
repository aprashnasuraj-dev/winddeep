"""Fail-closed structural audit for the Windeep v2 Windows offline kit."""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import PurePosixPath

REQUIRED_CATALOGS = {
    "recon_passive.json",
    "recon_active.json",
    "web_vulns.json",
    "mobile.json",
    "web3.json",
    "secrets.json",
    "network.json",
    "utilities.json",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path")
    args = parser.parse_args()

    with zipfile.ZipFile(args.zip_path) as archive:
        names = set(archive.namelist())
        roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
        if len(roots) != 1:
            raise RuntimeError(f"offline kit must have one top-level directory, found {sorted(roots)}")
        root = next(iter(roots))

        def require(relative: str) -> None:
            path = f"{root}/{relative}"
            if path not in names:
                raise RuntimeError(f"offline kit missing required file: {path}")

        require("Windeep-Setup.exe")
        require("Windeep/Windeep.exe")
        require("Windeep/VERSION")
        require("Windeep/tools_config.json")
        require("Windeep/app/static/index.html")
        require("Windeep/app/static/app.js")
        require("integration-inventory.json")
        require("README-OFFLINE.txt")
        require("KIT-SHA256.json")

        catalog_prefix = f"{root}/Windeep/app/tools/config/"
        catalog_names = {
            PurePosixPath(name).name
            for name in names
            if name.startswith(catalog_prefix) and name.endswith(".json")
        }
        missing_catalogs = REQUIRED_CATALOGS.difference(catalog_names)
        if missing_catalogs:
            raise RuntimeError(f"offline kit missing catalog files: {sorted(missing_catalogs)}")

        if not any(name.startswith(f"{root}/Windeep/runtime/python/") and name.lower().endswith("python.exe") for name in names):
            raise RuntimeError("offline kit is missing embedded Python 3.11 executable")
        if not any(name.startswith(f"{root}/Windeep/runtime/playwright-browsers/") for name in names):
            raise RuntimeError("offline kit is missing Playwright browser runtime")

        inventory = json.loads(archive.read(f"{root}/integration-inventory.json"))
        tools = inventory.get("tools") or []
        if inventory.get("integration_count") != 137 or len(tools) != 137:
            raise RuntimeError(f"integration inventory is not exactly 137 entries: declared={inventory.get('integration_count')} actual={len(tools)}")
        names_seen = {str(item.get("name")) for item in tools}
        if len(names_seen) != 137:
            raise RuntimeError("integration inventory contains duplicate names")
        if not all(item.get("requires_scope") is True for item in tools):
            raise RuntimeError("one or more offline integrations are not scope-bound")
        if not all(item.get("target_types") for item in tools):
            raise RuntimeError("one or more offline integrations lack target compatibility metadata")

        root_registry = json.loads(archive.read(f"{root}/Windeep/tools_config.json"))
        if root_registry.get("tool_count") != 137 or root_registry.get("active_tool_count") != 137:
            raise RuntimeError("packaged root registry does not declare 137 active integrations")

        manifest = json.loads(archive.read(f"{root}/Windeep/installer/tools-manifest.json")) if f"{root}/Windeep/installer/tools-manifest.json" in names else None
        # PyInstaller currently embeds the staged tools themselves, while the repository
        # manifest is audited before packaging.  If the manifest is shipped, validate it;
        # otherwise require at least the six known certified binary payloads to exist.
        if manifest is not None:
            provided = {alias for item in manifest.get("tools", []) for alias in item.get("provides", [])}
            if len(provided) < 6:
                raise RuntimeError("packaged tools manifest exposes fewer than six certified aliases")
        tool_files = [name for name in names if name.startswith(f"{root}/Windeep/tools/") and not name.endswith("/")]
        if len(tool_files) < 6:
            raise RuntimeError(f"offline kit contains too few staged certified tool files: {len(tool_files)}")

    print("Windeep v2 offline kit audit: PASS (137 integrations, UI, runtime, setup and portable payload present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
