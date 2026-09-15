"""Build the Windeep v2 Windows offline kit from an already-built dist tree."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools.release_metadata import apply_release_metadata

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PORTABLE = DIST / "Windeep"
INSTALLER = DIST / "Windeep-Setup.exe"
OUTPUT = DIST / "Windeep-v2-Offline-Kit.zip"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integration_inventory() -> dict[str, object]:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    effective = apply_release_metadata(classes, ROOT / "tools_config.json")
    tools: list[dict[str, object]] = []
    for name, cls in sorted(classes.items()):
        definition = effective.get(name, {})
        tools.append(
            {
                "name": name,
                "category": cls.category,
                "adapter": getattr(cls, "adapter_kind", "process"),
                "binary": cls.binary,
                "release_support": getattr(cls, "release_support", definition.get("release_support", "runtime")),
                "requires_scope": bool(cls.requires_scope),
                "target_types": list(getattr(cls, "target_types", ())),
                "scan_default": bool(getattr(cls, "scan_default", True)),
                "required_env": list(getattr(cls, "required_env", ())),
                "description": cls.description,
            }
        )
    if len(tools) != 137 or len({str(row["name"]) for row in tools}) != 137:
        raise RuntimeError(f"offline inventory requires exactly 137 unique integrations, found {len(tools)}")
    if not all(bool(row["requires_scope"]) for row in tools):
        raise RuntimeError("offline inventory contains a tool that is not scope-bound")
    return {
        "schema_version": 1,
        "product": "Windeep",
        "edition": "v2 Windows Offline Kit",
        "integration_count": len(tools),
        "tools": tools,
    }


def main() -> int:
    if not PORTABLE.is_dir():
        raise FileNotFoundError(f"portable build is missing: {PORTABLE}")
    if not INSTALLER.is_file():
        raise FileNotFoundError(f"installer is missing: {INSTALLER}")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    inventory = integration_inventory()

    with tempfile.TemporaryDirectory(prefix="windeep-v2-kit-") as tmp:
        stage = Path(tmp) / f"Windeep-v{version}-Offline-Kit"
        stage.mkdir(parents=True)
        shutil.copytree(PORTABLE, stage / "Windeep", dirs_exist_ok=True)
        shutil.copy2(INSTALLER, stage / "Windeep-Setup.exe")
        shutil.copy2(ROOT / "LICENSE", stage / "LICENSE")
        (stage / "integration-inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        readme = f"""Windeep v{version} Windows Offline Kit
=====================================

Contents
- Windeep-Setup.exe: per-user Windows installer.
- Windeep/: portable application tree.
- integration-inventory.json: all 137 UI/engine integrations and their runtime requirements.

Offline core
The application, embedded Python 3.11, Playwright Chromium runtime, dashboard,
engine, all eight tool catalog files, and the separately certified portable
binary payloads are included in this kit.

137 integrations
Every catalog integration is present in the Windows UI/engine. Integrations
that depend on third-party executables, WSL, authenticated APIs, services,
licensed software, another host OS, or a physical/mobile device still require
that prerequisite before execution. Windeep reports those requirements in the
Tool Matrix instead of pretending the dependency is bundled.

Safety
Execution remains bound to explicit scope, signed local consent, bounded rates,
local authentication, and encrypted-at-rest persistence. Plaintext report
exports are generated only through the authenticated local report workflow.
"""
        (stage / "README-OFFLINE.txt").write_text(readme, encoding="utf-8")
        hashes = {
            "Windeep-Setup.exe": sha256(stage / "Windeep-Setup.exe"),
            "Windeep/Windeep.exe": sha256(stage / "Windeep" / "Windeep.exe"),
            "integration-inventory.json": sha256(stage / "integration-inventory.json"),
        }
        (stage / "KIT-SHA256.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        if OUTPUT.exists():
            OUTPUT.unlink()
        with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(stage.parent).as_posix())
    print(f"Built {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
