# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir specification for the self-contained Windows release."""
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPEC).resolve().parent

datas = [
    (str(ROOT / "VERSION"), "."),
    (str(ROOT / "LICENSE"), "."),
    (str(ROOT / "README.md"), "."),
    (str(ROOT / "tools_config.json"), "."),
]
for source, target in [
    (ROOT / "app" / "tools" / "config", "app/tools/config"),
    (ROOT / "app" / "data" / "migrations", "app/data/migrations"),
    (ROOT / "app" / "static", "app/static"),
    (ROOT / "tools", "tools"),
    (ROOT / "runtime", "runtime"),
]:
    if source.exists():
        datas.append((str(source), target))

analysis = Analysis(
    [str(ROOT / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=collect_submodules("app"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="Windeep",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
collect = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=True,
    name="Windeep",
)
