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
    (str(ROOT / "requirements-capture.txt"), "."),
]
# The dedicated Python 3.12 capture process executes app/capture/standalone.py
# outside the PyInstaller interpreter. Ship the reviewed production app source
# tree as data so that process imports the exact same crypto/database/capture
# modules as the desktop executable, rather than resolving anything ambient.
for source, target in [
    (ROOT / "app", "app"),
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
    excludes=["mitmproxy"],
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
    contents_directory=".",
)
collect = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=True,
    name="Windeep",
)
