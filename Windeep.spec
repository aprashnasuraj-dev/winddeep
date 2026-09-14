# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for the Windeep Windows executable."""

from pathlib import Path

ROOT = Path(SPEC).resolve().parent

analysis = Analysis(
    [str(ROOT / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "VERSION"), "."),
        (str(ROOT / "LICENSE"), "."),
    ],
    hiddenimports=["app.server", "flask"],
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
    analysis.binaries,
    analysis.datas,
    [],
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
