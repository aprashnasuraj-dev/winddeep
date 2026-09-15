"""Windeep release-audit dispatcher.

A/B/D/E/F remain byte-for-byte in release_audit_legacy.py. V3 is additive.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path


def _phase() -> str | None:
    try:
        index = sys.argv.index("--phase")
    except ValueError:
        return None
    return sys.argv[index + 1] if index + 1 < len(sys.argv) else None


if __name__ == "__main__":
    if _phase() == "V3":
        from scripts.audit.v3_release_audit import main
        raise SystemExit(main())
    runpy.run_path(str(Path(__file__).with_name("release_audit_legacy.py")), run_name="__main__")
