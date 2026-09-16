"""Release-audit dispatcher.

Phases A/B/D/E/F execute the byte-identical legacy auditor. V3 executes the
v3.0.0 tester-first/all-findings release checks.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path


def _phase(argv: list[str]) -> str:
    for index, value in enumerate(argv):
        if value == "--phase" and index + 1 < len(argv):
            return argv[index + 1].strip().upper()
        if value.startswith("--phase="):
            return value.split("=", 1)[1].strip().upper()
    return ""


def main() -> int:
    if _phase(sys.argv[1:]) == "V3":
        from scripts.audit.release_audit_v3 import main as v3_main
        return int(v3_main())
    legacy = Path(__file__).with_name("release_audit_legacy.py")
    runpy.run_path(str(legacy), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
