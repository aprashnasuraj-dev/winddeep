#!/usr/bin/env python3
"""Safe environment preflight; canonical evidence packaging lives in rapyd_handoff.py."""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ("git",)
OPTIONAL = ("gh", "rg", "docker", "node", "java", "terraform")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["doctor"])
    p.add_argument("--check", action="store_true",
                   help="also execute the existing private-evidence and scope gate")
    args = p.parse_args()
    tools = {name: shutil.which(name) is not None for name in REQUIRED + OPTIONAL}
    result = {
        "python": sys.version.split()[0],
        "python_compatible": sys.version_info >= (3, 11),
        "tool_available": tools,
        "canonical_bundle_helper": "scripts/audit/rapyd_handoff.py",
        "private_evidence_only": True,
    }
    if args.check:
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts/audit/rapyd_handoff.py"), "repo-check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        result["repository_gate_passed"] = run.returncode == 0
        result["repository_gate_message"] = (run.stdout if run.returncode == 0
                                             else run.stderr).strip()
    result["ready"] = bool(result["python_compatible"] and
                           all(tools[name] for name in REQUIRED) and
                           (not args.check or result["repository_gate_passed"]))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["ready"] else 2

if __name__ == "__main__":
    raise SystemExit(main())
