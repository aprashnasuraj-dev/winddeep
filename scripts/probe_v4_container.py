"""Probe every Windeep v4 tool that declares the shared OCI image.

This script is deliberately stdlib-only so the container CI gate can run it
before installing the Python application.  It validates the config-to-image
contract rather than maintaining a second hand-written probe list.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise SystemExit(f"{path}: tools must be an object")
    return tools


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("app/tools/config/v4_runtime.json"))
    parser.add_argument("--image", default="winddeep/tools:v3")
    parser.add_argument("--runtime", default="docker")
    args = parser.parse_args()

    failures: list[str] = []
    declared = 0
    for name, raw in sorted(_load(args.config).items()):
        if not isinstance(raw, dict) or str(raw.get("container_image") or "") != args.image:
            continue
        declared += 1
        command = str(raw.get("container_command") or raw.get("execution_name") or name)
        probe = raw.get("probe") or ["--help"]
        if not isinstance(probe, list) or not all(isinstance(item, str) for item in probe):
            failures.append(f"{name}: invalid probe declaration")
            continue
        argv = [args.runtime, "run", "--rm", args.image, command, *probe]
        try:
            completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            failures.append(f"{name}: timeout")
            continue
        except OSError as exc:
            failures.append(f"{name}: {exc}")
            continue
        output = (completed.stdout or "").strip()
        print(f"[{name}] command={command} rc={completed.returncode}")
        if output:
            print("\n".join(output.splitlines()[:12]))
        # 0/1/2 are accepted liveness exits for help/version contracts.
        if completed.returncode not in {0, 1, 2}:
            failures.append(f"{name}: rc={completed.returncode}")
        elif not output:
            failures.append(f"{name}: empty liveness output")

    if declared == 0:
        raise SystemExit("no shared-container routes were declared")
    if failures:
        raise SystemExit("container route failures:\n- " + "\n- ".join(failures))
    print(f"validated {declared} shared-container routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
