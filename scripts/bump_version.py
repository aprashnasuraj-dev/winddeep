"""Validate and update the repository VERSION file."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def set_version(version: str, root: Path) -> None:
    """Write a validated semantic version to VERSION."""
    if not SEMVER.fullmatch(version):
        raise ValueError(f"Invalid semantic version: {version}")
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")


def main() -> int:
    """CLI entry point for version updates."""
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    set_version(args.version, args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
