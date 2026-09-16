"""Fail CI when release-critical v3 modules fall below their per-file coverage floor."""
from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def normalize(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def candidates(name: str) -> tuple[str, ...]:
    normalized = normalize(name)
    values = [normalized]
    # pytest-cov may emit paths relative to the measured source root. With
    # ``--cov=app`` that means ``v3/api.py`` instead of ``app/v3/api.py``.
    if normalized.startswith("app/"):
        values.append(normalized[len("app/"):])
    return tuple(dict.fromkeys(values))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage_xml", type=Path)
    parser.add_argument("modules", nargs="+")
    parser.add_argument("--minimum", type=float, default=90.0)
    args = parser.parse_args()

    root = ET.parse(args.coverage_xml).getroot()
    by_name: dict[str, float] = {}
    for node in root.findall(".//class"):
        filename = normalize(str(node.attrib.get("filename", "")))
        try:
            rate = float(node.attrib["line-rate"]) * 100.0
        except (KeyError, ValueError):
            continue
        by_name[filename] = rate

    failed = False
    for raw in args.modules:
        wanted = normalize(raw)
        acceptable = candidates(wanted)
        matches = [
            (name, rate)
            for name, rate in by_name.items()
            if any(name == value or name.endswith("/" + value) for value in acceptable)
        ]
        if not matches:
            print(f"[FAIL] {wanted}: absent from coverage XML")
            failed = True
            continue
        _name, rate = max(matches, key=lambda item: item[1])
        ok = rate + 1e-9 >= args.minimum
        print(f"[{'PASS' if ok else 'FAIL'}] {wanted}: {rate:.2f}% (minimum {args.minimum:.2f}%)")
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
