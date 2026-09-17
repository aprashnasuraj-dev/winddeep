"""Validate one post-heal Windeep v4 doctor report.

A host report is clean when its catalog/accounting invariants hold and every
route that resolves on that host has a passing (or intentionally undeclared)
liveness probe. Host-specific unavailability is evaluated by the matrix-union
gate rather than being misclassified as a per-host heal failure.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_HEALTHY_PROBES = {"pass", "resolved"}


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema") != "windeep.doctor.v4":
        raise SystemExit(f"{path}: unexpected doctor schema {data.get('schema')!r}")
    tools = data.get("tools")
    if not isinstance(tools, list):
        raise SystemExit(f"{path}: tools must be a list")
    return data


def validate(report: dict[str, Any], *, source: Path) -> dict[str, Any]:
    tools = report["tools"]
    catalog = int(report.get("catalog", -1))
    runnable = int(report.get("runnable", -1))
    unavailable = int(report.get("unavailable", -1))
    names = [str(row.get("tool") or "") for row in tools]
    if catalog != len(tools):
        raise SystemExit(f"{source}: catalog={catalog} but tools={len(tools)}")
    if len(names) != len(set(names)):
        raise SystemExit(f"{source}: duplicate tool rows")
    if runnable + unavailable != catalog:
        raise SystemExit(f"{source}: runnable + unavailable does not equal catalog")
    tiers = report.get("tiers") or {}
    if not isinstance(tiers, dict) or sum(int(value) for value in tiers.values()) != catalog:
        raise SystemExit(f"{source}: tier counts do not equal catalog")

    bad_probes: list[str] = []
    for row in tools:
        if row.get("tier") == "unavailable":
            continue
        status = str((row.get("probe") or {}).get("status") or "").lower()
        if status not in _HEALTHY_PROBES:
            bad_probes.append(f"{row.get('tool')}:{status or 'missing'}")
    if bad_probes:
        raise SystemExit(f"{source}: resolved routes with failed liveness: " + ", ".join(sorted(bad_probes)))

    return {
        "catalog": catalog,
        "runnable": runnable,
        "unavailable": unavailable,
        "clean_resolved_probes": runnable,
    }


def compare_heal(healed: dict[str, Any], rechecked: dict[str, Any], *, healed_path: Path, rechecked_path: Path) -> None:
    if int(rechecked.get("unavailable", -1)) > int(healed.get("unavailable", -1)):
        raise SystemExit(
            f"{rechecked_path}: recheck regressed unavailable count "
            f"{healed.get('unavailable')} -> {rechecked.get('unavailable')}"
        )
    before = {str(row.get("tool")): row for row in healed.get("tools", [])}
    after = {str(row.get("tool")): row for row in rechecked.get("tools", [])}
    regressed = sorted(
        name
        for name, row in before.items()
        if row.get("tier") != "unavailable" and after.get(name, {}).get("tier") == "unavailable"
    )
    if regressed:
        raise SystemExit(
            f"{rechecked_path}: routes resolved by heal became unavailable on immediate recheck: "
            + ", ".join(regressed)
        )
    if set(before) != set(after):
        raise SystemExit(f"{rechecked_path}: heal/recheck catalog membership differs from {healed_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--healed-from", type=Path)
    args = parser.parse_args()

    report_path = args.report.resolve()
    report = _load(report_path)
    summary = validate(report, source=report_path)
    if args.healed_from:
        healed_path = args.healed_from.resolve()
        healed = _load(healed_path)
        validate(healed, source=healed_path)
        compare_heal(healed, report, healed_path=healed_path, rechecked_path=report_path)
        summary["healed_from"] = healed_path.name
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
