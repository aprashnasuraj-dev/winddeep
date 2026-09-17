"""Aggregate Windeep v4 doctor reports into a release-grade route verdict.

A tool is runtime-proven when at least one matrix report resolves it to a
non-unavailable tier and its liveness probe passes (or no probe is declared).
Host/credential-gated integrations, catalog entries explicitly marked
unsupported, and narrowly documented portability/package exceptions are
reported as contract-only rather than being misrepresented as runtime-proven.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

# Running this file directly makes Python put ``scripts/`` on sys.path rather
# than the repository root. Add the root explicitly so repo-local ``app``
# imports work in CI and for direct operator invocation without PYTHONPATH.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_fallbacks, builtin_integrations
from app.tools.release_metadata import effective_definitions

RELEASE_CONTRACTS = ROOT / "app" / "tools" / "config" / "v4_release_contracts.json"
ALLOWED_CONTRACT_KINDS = {
    "bundle-required",
    "provisioning-route-pending",
    "upstream-packaging",
}


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema") != "windeep.doctor.v4":
        raise SystemExit(f"{path}: unexpected doctor schema {data.get('schema')!r}")
    rows = data.get("tools")
    if not isinstance(rows, list):
        raise SystemExit(f"{path}: doctor tools must be a list")
    return data


def _load_release_contracts(expected: set[str]) -> dict[str, dict[str, str]]:
    if not RELEASE_CONTRACTS.is_file():
        return {}
    raw = json.loads(RELEASE_CONTRACTS.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1 or not isinstance(raw.get("contract_only"), dict):
        raise SystemExit(f"{RELEASE_CONTRACTS}: invalid v4 release-contract schema")
    contracts: dict[str, dict[str, str]] = {}
    for name, item in raw["contract_only"].items():
        if name not in expected:
            raise SystemExit(f"{RELEASE_CONTRACTS}: unknown catalog tool {name!r}")
        if not isinstance(item, dict):
            raise SystemExit(f"{RELEASE_CONTRACTS}: contract for {name} must be an object")
        kind = str(item.get("kind") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if kind not in ALLOWED_CONTRACT_KINDS:
            raise SystemExit(f"{RELEASE_CONTRACTS}: invalid contract kind for {name}: {kind!r}")
        if len(reason) < 20:
            raise SystemExit(f"{RELEASE_CONTRACTS}: contract for {name} requires a substantive reason")
        contracts[str(name)] = {"kind": kind, "reason": reason}
    return contracts


def _healthy(row: dict[str, Any]) -> bool:
    if row.get("tier") == "unavailable":
        return False
    status = str((row.get("probe") or {}).get("status") or "").lower()
    return status in {"pass", "resolved"}


def _contract_only_reason(
    cls: type[Any],
    definition: Mapping[str, Any],
    declared_contract: Mapping[str, str] | None,
) -> str | None:
    release_support = str(definition.get("release_support") or "").strip().lower()
    unsupported_reason = str(definition.get("unsupported_reason") or "").strip()
    if release_support == "unsupported" and unsupported_reason:
        return "catalog-unsupported:" + unsupported_reason

    if declared_contract:
        return f"{declared_contract['kind']}:{declared_contract['reason']}"

    requires_host = str(getattr(cls, "requires_host", "") or "").strip().lower()
    preference = {str(item) for item in (getattr(cls, "execution_preference", ()) or ())}
    if requires_host and "remote_worker" in preference:
        return f"remote-host:{requires_host}"

    adapter = str(getattr(cls, "builtin_fallback", "") or getattr(cls, "execution_name", "") or getattr(cls, "tool_name", ""))
    required = {
        *getattr(cls, "required_env", ()),
        *builtin_integrations.required_env(adapter),
        *builtin_fallbacks.required_env(adapter),
    }
    if required:
        return "credentials:" + ",".join(sorted(str(item) for item in required))
    return None


def validate(registry: Path, reports: list[Path]) -> dict[str, Any]:
    classes = ToolWrapperFactory(registry).load()
    definitions = effective_definitions(registry)
    expected = set(classes)
    contracts = _load_release_contracts(expected)
    if not reports:
        raise SystemExit("no doctor reports supplied")

    # Path sorting makes merged evidence independent of shell/filesystem ordering.
    ordered_reports = sorted((path.resolve() for path in reports), key=lambda path: path.as_posix().casefold())
    proven: dict[str, list[dict[str, str]]] = {name: [] for name in expected}
    report_summaries: list[dict[str, Any]] = []

    for path in ordered_reports:
        data = _load(path)
        rows = data["tools"]
        names = [str(row.get("tool") or "") for row in rows]
        if len(names) != len(set(names)):
            raise SystemExit(f"{path}: duplicate tool rows")
        found = set(names)
        if found != expected:
            missing = sorted(expected - found)
            extra = sorted(found - expected)
            raise SystemExit(f"{path}: catalog mismatch missing={missing} extra={extra}")
        healthy_count = 0
        for row in sorted(rows, key=lambda item: str(item.get("tool") or "").casefold()):
            name = str(row["tool"])
            if _healthy(row):
                healthy_count += 1
                proven[name].append(
                    {
                        "report": path.name,
                        "tier": str(row.get("tier") or ""),
                        "backend": str(row.get("backend") or ""),
                        "probe": str((row.get("probe") or {}).get("status") or ""),
                    }
                )
        report_summaries.append(
            {
                "report": path.name,
                "catalog": int(data.get("catalog", 0)),
                "runnable": int(data.get("runnable", 0)),
                "healthy": healthy_count,
                "unavailable": int(data.get("unavailable", 0)),
                "tiers": data.get("tiers", {}),
            }
        )

    runtime_proven = sorted(name for name, routes in proven.items() if routes)
    contract_only: dict[str, str] = {}
    unproven: list[str] = []
    for name in sorted(expected):
        if proven[name]:
            continue
        reason = _contract_only_reason(classes[name], definitions[name], contracts.get(name))
        if reason:
            contract_only[name] = reason
        else:
            unproven.append(name)

    stale_contracts = sorted(name for name in contracts if proven.get(name))
    summary = {
        "schema": "windeep.v4.runtime-matrix.v1",
        "catalog": len(expected),
        "runtime_proven": len(runtime_proven),
        "contract_only": len(contract_only),
        "unproven": len(unproven),
        "reports": report_summaries,
        "contract_only_tools": contract_only,
        "declared_release_contracts": contracts,
        "stale_release_contracts": stale_contracts,
        "unproven_tools": unproven,
        "routes": {name: proven[name] for name in runtime_proven},
    }
    if unproven:
        print(json.dumps(summary, indent=2, sort_keys=True))
        raise SystemExit("v4 runtime matrix has unproven tools: " + ", ".join(unproven))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--registry", type=Path, default=Path("tools_config.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    summary = validate(args.registry.resolve(), args.reports)
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
