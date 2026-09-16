"""Generate/check Windeep v4 catalog metadata from executable route contracts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_integrations
from app.tools.release_metadata import effective_definitions

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools_config.json"


def compute(registry: Path = REGISTRY) -> dict[str, int]:
    classes = ToolWrapperFactory(registry).load()
    effective = effective_definitions(registry)
    route_covered = 0
    aliases = 0
    provisioned = 0
    containers = 0
    builtin_routes = 0
    remote_host = 0
    for name, cls in classes.items():
        release_support = str(effective[name].get("release_support") or "")
        has_alias = bool(getattr(cls, "alias_to", ""))
        has_provision = bool(getattr(cls, "provision", None))
        has_container = bool(getattr(cls, "container_image", ""))
        has_builtin = bool(getattr(cls, "builtin_fallback", "") or builtin_integrations.supports(name))
        has_remote = bool(getattr(cls, "requires_host", ""))
        aliases += int(has_alias)
        provisioned += int(has_provision)
        containers += int(has_container)
        builtin_routes += int(has_builtin)
        remote_host += int(has_remote)
        if has_alias or has_provision or has_container or has_builtin or has_remote or release_support == "bundled":
            route_covered += 1
    return {
        "registered_tool_count": len(classes),
        "active_tool_count": route_covered,
        "alias_route_count": aliases,
        "provision_route_count": provisioned,
        "container_route_count": containers,
        "builtin_route_count": builtin_routes,
        "host_specific_route_count": remote_host,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    args = parser.parse_args()
    registry = args.registry.resolve()
    current = json.loads(registry.read_text(encoding="utf-8"))
    generated = compute(registry)
    expected = {
        "tool_count": generated["registered_tool_count"],
        "registered_tool_count": generated["registered_tool_count"],
        "active_tool_count": generated["active_tool_count"],
    }
    if args.check:
        failures = [f"{key}: expected {value!r}, found {current.get(key)!r}" for key, value in expected.items() if current.get(key) != value]
        if failures:
            raise SystemExit("v4 generated metadata drift:\n- " + "\n- ".join(failures))
        print(json.dumps({"authoritative": expected, "route_diagnostics": generated}, indent=2, sort_keys=True))
        return 0
    current.update(expected)
    registry.write_text(json.dumps(current, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(json.dumps({"authoritative": expected, "route_diagnostics": generated}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
