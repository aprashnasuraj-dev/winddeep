"""Generate/check Windeep v4 catalog metadata from executable route contracts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Keep direct script execution import-safe. ``python scripts/...`` otherwise
# puts only the scripts directory on sys.path, which breaks repository-local
# ``app`` imports in clean CI jobs.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools import builtin_integrations
from app.tools.release_metadata import effective_definitions

REGISTRY = ROOT / "tools_config.json"
README = ROOT / "README.md"
README_START = "<!-- v4-runtime-counts:start -->"
README_END = "<!-- v4-runtime-counts:end -->"


def compute(registry: Path = REGISTRY) -> dict[str, int]:
    classes = ToolWrapperFactory(registry).load()
    effective = effective_definitions(registry)
    route_covered = 0
    aliases = 0
    provisioned = 0
    containers = 0
    builtin_routes = 0
    remote_host = 0
    excluded_dead = 0
    for name, cls in classes.items():
        release_support = str(effective[name].get("release_support") or "")
        catalog_support = str(effective[name].get("catalog_release_support") or "")
        launch_excluded = release_support in {"deprecated", "legacy"} or (
            release_support == "unsupported" and catalog_support == "unsupported"
        )
        if launch_excluded:
            excluded_dead += 1
            continue
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
        "launch_excluded_count": excluded_dead,
    }


def _readme_block(generated: dict[str, int]) -> str:
    return "\n".join(
        [
            README_START,
            f"- **{generated['registered_tool_count']} registered integrations** are retained for historical scan/template compatibility.",
            f"- **{generated['active_tool_count']} active v4.1 launch integrations** have a supported route, maintained fallback, host contract, or explicit external-service workflow.",
            f"- **{generated['launch_excluded_count']} dead/deprecated/catalog-only integrations** are excluded from the active launch surface instead of appearing as runnable tools.",
            README_END,
        ]
    )


def _replace_readme_block(text: str, block: str) -> str:
    start = text.find(README_START)
    end = text.find(README_END)
    if start >= 0 and end >= start:
        end += len(README_END)
        return text[:start] + block + text[end:]

    anchor = "## Catalog counts"
    anchor_at = text.find(anchor)
    if anchor_at < 0:
        raise ValueError("README is missing the '## Catalog counts' section")
    first = text.find("- **", anchor_at)
    if first < 0:
        raise ValueError("README catalog-count bullets are missing")
    second = text.find("\n- **", first)
    if second < 0:
        raise ValueError("README route-covered count bullet is missing")
    second += 1
    second_end = text.find("\n", second)
    if second_end < 0:
        second_end = len(text)
    return text[:first] + block + text[second_end:]


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

    # README generation is authoritative only for the repository's canonical
    # registry. Custom registries used by tooling/tests should not rewrite docs.
    manage_readme = registry == REGISTRY.resolve()
    readme_block = _readme_block(generated)

    if args.check:
        failures = [
            f"{key}: expected {value!r}, found {current.get(key)!r}"
            for key, value in expected.items()
            if current.get(key) != value
        ]
        if manage_readme:
            readme_text = README.read_text(encoding="utf-8")
            start = readme_text.find(README_START)
            end = readme_text.find(README_END)
            actual_block = ""
            if start >= 0 and end >= start:
                actual_block = readme_text[start : end + len(README_END)]
            if actual_block != readme_block:
                failures.append("README v4 runtime count block does not match resolver-generated counts")
        if failures:
            raise SystemExit(
                "v4 generated metadata drift:\n- "
                + "\n- ".join(failures)
                + "\nRegenerate with: python scripts/generate_v4_metadata.py"
            )
        print(json.dumps({"authoritative": expected, "route_diagnostics": generated}, indent=2, sort_keys=True))
        return 0

    current.update(expected)
    registry.write_text(json.dumps(current, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if manage_readme:
        readme_text = README.read_text(encoding="utf-8")
        README.write_text(_replace_readme_block(readme_text, readme_block), encoding="utf-8")
    print(json.dumps({"authoritative": expected, "route_diagnostics": generated}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
