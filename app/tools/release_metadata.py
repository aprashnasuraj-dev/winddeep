"""Release-support metadata for the complete Windeep tool catalog.

The root registry deliberately separates ``catalog_includes`` (all documented
integrations) from ``includes`` (the small, executable Windows release set).
This module evaluates the complete catalog for release auditing while allowing
runtime classes to be a certified subset of that catalog.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def load_definitions(config_path: str | Path) -> dict[str, dict[str, Any]]:
    root_config = Path(config_path).resolve()
    include_root = root_config.parent
    visited: set[Path] = set()

    def load(path: Path) -> dict[str, dict[str, Any]]:
        path = path.resolve()
        if path in visited:
            raise ValueError(f"cyclic tool config include: {path}")
        if not path.is_relative_to(include_root):
            raise ValueError(f"tool config include escapes registry root: {path}")
        visited.add(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError(f"tool config must be an object: {path}")
        output: dict[str, dict[str, Any]] = {}
        tools = raw.get("tools", {})
        if not isinstance(tools, Mapping):
            raise ValueError(f"tools must be an object: {path}")
        for name, definition in tools.items():
            if not isinstance(definition, Mapping):
                raise ValueError(f"tool definition must be an object: {name}")
            output[str(name)] = dict(definition)

        # Only the root has a catalog/runtime split. Child registries retain the
        # ordinary includes key so nested modular registries remain supported.
        includes_key = "catalog_includes" if path == root_config and "catalog_includes" in raw else "includes"
        includes = raw.get(includes_key, [])
        if not isinstance(includes, list) or not all(isinstance(item, str) for item in includes):
            raise ValueError(f"{includes_key} must be a list of paths: {path}")
        for include in includes:
            child = (include_root / include).resolve()
            for name, definition in load(child).items():
                if name in output:
                    raise ValueError(f"duplicate tool definition: {name}")
                output[name] = definition
        visited.remove(path)
        return output

    return load(root_config)


def load_release_policy(config_path: str | Path) -> dict[str, Any]:
    root = Path(config_path).resolve().parent
    policy_path = root / "app" / "tools" / "release-policy.json"
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("release policy must be a JSON object")
    default = raw.get("default")
    tools = raw.get("tools")
    if not isinstance(default, Mapping) or not isinstance(tools, Mapping):
        raise ValueError("release policy requires default and tools objects")
    return {
        "default": dict(default),
        "tools": {str(k): dict(v) for k, v in tools.items() if isinstance(v, Mapping)},
    }


def effective_definitions(config_path: str | Path) -> dict[str, dict[str, Any]]:
    """Return all catalog definitions with the authoritative release policy overlaid."""
    definitions = load_definitions(config_path)
    policy = load_release_policy(config_path)
    default = policy["default"]
    overrides = policy["tools"]
    unknown = sorted(set(overrides).difference(definitions))
    if unknown:
        raise ValueError(f"release policy references unknown tools: {unknown}")
    effective: dict[str, dict[str, Any]] = {}
    for name, definition in definitions.items():
        merged = dict(definition)
        merged.update(default)
        merged.update(overrides.get(name, {}))
        effective[name] = merged
    return effective


def apply_release_metadata(classes: Mapping[str, type], config_path: str | Path) -> dict[str, dict[str, Any]]:
    """Annotate executable wrapper classes from the complete catalog policy.

    Runtime classes are intentionally a subset of the 137-entry catalog. A
    class unknown to the catalog is an error; catalog-only integrations remain
    disabled because they never receive a runtime wrapper class.
    """
    definitions = effective_definitions(config_path)
    unknown_classes = sorted(set(classes).difference(definitions))
    if unknown_classes:
        raise ValueError(f"runtime wrapper(s) missing from catalog: {unknown_classes}")
    for name, cls in classes.items():
        definition = definitions[name]
        setattr(cls, "release_support", str(definition.get("release_support") or "unsupported"))
        setattr(cls, "unsupported_reason", str(definition.get("unsupported_reason") or ""))
        setattr(cls, "replacement", str(definition.get("replacement") or ""))
        setattr(cls, "homepage", str(definition.get("homepage") or ""))
        setattr(cls, "license", str(definition.get("license") or ""))
    return definitions
