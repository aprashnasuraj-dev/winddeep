"""Release-support metadata overlay for generated tool-wrapper classes.

Execution behavior remains in ToolWrapperFactory. This module only carries the
Windows-release classification used by the UI, installer audit, and runtime
gate so unsupported/deprecated integrations cannot be mistaken for bundled
working tools.
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
        includes = raw.get("includes", [])
        if not isinstance(includes, list):
            raise ValueError(f"includes must be a list: {path}")
        for include in includes:
            child = (include_root / str(include)).resolve()
            for name, definition in load(child).items():
                if name in output:
                    raise ValueError(f"duplicate tool definition: {name}")
                output[name] = definition
        visited.remove(path)
        return output

    return load(root_config)


def apply_release_metadata(classes: Mapping[str, type], config_path: str | Path) -> dict[str, dict[str, Any]]:
    """Overlay reviewed release fields onto dynamic wrapper classes and return definitions."""
    definitions = load_definitions(config_path)
    if set(classes) != set(definitions):
        missing = sorted(set(definitions) - set(classes))
        extra = sorted(set(classes) - set(definitions))
        raise ValueError(f"wrapper/definition mismatch missing={missing} extra={extra}")
    for name, cls in classes.items():
        definition = definitions[name]
        setattr(cls, "release_support", str(definition.get("release_support") or "unreviewed"))
        setattr(cls, "unsupported_reason", str(definition.get("unsupported_reason") or ""))
        setattr(cls, "replacement", str(definition.get("replacement") or ""))
        setattr(cls, "homepage", str(definition.get("homepage") or ""))
        setattr(cls, "license", str(definition.get("license") or ""))
    return definitions
