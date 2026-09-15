"""Release contract for P5 Web3 engines."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

WEB3_ENGINE_PINS: dict[str, str] = {
    "slither": "0.11.3",
    "mythril": "0.24.8",
    "aderyn": "0.3.2",
}


def validate_web3_catalog(wrapper_classes: Mapping[str, Any]) -> dict[str, Any]:
    required = ("slither", "mythril")
    result: dict[str, Any] = {"ok": True, "engines": {}}
    for name in required:
        if name not in wrapper_classes:
            raise KeyError(f"required Web3 engine missing from catalog: {name}")
        cls = wrapper_classes[name]
        category = str(getattr(cls, "category", ""))
        timeout = float(getattr(cls, "timeout", 0.0))
        requires_scope = bool(getattr(cls, "requires_scope", False))
        if category != "web3":
            raise ValueError(f"{name} must use web3 resource class")
        if timeout <= 0 or timeout > 900:
            raise ValueError(f"{name} timeout is outside reviewed bounds")
        if not requires_scope:
            raise ValueError(f"{name} must require explicit scope")
        result["engines"][name] = {
            "version_pin": WEB3_ENGINE_PINS[name],
            "resource_class": category,
            "timeout": timeout,
            "requires_scope": requires_scope,
        }
    return result


__all__ = ["WEB3_ENGINE_PINS", "validate_web3_catalog"]
