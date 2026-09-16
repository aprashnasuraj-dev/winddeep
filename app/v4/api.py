"""Windeep v4 resolver/readiness API.

This surface exposes runtime truth (tier/backend/readiness) and provides an
explicitly consented provisioning action. It does not silently install during
normal scan planning.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

from app.tools.provisioning import Provisioner, ProvisioningError


_TARGET_ALIASES = {"website": "url", "ip": "host", "cidr": "host", "repository": "repo", "source": "repo"}


def _target_type(value: str) -> str:
    raw = str(value or "").strip().lower()
    return _TARGET_ALIASES.get(raw, raw)


def _compatible(cls: type[Any], target_type: str | None) -> bool:
    if not target_type:
        return True
    normalized = _target_type(target_type)
    declared = tuple(str(item).lower() for item in getattr(cls, "target_types", ()) if str(item))
    if not declared:
        return True
    return normalized in declared or ("web" in declared and normalized in {"domain", "url", "host", "web"})


def register_v4_api(app: Flask, *, authenticated: Callable[[Callable[..., Any]], Callable[..., Any]], audit: Any) -> None:
    factory = app.extensions["windeep.tool_factory"]
    classes = factory.load()
    root = Path(os.getenv("WINDEEP_APP_ROOT", Path.cwd())).resolve()
    tools_dir = root / "tools"

    def descriptor(name: str, cls: type[Any], target_type: str | None = None) -> dict[str, Any]:
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: True, environment=os.environ)
        status = wrapper.runtime_status()
        compatible = _compatible(cls, target_type)
        missing_env = list(wrapper.missing_environment())
        ready = status["tier"] != "unavailable" and compatible
        try:
            options_schema = cls.input_schema.model_json_schema()
        except Exception:
            options_schema = {"type": "object", "properties": {}}
        if not compatible:
            blocked_reason = f"Not compatible with target type '{_target_type(target_type or '')}'"
        elif missing_env and status["tier"] == "unavailable":
            blocked_reason = "Missing configuration: " + ", ".join(missing_env)
        elif status["tier"] == "unavailable" and getattr(cls, "provision", None):
            blocked_reason = "Not installed yet; provision on demand or run 'winddeep doctor --heal'."
        elif status["tier"] == "unavailable" and getattr(cls, "requires_host", ""):
            blocked_reason = f"Requires {getattr(cls, 'requires_host')} host; configure a compatible WSL/remote worker."
        elif status["tier"] == "unavailable":
            blocked_reason = "No execution backend currently resolves this integration."
        else:
            blocked_reason = ""
        return {
            "name": name,
            "execution_name": getattr(cls, "execution_name", name),
            "alias_to": getattr(cls, "alias_to", "") or None,
            "served_by": getattr(cls, "execution_name", name) if getattr(cls, "alias_to", "") else None,
            "category": getattr(cls, "category", "uncategorized"),
            "description": getattr(cls, "description", ""),
            "runtime_strategy": getattr(cls, "runtime_strategy", "auto"),
            "execution_preference": list(getattr(cls, "execution_preference", ())),
            "adapter": status["backend"] or getattr(cls, "runtime_strategy", "auto"),
            "tier": status["tier"],
            "backend": status["backend"],
            "backend_chain": status["chain"],
            "ready": ready,
            "compatible": compatible,
            "blocked_reason": blocked_reason,
            "target_types": list(getattr(cls, "target_types", ())),
            "scan_default": bool(getattr(cls, "scan_default", True)),
            "missing_env": missing_env,
            "configured": not missing_env or status["tier"] == "remote",
            "provisionable": bool(getattr(cls, "provision", None)),
            "provision": dict(getattr(cls, "provision", {}) or {}),
            "container_image": getattr(cls, "container_image", "") or None,
            "builtin_fallback": getattr(cls, "builtin_fallback", "") or None,
            "requires_host": getattr(cls, "requires_host", "") or None,
            "probe": list(getattr(cls, "probe", ())),
            "options_schema": options_schema,
            "release_support": getattr(cls, "release_support", "resolver-managed"),
            "windows_certified": getattr(cls, "release_support", "") == "bundled",
        }

    @app.get("/api/v4/status")
    @authenticated
    def v4_status() -> Response:
        rows = [descriptor(name, cls) for name, cls in sorted(classes.items())]
        tiers: dict[str, int] = {}
        for row in rows:
            tiers[row["tier"]] = tiers.get(row["tier"], 0) + 1
        runnable = sum(1 for row in rows if row["tier"] != "unavailable")
        return jsonify({"version": "4.0.0", "catalog": len(rows), "runnable": runnable, "unavailable": len(rows) - runnable, "tiers": tiers})

    @app.get("/api/v4/tools")
    @authenticated
    def v4_tools() -> Response:
        target_type = request.args.get("target_type")
        rows = [descriptor(name, cls, target_type) for name, cls in sorted(classes.items())]
        return jsonify({
            "total": len(rows),
            "ready": sum(1 for row in rows if row["ready"]),
            "runnable": sum(1 for row in rows if row["tier"] != "unavailable"),
            "unavailable": sum(1 for row in rows if row["tier"] == "unavailable"),
            "tiers": {tier: sum(1 for row in rows if row["tier"] == tier) for tier in sorted({row["tier"] for row in rows})},
            "tools": rows,
        })

    @app.post("/api/v4/tools/<tool_name>/provision")
    @authenticated
    def v4_provision(tool_name: str) -> tuple[Response, int] | Response:
        cls = classes.get(tool_name)
        if cls is None:
            return jsonify({"error": "unknown tool"}), 404
        body = request.get_json(silent=True) or {}
        if body.get("consent") is not True:
            return jsonify({"error": "explicit provisioning consent is required"}), 403
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: True, environment=os.environ)
        if not getattr(cls, "provision", None):
            return jsonify({"error": "tool has no provisioning recipe", "runtime": wrapper.runtime_status()}), 409
        try:
            result = Provisioner(tools_dir, environment=os.environ).provision(wrapper, consent=True)
        except (ProvisioningError, OSError, PermissionError) as exc:
            audit.append("v4.tool.provision_failed", {"tool": tool_name, "reason": str(exc)})
            return jsonify({"error": str(exc), "runtime": wrapper.runtime_status()}), 409
        after = wrapper.runtime_status()
        audit.append("v4.tool.provisioned", {"tool": tool_name, "ecosystem": result.ecosystem, "sha256": result.sha256, "tier": after["tier"]})
        return jsonify({"result": result.__dict__, "runtime": after})

    @app.post("/api/v4/tools/<tool_name>/probe")
    @authenticated
    def v4_probe(tool_name: str) -> tuple[Response, int] | Response:
        cls = classes.get(tool_name)
        if cls is None:
            return jsonify({"error": "unknown tool"}), 404
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: True, environment=os.environ)
        try:
            backend = wrapper.resolver.resolve(wrapper)
        except Exception as exc:
            return jsonify({"status": "unavailable", "error": str(exc)}), 409
        probe = list(getattr(cls, "probe", ()) or [])
        if not probe:
            return jsonify({"status": "resolved", "tier": backend.tier, "backend": backend.key, "probe": "not-declared"})
        try:
            stdout, stderr, rc = asyncio.run(backend.probe(wrapper, probe, timeout=20.0))
        except Exception as exc:
            return jsonify({"status": "failed", "tier": backend.tier, "backend": backend.key, "error": str(exc)}), 409
        payload = {"status": "pass" if rc == 0 else "failed", "tier": backend.tier, "backend": backend.key, "rc": rc, "stdout_tail": stdout[-1000:], "stderr_tail": stderr[-1000:]}
        return jsonify(payload), 200 if rc == 0 else 409


__all__ = ["register_v4_api"]
