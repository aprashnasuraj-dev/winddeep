"""Resolver-aware diagnostics and explicit healing for Windeep v4."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

from app.tools.process_utils import hidden_process_kwargs

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools.backends import BackendUnavailableError, backend_capabilities
from app.tools.provisioning import Provisioner, ProvisioningError
from app.tools.release_metadata import effective_definitions
from app.tools.wsl_provisioning import WslProvisioningError, provision_wsl


def _root_from_registry(registry: Path) -> Path:
    return registry.resolve().parent


def _load_release_contracts(root: Path) -> dict[str, dict[str, str]]:
    path = root / "app" / "tools" / "config" / "v4_release_contracts.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    contracts = raw.get("contract_only", {}) if isinstance(raw, dict) else {}
    if not isinstance(contracts, dict):
        return {}
    return {
        str(name): {"kind": str(item.get("kind") or ""), "reason": str(item.get("reason") or "")}
        for name, item in contracts.items()
        if isinstance(item, dict)
    }


def _skip_heal_reason(
    name: str,
    cls: type[Any],
    definition: Mapping[str, Any],
    contracts: Mapping[str, Mapping[str, str]],
    env: Mapping[str, str],
) -> str | None:
    release_support = str(definition.get("release_support") or "").strip().lower()
    unsupported_reason = str(definition.get("unsupported_reason") or "").strip()
    if release_support == "unsupported" and unsupported_reason:
        return "catalog-unsupported:" + unsupported_reason

    declared = contracts.get(name)
    if declared:
        kind = str(declared.get("kind") or "contract-only")
        reason = str(declared.get("reason") or "explicit v4 release contract")
        return f"{kind}:{reason}"

    missing_env = [
        str(key)
        for key in getattr(cls, "required_env", ())
        if not str(env.get(str(key)) or "").strip()
    ]
    if missing_env:
        return "credentials:" + ",".join(sorted(missing_env))
    return None


def _build_container(image: str, root: Path) -> dict[str, Any]:
    runtime = shutil.which("docker") or shutil.which("podman")
    if not runtime:
        return {"status": "skipped", "reason": "docker/podman unavailable"}
    dockerfile = root / "docker" / "tools.Dockerfile"
    if not dockerfile.is_file():
        return {"status": "failed", "reason": f"missing {dockerfile}"}
    completed = subprocess.run(
        [runtime, "build", "-f", str(dockerfile), "-t", image, str(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=3600,
        check=False,
        **hidden_process_kwargs(),
    )
    return {
        "status": "built" if completed.returncode == 0 else "failed",
        "rc": completed.returncode,
        "tail": (completed.stdout or "")[-4000:],
    }


async def _probe(wrapper: Any) -> dict[str, Any]:
    try:
        backend = wrapper.resolver.resolve(wrapper)
    except BackendUnavailableError as exc:
        return {"status": "unavailable", "error": str(exc)}

    if backend.key == "builtin_fallback":
        return {
            "status": "pass",
            "backend": backend.key,
            "tier": backend.tier,
            "probe": "adapter-registration",
        }

    probe = list(getattr(wrapper, "probe", ()) or [])
    if not probe:
        return {"status": "resolved", "backend": backend.key, "tier": backend.tier, "probe": "not-declared"}
    try:
        stdout, stderr, rc = await backend.probe(wrapper, probe, timeout=20.0)
    except Exception as exc:
        return {"status": "failed", "backend": backend.key, "tier": backend.tier, "error": str(exc)}

    accepted = tuple(getattr(wrapper, "probe_success_codes", (0, 1, 2)) or (0, 1, 2))
    return {
        "status": "pass" if rc in accepted else "failed",
        "backend": backend.key,
        "tier": backend.tier,
        "rc": rc,
        "accepted_rc": list(accepted),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
    }


def doctor(
    registry: str | Path,
    *,
    tools_dir: str | Path,
    heal: bool = False,
    consent: bool = False,
    environment: Mapping[str, str] | None = None,
    probe: bool = True,
) -> dict[str, Any]:
    """Inspect every catalog tool and optionally provision declared dependencies."""
    registry_path = Path(registry).resolve()
    root = _root_from_registry(registry_path)
    env = {**os.environ, **dict(environment or {})}
    classes = ToolWrapperFactory(registry_path).load()
    definitions = effective_definitions(registry_path)
    release_contracts = _load_release_contracts(root)
    provisioner = Provisioner(tools_dir, environment=env)
    container_results: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []

    for name, cls in sorted(classes.items()):
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _target: True, environment=env)
        before = wrapper.runtime_status()
        actions: list[dict[str, Any]] = []
        if heal and before["tier"] == "unavailable":
            skip_reason = _skip_heal_reason(name, cls, definitions[name], release_contracts, env)
            if skip_reason:
                actions.append({"action": "contract-only", "status": "skipped", "reason": skip_reason})
            else:
                if getattr(cls, "provision", None):
                    try:
                        result = provisioner.provision(wrapper, consent=consent)
                        actions.append({"action": "provision", "status": result.status, "ecosystem": result.ecosystem, "binary": result.binary, "sha256": result.sha256})
                    except (ProvisioningError, PermissionError, OSError, subprocess.SubprocessError) as exc:
                        actions.append({"action": "provision", "status": "failed", "error": str(exc)})

                # On Windows, a failed/unavailable host install can be recovered in
                # the Linux environment using the same declared recipe. This is
                # explicitly consented and installs into WSL /usr/local/bin.
                if os.name == "nt" and wrapper.runtime_status()["tier"] == "unavailable" and consent:
                    try:
                        result = provision_wsl(wrapper, consent=True)
                        actions.append({"action": "wsl-provision", "status": result.status, "ecosystem": result.ecosystem, "binary": result.binary})
                    except (WslProvisioningError, PermissionError, OSError, subprocess.SubprocessError) as exc:
                        actions.append({"action": "wsl-provision", "status": "failed", "error": str(exc)})

                image = str(getattr(cls, "container_image", "") or "")
                if image and wrapper.runtime_status()["tier"] == "unavailable" and consent:
                    if image not in container_results:
                        container_results[image] = _build_container(image, root)
                    actions.append({"action": "container", "image": image, **container_results[image]})
        after = wrapper.runtime_status()
        probe_result = asyncio.run(_probe(wrapper)) if probe and after["tier"] != "unavailable" else {"status": "skipped"}
        rows.append(
            {
                "tool": name,
                "execution_name": getattr(cls, "execution_name", name),
                "alias_to": getattr(cls, "alias_to", "") or None,
                "before_tier": before["tier"],
                "tier": after["tier"],
                "backend": after["backend"],
                "runtime_strategy": after["runtime_strategy"],
                "has_provision_recipe": bool(getattr(cls, "provision", None)),
                "container_image": getattr(cls, "container_image", "") or None,
                "builtin_fallback": getattr(cls, "builtin_fallback", "") or None,
                "requires_host": getattr(cls, "requires_host", "") or None,
                "actions": actions,
                "probe": probe_result,
            }
        )

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["tier"]] = counts.get(row["tier"], 0) + 1
    runnable = sum(value for key, value in counts.items() if key != "unavailable")
    return {
        "schema": "windeep.doctor.v4",
        "catalog": len(rows),
        "runnable": runnable,
        "unavailable": len(rows) - runnable,
        "tiers": counts,
        "backends": backend_capabilities(env),
        "tools": rows,
    }


def render_text(report: Mapping[str, Any]) -> str:
    lines = [
        f"Windeep doctor: {report.get('runnable', 0)}/{report.get('catalog', 0)} tools resolve on this host",
        "Backends: " + ", ".join(f"{key}={'yes' if value else 'no'}" for key, value in dict(report.get('backends') or {}).items()),
        "Tiers: " + ", ".join(f"{key}={value}" for key, value in sorted(dict(report.get('tiers') or {}).items())),
        "",
    ]
    for row in report.get("tools", []):
        probe = row.get("probe") or {}
        suffix = f" probe={probe.get('status', 'unknown')}"
        alias = f" -> {row['alias_to']}" if row.get("alias_to") else ""
        lines.append(f"{row['tool']}{alias}: {row['tier']} ({row.get('backend') or 'none'}){suffix}")
        for action in row.get("actions", []):
            lines.append("  " + json.dumps(action, sort_keys=True, default=str))
    return "\n".join(lines)
