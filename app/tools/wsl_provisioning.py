"""Consented provisioning of declared Windeep recipes inside WSL.

The execution backend never installs anything.  ``doctor --heal`` calls this
module only after the operator has granted provisioning consent.  Installation
runs as the WSL distro's root user so it is deterministic and non-interactive,
and places CLI entry points in /usr/local/bin where the normal WSL execution
backend can discover them without shell/profile assumptions.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping


class WslProvisioningError(RuntimeError):
    pass


@dataclass(frozen=True)
class WslProvisionResult:
    tool: str
    ecosystem: str
    binary: str
    status: str


def _launcher() -> str | None:
    return shutil.which("wsl.exe") if os.name == "nt" else None


def _distro_args(tool: Any) -> list[str]:
    distro = str(getattr(tool, "wsl_distro", "") or tool.environment.get("WINDEEP_WSL_DISTRO", "")).strip()
    return ["-d", distro] if distro else []


def _run(tool: Any, argv: list[str], *, timeout: float = 1800.0, root: bool = False) -> subprocess.CompletedProcess[str]:
    launcher = _launcher()
    if not launcher:
        raise WslProvisioningError("wsl.exe is unavailable")
    prefix = [launcher, *_distro_args(tool)]
    if root:
        prefix.extend(["-u", "root"])
    completed = subprocess.run(
        [*prefix, "--", *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed


def _ensure_command(tool: Any, command: str, apt_package: str) -> None:
    check = _run(tool, ["sh", "-lc", f"command -v {command} >/dev/null 2>&1"], timeout=15.0)
    if check.returncode == 0:
        return
    update = _run(tool, ["apt-get", "update"], timeout=1200.0, root=True)
    if update.returncode != 0:
        raise WslProvisioningError(f"WSL apt-get update failed: {(update.stdout or '')[-2000:]}")
    install = _run(tool, ["apt-get", "install", "-y", apt_package], timeout=1800.0, root=True)
    if install.returncode != 0:
        raise WslProvisioningError(f"WSL prerequisite {apt_package} failed: {(install.stdout or '')[-2000:]}")


def _apt_package(recipe: Mapping[str, Any]) -> str:
    packages = recipe.get("packages") or {}
    if isinstance(packages, Mapping) and packages.get("apt"):
        return str(packages["apt"])
    package = str(recipe.get("package") or "").strip()
    if not package:
        raise WslProvisioningError("WSL OS recipe has no apt package")
    return package


def provision_wsl(tool: Any, *, consent: bool) -> WslProvisionResult:
    if not consent:
        raise PermissionError("WSL provisioning requires explicit operator consent")
    if _launcher() is None:
        raise WslProvisioningError("wsl.exe is unavailable")
    required_host = str(getattr(tool, "requires_host", "") or "").lower()
    if required_host in {"macos", "device"}:
        raise WslProvisioningError(f"{tool.tool_name} requires host={required_host}")
    preference = tuple(str(item) for item in (getattr(tool, "execution_preference", ()) or ()))
    if preference and "wsl" not in preference:
        raise WslProvisioningError(f"{tool.tool_name} does not declare a WSL execution route")

    recipe = dict(getattr(tool, "provision", {}) or {})
    if not recipe:
        raise WslProvisioningError(f"{tool.tool_name} has no WSL-provisionable recipe")
    ecosystem = str(recipe.get("ecosystem") or "").lower()
    package = str(recipe.get("package") or "").strip()
    version = str(recipe.get("version") or "").strip()
    binary = str(recipe.get("binary") or getattr(tool, "execution_name", "") or tool.binary)
    timeout = float(recipe.get("timeout", 1800.0))

    if ecosystem == "go":
        _ensure_command(tool, "go", "golang-go")
        spec = f"{package}@{version or 'latest'}"
        command = ["env", "GOBIN=/usr/local/bin", "go", "install", spec]
    elif ecosystem == "cargo":
        _ensure_command(tool, "cargo", "cargo")
        command = ["cargo", "install", "--root", "/usr/local", package]
        if version and version not in {"latest", "*"}:
            command.extend(["--version", version])
    elif ecosystem == "pipx":
        _ensure_command(tool, "pipx", "pipx")
        spec = package if not version or version in {"latest", "*"} else f"{package}=={version}"
        command = ["env", "PIPX_HOME=/opt/windeep/pipx", "PIPX_BIN_DIR=/usr/local/bin", "pipx", "install", "--force", spec]
    elif ecosystem == "npm":
        _ensure_command(tool, "npm", "npm")
        spec = package if not version else f"{package}@{version}"
        command = ["npm", "install", "-g", spec]
    elif ecosystem == "os":
        update = _run(tool, ["apt-get", "update"], timeout=1200.0, root=True)
        if update.returncode != 0:
            raise WslProvisioningError(f"WSL apt-get update failed: {(update.stdout or '')[-2000:]}")
        command = ["apt-get", "install", "-y", _apt_package(recipe)]
    else:
        raise WslProvisioningError(f"unsupported WSL provisioning ecosystem: {ecosystem}")

    completed = _run(tool, command, timeout=timeout, root=True)
    if completed.returncode != 0:
        raise WslProvisioningError(
            f"WSL provisioning failed ({completed.returncode}): {' '.join(command)}\n{(completed.stdout or '')[-3000:]}"
        )
    probe = _run(tool, ["sh", "-lc", f"command -v '{binary}'"], timeout=20.0)
    if probe.returncode != 0 or not (probe.stdout or "").strip():
        raise WslProvisioningError(f"WSL provisioning completed but {binary} is not discoverable")
    return WslProvisionResult(tool=tool.tool_name, ecosystem=ecosystem, binary=(probe.stdout or "").strip().splitlines()[-1], status="provisioned")
