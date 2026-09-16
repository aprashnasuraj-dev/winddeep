"""Consented, ecosystem-aware lazy provisioning for Windeep v4.

Provisioning is intentionally never triggered implicitly by backend resolution.
Callers must pass ``consent=True`` (doctor --heal or an explicit scan request)
before any package manager is invoked.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class ProvisioningError(RuntimeError):
    """Raised when a provisioning contract cannot be satisfied."""


@dataclass(frozen=True)
class ProvisionResult:
    tool: str
    ecosystem: str
    command: tuple[str, ...]
    binary: str | None
    sha256: str | None
    cache_record: str | None
    status: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def _candidate_names(binary: str) -> list[str]:
    names = [binary]
    if os.name == "nt" and not Path(binary).suffix:
        names.extend([binary + suffix for suffix in (".exe", ".cmd", ".bat")])
    return names


def provisioned_candidates(tool: Any) -> list[Path]:
    recipe = dict(getattr(tool, "provision", {}) or {})
    ecosystem = str(recipe.get("ecosystem") or "").lower()
    binary = str(recipe.get("binary") or getattr(tool, "execution_name", "") or tool.binary)
    root = Path(tool.tools_dir) / "provisioned"
    bases: list[Path] = []
    if ecosystem == "go":
        bases.append(root / "bin")
    elif ecosystem == "cargo":
        bases.append(root / "cargo" / "bin")
    elif ecosystem == "pipx":
        bases.append(root / "pipx" / "bin")
    elif ecosystem == "npm":
        bases.append(root / "npm" / "node_modules" / ".bin")
    elif ecosystem == "portable":
        bases.append(root / "portable" / str(getattr(tool, "tool_name", "tool")))
    for base in bases:
        for name in _candidate_names(binary):
            yield base / name


class Provisioner:
    """Install one declared recipe into Windeep-managed locations where possible."""

    def __init__(self, tools_dir: str | Path, *, environment: Mapping[str, str] | None = None) -> None:
        self.tools_dir = Path(tools_dir).resolve()
        self.environment = {**os.environ, **dict(environment or {})}
        self.root = self.tools_dir / "provisioned"
        self.cache = self.tools_dir / ".cache"
        self.cache_objects = self.cache / "objects"
        self.cache_records = self.cache / "records"
        for path in (self.root, self.cache_objects, self.cache_records):
            path.mkdir(parents=True, exist_ok=True)

    def _run(self, argv: list[str], *, env: Mapping[str, str] | None = None, timeout: float = 1800.0) -> None:
        completed = subprocess.run(
            argv,
            env=dict(env or self.environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            tail = (completed.stdout or "")[-4000:]
            raise ProvisioningError(f"provision command failed ({completed.returncode}): {' '.join(argv)}\n{tail}")

    def _record_binary(self, tool: Any, binary: Path | None, ecosystem: str, command: list[str]) -> ProvisionResult:
        sha: str | None = None
        record_path: Path | None = None
        if binary is not None and binary.is_file():
            sha = _sha256(binary)
            object_path = self.cache_objects / sha
            if not object_path.exists():
                shutil.copy2(binary, object_path)
            recipe = dict(getattr(tool, "provision", {}) or {})
            version = str(recipe.get("version") or "unversioned")
            record_path = self.cache_records / f"{_safe_name(tool.tool_name)}-{_safe_name(version)}-{sha}.json"
            record_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "tool": tool.tool_name,
                        "execution_name": str(getattr(tool, "execution_name", "") or tool.tool_name),
                        "ecosystem": ecosystem,
                        "version": version,
                        "sha256": sha,
                        "object": str(object_path.relative_to(self.tools_dir)),
                        "binary": str(binary.relative_to(self.tools_dir)) if binary.is_relative_to(self.tools_dir) else str(binary),
                        "created_at": int(time.time()),
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
        return ProvisionResult(
            tool=tool.tool_name,
            ecosystem=ecosystem,
            command=tuple(command),
            binary=str(binary) if binary else None,
            sha256=sha,
            cache_record=str(record_path) if record_path else None,
            status="provisioned",
        )

    def _resolved_binary(self, tool: Any) -> Path | None:
        for candidate in provisioned_candidates(tool):
            if candidate.is_file():
                return candidate.resolve()
        name = str(getattr(tool, "execution_name", "") or tool.binary)
        found = shutil.which(name)
        return Path(found).resolve() if found else None

    def provision(self, tool: Any, *, consent: bool) -> ProvisionResult:
        if not consent:
            raise PermissionError("tool provisioning requires explicit operator consent")
        recipe = dict(getattr(tool, "provision", {}) or {})
        if not recipe:
            raise ProvisioningError(f"no provision recipe declared for {tool.tool_name}")
        ecosystem = str(recipe.get("ecosystem") or "").lower()
        package = str(recipe.get("package") or "").strip()
        version = str(recipe.get("version") or "").strip()
        if not ecosystem or not package:
            raise ProvisioningError(f"invalid provision recipe for {tool.tool_name}")

        existing = self._resolved_binary(tool)
        if existing is not None:
            return self._record_binary(tool, existing, ecosystem, ["<already-present>"])

        env = dict(self.environment)
        command: list[str]
        if ecosystem == "go":
            executable = shutil.which("go")
            if not executable:
                raise ProvisioningError("Go toolchain is not available")
            destination = self.root / "bin"
            destination.mkdir(parents=True, exist_ok=True)
            env["GOBIN"] = str(destination)
            spec = f"{package}@{version or 'latest'}"
            command = [executable, "install", spec]
        elif ecosystem == "cargo":
            executable = shutil.which("cargo")
            if not executable:
                raise ProvisioningError("Cargo is not available")
            cargo_root = self.root / "cargo"
            cargo_root.mkdir(parents=True, exist_ok=True)
            command = [executable, "install", "--root", str(cargo_root), package]
            if version and version not in {"latest", "*"}:
                command.extend(["--version", version])
        elif ecosystem == "pipx":
            executable = shutil.which("pipx")
            if not executable:
                raise ProvisioningError("pipx is not available")
            pipx_root = self.root / "pipx"
            env["PIPX_HOME"] = str(pipx_root / "home")
            env["PIPX_BIN_DIR"] = str(pipx_root / "bin")
            spec = package if not version or version in {"latest", "*"} else f"{package}=={version}"
            command = [executable, "install", "--force", spec]
        elif ecosystem == "npm":
            executable = shutil.which("npm")
            if not executable:
                raise ProvisioningError("npm is not available")
            npm_root = self.root / "npm"
            npm_root.mkdir(parents=True, exist_ok=True)
            spec = package if not version else f"{package}@{version}"
            command = [executable, "install", "--prefix", str(npm_root), spec]
        elif ecosystem == "os":
            command = self._os_command(recipe)
        else:
            raise ProvisioningError(f"unsupported provision ecosystem: {ecosystem}")

        self._run(command, env=env, timeout=float(recipe.get("timeout", 1800.0)))
        binary = self._resolved_binary(tool)
        if binary is None:
            raise ProvisioningError(
                f"{tool.tool_name} provisioning completed but executable was not discovered; expected {recipe.get('binary') or tool.binary}"
            )
        expected_sha = str(recipe.get("sha256") or "").lower().strip()
        if expected_sha:
            actual = _sha256(binary)
            if actual != expected_sha:
                raise ProvisioningError(f"provisioned binary checksum mismatch for {tool.tool_name}: {actual}")
        return self._record_binary(tool, binary, ecosystem, command)

    @staticmethod
    def _privileged(command: list[str]) -> list[str]:
        if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0:
            return command
        sudo = shutil.which("sudo")
        if not sudo:
            raise ProvisioningError("OS package installation requires root privileges or sudo")
        return [sudo, *command]

    def _os_command(self, recipe: Mapping[str, Any]) -> list[str]:
        packages = recipe.get("packages") or {}
        if not isinstance(packages, Mapping):
            raise ProvisioningError("OS recipe requires a packages mapping")
        version = str(recipe.get("version") or "").strip()
        if os.name == "nt":
            choco = shutil.which("choco")
            if choco and packages.get("choco"):
                command = [choco, "install", "-y", str(packages["choco"])]
                if version and version not in {"latest", "*"}:
                    command.extend(["--version", version])
                return command
            winget = shutil.which("winget")
            if winget and packages.get("winget"):
                return [winget, "install", "--id", str(packages["winget"]), "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements"]
        apt = shutil.which("apt-get")
        if apt and packages.get("apt"):
            package = str(packages["apt"])
            if version and version not in {"latest", "*"}:
                package = f"{package}={version}"
            return self._privileged([apt, "install", "-y", package])
        brew = shutil.which("brew")
        if brew and packages.get("brew"):
            return [brew, "install", str(packages["brew"])]
        raise ProvisioningError("no supported OS package manager/recipe combination is available")


def restore_cached_binary(tool: Any) -> Path | None:
    """Restore the newest matching content-addressed binary record when possible."""
    root = Path(tool.tools_dir)
    records = root / ".cache" / "records"
    if not records.exists():
        return None
    prefix = _safe_name(tool.tool_name) + "-"
    candidates = sorted((path for path in records.glob(prefix + "*.json") if path.is_file()), reverse=True)
    for record in candidates:
        try:
            data = json.loads(record.read_text(encoding="utf-8"))
            object_path = root / str(data["object"])
            binary_raw = str(data["binary"])
            binary = Path(binary_raw)
            if not binary.is_absolute():
                binary = root / binary
            if not object_path.is_file() or _sha256(object_path) != str(data["sha256"]):
                continue
            binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(object_path, binary)
            return binary.resolve()
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            continue
    return None
