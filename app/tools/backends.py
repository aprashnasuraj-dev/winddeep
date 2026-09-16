"""Execution backends and ordered resolver for Windeep v4.

A catalog entry is never assumed to be locally executable.  Each run resolves
through explicit backends and records the backend that actually served it.
Normal scans do not install software; provisioning is a separate, consented
operation handled by :mod:`app.tools.provisioning`.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

import httpx

from app.tools import builtin_integrations


class BackendUnavailableError(RuntimeError):
    """Raised when no configured backend can execute an integration."""


class BackendExecutionError(RuntimeError):
    """Raised when a backend cannot complete an execution contract."""


class ExecutionBackend(ABC):
    """Common contract implemented by all execution backends."""

    key: str
    tier: str

    @abstractmethod
    def can_run(self, tool: Any) -> bool:
        """Return whether this backend can currently serve ``tool``."""

    @abstractmethod
    async def exec(
        self,
        tool: Any,
        argv: Sequence[str],
        stdin: bytes | None,
        timeout: float,
    ) -> tuple[str, str, int]:
        """Execute ``argv`` and return stdout, stderr and process-style rc."""

    async def probe(self, tool: Any, probe: Sequence[str], timeout: float = 15.0) -> tuple[str, str, int]:
        return await self.exec(tool, [str(item) for item in probe], None, timeout)


async def _exec_process(
    argv: Sequence[str],
    stdin: bytes | None,
    timeout: float,
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
) -> tuple[str, str, int]:
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0)
    process = await asyncio.create_subprocess_exec(
        *[str(item) for item in argv],
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=creationflags,
        env=dict(env) if env is not None else None,
        cwd=str(cwd) if cwd is not None else None,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(stdin), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    return (
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
        int(process.returncode or 0),
    )


class LocalBinaryBackend(ExecutionBackend):
    key = "local_binary"
    tier = "native"

    def can_run(self, tool: Any) -> bool:
        if str(getattr(tool, "requires_host", "")).lower() in {"linux", "macos", "device"}:
            return False
        return tool.resolve_local_binary() is not None

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        binary = tool.resolve_local_binary()
        if binary is None:
            raise BackendUnavailableError(f"local binary unavailable for {tool.tool_name}")
        return await _exec_process([str(binary), *argv], stdin, timeout, env=tool.environment)


class ProvisionedBinaryBackend(ExecutionBackend):
    key = "provisioned_binary"
    tier = "provisioned"

    def can_run(self, tool: Any) -> bool:
        return tool.resolve_provisioned_binary() is not None

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        binary = tool.resolve_provisioned_binary()
        if binary is None:
            raise BackendUnavailableError(f"provisioned binary unavailable for {tool.tool_name}")
        return await _exec_process([str(binary), *argv], stdin, timeout, env=tool.environment)


class ContainerBackend(ExecutionBackend):
    key = "container"
    tier = "container"
    _health_cache: dict[str, tuple[float, bool]] = {}

    def _runtime(self, tool: Any) -> str | None:
        requested = str(getattr(tool, "container_runtime", "") or "").strip()
        candidates = [requested] if requested else ["docker", "podman"]
        for name in candidates:
            if name and shutil.which(name):
                return name
        return None

    def _healthy(self, runtime: str) -> bool:
        cached = self._health_cache.get(runtime)
        now = time.monotonic()
        if cached and now - cached[0] < 15.0:
            return cached[1]
        try:
            completed = subprocess.run(
                [runtime, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
            ok = completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        self._health_cache[runtime] = (now, ok)
        return ok

    def can_run(self, tool: Any) -> bool:
        image = str(getattr(tool, "container_image", "") or "").strip()
        if not image:
            return False
        runtime = self._runtime(tool)
        return bool(runtime and self._healthy(runtime))

    @staticmethod
    def _rewrite_host_paths(argv: Sequence[str]) -> tuple[list[str], list[tuple[Path, str]]]:
        rewritten: list[str] = []
        mounts: list[tuple[Path, str]] = []
        by_parent: dict[Path, str] = {}
        for token in argv:
            raw = str(token)
            candidate = Path(raw).expanduser()
            if candidate.is_absolute() and candidate.exists():
                parent = candidate.parent if candidate.is_file() else candidate
                mount = by_parent.get(parent)
                if mount is None:
                    mount = f"/windeep/input{len(by_parent)}"
                    by_parent[parent] = mount
                    mounts.append((parent, mount))
                rewritten.append(str(Path(mount) / candidate.name) if candidate.is_file() else mount)
            else:
                rewritten.append(raw)
        return rewritten, mounts

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        runtime = self._runtime(tool)
        image = str(getattr(tool, "container_image", "") or "").strip()
        if not runtime or not image or not self._healthy(runtime):
            raise BackendUnavailableError(f"container runtime unavailable for {tool.tool_name}")
        rewritten, mounts = self._rewrite_host_paths(argv)
        with tempfile.TemporaryDirectory(prefix="windeep-container-") as scratch:
            command = [runtime, "run", "--rm", "-i", "--network", "host"]
            command.extend(["-v", f"{Path(scratch).resolve()}:/windeep/scratch"])
            for host, guest in mounts:
                command.extend(["-v", f"{host.resolve()}:{guest}:ro"])
            command.append(image)
            binary = str(getattr(tool, "container_command", "") or getattr(tool, "execution_name", "") or tool.binary)
            command.extend([binary, *rewritten])
            return await _exec_process(command, stdin, timeout, env=tool.environment)


class WslBackend(ExecutionBackend):
    key = "wsl"
    tier = "wsl"

    def _launcher(self) -> str | None:
        return shutil.which("wsl.exe") if os.name == "nt" else None

    def _distro_args(self, tool: Any) -> list[str]:
        distro = str(getattr(tool, "wsl_distro", "") or tool.environment.get("WINDEEP_WSL_DISTRO", "")).strip()
        return ["-d", distro] if distro else []

    def can_run(self, tool: Any) -> bool:
        if str(getattr(tool, "requires_host", "")).lower() in {"macos", "device"}:
            return False
        launcher = self._launcher()
        if not launcher:
            return False
        binary = str(getattr(tool, "execution_name", "") or tool.binary)
        try:
            completed = subprocess.run(
                [launcher, *self._distro_args(tool), "--", "sh", "-lc", f"command -v {shlex_quote(binary)} >/dev/null 2>&1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
            return completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    async def _translate(self, tool: Any, value: str) -> str:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute() or not candidate.exists():
            return value
        launcher = self._launcher()
        if not launcher:
            return value
        stdout, _stderr, rc = await _exec_process(
            [launcher, *self._distro_args(tool), "--", "wslpath", "-a", str(candidate)],
            None,
            5.0,
        )
        return stdout.strip() if rc == 0 and stdout.strip() else value

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        launcher = self._launcher()
        if not launcher:
            raise BackendUnavailableError(f"WSL unavailable for {tool.tool_name}")
        translated = [await self._translate(tool, str(item)) for item in argv]
        binary = str(getattr(tool, "execution_name", "") or tool.binary)
        return await _exec_process(
            [launcher, *self._distro_args(tool), "--", binary, *translated],
            stdin,
            timeout,
            env=tool.environment,
        )


class RemoteWorkerBackend(ExecutionBackend):
    key = "remote_worker"
    tier = "remote"

    def _settings(self, tool: Any) -> tuple[str, str]:
        url = str(tool.environment.get("WINDEEP_REMOTE_WORKER_URL", "")).strip().rstrip("/")
        token = str(tool.environment.get("WINDEEP_REMOTE_WORKER_TOKEN", "")).strip()
        return url, token

    def can_run(self, tool: Any) -> bool:
        url, token = self._settings(tool)
        if not url or not token:
            return False
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return True
        return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        url, token = self._settings(tool)
        if not self.can_run(tool):
            raise BackendUnavailableError(f"remote worker unavailable for {tool.tool_name}")
        payload = {
            "tool": str(getattr(tool, "execution_name", "") or tool.tool_name),
            "argv": [str(item) for item in argv],
            "stdin_b64": base64.b64encode(stdin).decode("ascii") if stdin is not None else None,
            "timeout": float(timeout),
            "requires_host": str(getattr(tool, "requires_host", "") or ""),
        }
        async with httpx.AsyncClient(timeout=timeout + 10.0) as client:
            response = await client.post(
                f"{url}/v1/exec",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict):
            raise BackendExecutionError("remote worker returned a non-object response")
        return str(data.get("stdout") or ""), str(data.get("stderr") or ""), int(data.get("rc", 1))


class BuiltinFallbackBackend(ExecutionBackend):
    key = "builtin_fallback"
    tier = "builtin-fallback"

    def can_run(self, tool: Any) -> bool:
        adapter = str(getattr(tool, "builtin_fallback", "") or getattr(tool, "execution_name", "") or tool.tool_name)
        return builtin_integrations.supports(adapter) or builtin_integrations.supports_fallback(adapter)

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        del argv, stdin
        adapter = str(getattr(tool, "builtin_fallback", "") or getattr(tool, "execution_name", "") or tool.tool_name)
        target = str(getattr(tool, "current_target", "") or "")
        if not target:
            raise BackendExecutionError("builtin fallback requires the active target")
        rows = await asyncio.wait_for(
            builtin_integrations.run_adapter(adapter, target, environment=tool.environment, requested_name=tool.tool_name),
            timeout=timeout,
        )
        return "\n".join(json.dumps(row, separators=(",", ":"), default=str) for row in rows), "", 0


def shlex_quote(value: str) -> str:
    """Small POSIX quote helper kept local to avoid shell execution elsewhere."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


class ExecutionResolver:
    """Resolve one tool against its runtime strategy and ordered preferences."""

    DEFAULT_ORDER = (
        "local_binary",
        "provisioned_binary",
        "container",
        "wsl",
        "remote_worker",
        "builtin_fallback",
    )

    STRATEGY_KEYS = {
        "process": {"local_binary", "provisioned_binary"},
        "builtin": {"builtin_fallback"},
        "container": {"container"},
        "wsl": {"wsl"},
        "remote": {"remote_worker"},
        "auto": set(DEFAULT_ORDER),
    }

    def __init__(self, backends: Iterable[ExecutionBackend] | None = None) -> None:
        items = list(backends or [
            LocalBinaryBackend(),
            ProvisionedBinaryBackend(),
            ContainerBackend(),
            WslBackend(),
            RemoteWorkerBackend(),
            BuiltinFallbackBackend(),
        ])
        self.backends = {item.key: item for item in items}

    def ordered_keys(self, tool: Any) -> list[str]:
        strategy = str(getattr(tool, "runtime_strategy", "auto") or "auto").lower()
        if strategy not in self.STRATEGY_KEYS:
            raise ValueError(f"unknown runtime_strategy for {tool.tool_name}: {strategy}")
        preference = list(getattr(tool, "execution_preference", ()) or self.DEFAULT_ORDER)
        normalized = []
        aliases = {
            "local": "local_binary",
            "provision": "provisioned_binary",
            "provisioned": "provisioned_binary",
            "remote": "remote_worker",
            "builtin": "builtin_fallback",
        }
        allowed = self.STRATEGY_KEYS[strategy]
        for raw in preference:
            key = aliases.get(str(raw), str(raw))
            if key in allowed and key in self.backends and key not in normalized:
                normalized.append(key)
        if strategy != "auto" and not normalized:
            normalized = [key for key in self.DEFAULT_ORDER if key in allowed and key in self.backends]
        return normalized

    def resolve(self, tool: Any) -> ExecutionBackend:
        for key in self.ordered_keys(tool):
            backend = self.backends[key]
            if backend.can_run(tool):
                return backend
        attempted = ", ".join(self.ordered_keys(tool)) or "none"
        raise BackendUnavailableError(
            f"no execution backend available for {tool.tool_name}; attempted: {attempted}"
        )

    def status(self, tool: Any) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        selected: ExecutionBackend | None = None
        for key in self.ordered_keys(tool):
            backend = self.backends[key]
            available = bool(backend.can_run(tool))
            rows.append({"backend": key, "tier": backend.tier, "available": available})
            if selected is None and available:
                selected = backend
        return {
            "tool": tool.tool_name,
            "runtime_strategy": str(getattr(tool, "runtime_strategy", "auto")),
            "tier": selected.tier if selected else "unavailable",
            "backend": selected.key if selected else None,
            "chain": rows,
        }


def backend_capabilities(environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = {**os.environ, **dict(environment or {})}
    remote_url = str(env.get("WINDEEP_REMOTE_WORKER_URL", "")).strip()
    remote_token = str(env.get("WINDEEP_REMOTE_WORKER_TOKEN", "")).strip()
    return {
        "local": True,
        "go": bool(shutil.which("go")),
        "pipx": bool(shutil.which("pipx")),
        "cargo": bool(shutil.which("cargo")),
        "npm": bool(shutil.which("npm")),
        "docker": bool(shutil.which("docker")),
        "podman": bool(shutil.which("podman")),
        "wsl": bool(os.name == "nt" and shutil.which("wsl.exe")),
        "remote": bool(remote_url and remote_token),
    }
