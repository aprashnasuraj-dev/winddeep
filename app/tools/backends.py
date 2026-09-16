"""Execution backends and ordered resolver for Windeep v4."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import httpx

from app.tools import builtin_fallbacks, builtin_integrations


class BackendUnavailableError(RuntimeError):
    pass


class BackendExecutionError(RuntimeError):
    pass


class ExecutionBackend(ABC):
    key = "base"
    tier = "unavailable"

    @abstractmethod
    def can_run(self, tool: Any) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        raise NotImplementedError

    async def probe(self, tool: Any, argv: Sequence[str], timeout: float = 20.0) -> tuple[str, str, int]:
        return await self.exec(tool, argv, None, timeout)


async def _exec_process(
    argv: Sequence[str | Path],
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
    return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), int(process.returncode or 0)


def _required_env_present(tool: Any) -> bool:
    return all(str(tool.environment.get(name) or "").strip() for name in getattr(tool, "required_env", ()))


async def _wrapper_process(tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
    """Run through the wrapper hook when available.

    V4 keeps process execution behind backends, but the wrapper hook is an
    intentional compatibility/test seam and carries its cancellation/runtime
    environment semantics.  Older integrations also monkeypatch this method.
    """
    runner = getattr(tool, "_run_process", None)
    if callable(runner):
        try:
            return await runner(list(argv), stdin)
        except TypeError:
            # Legacy test/adapters exposed _run_process(argv) only.
            if stdin is None:
                return await runner(list(argv))
            raise
    return await _exec_process(argv, stdin, timeout, env=tool.environment)


class LocalBinaryBackend(ExecutionBackend):
    key = "local_binary"
    tier = "native"

    def can_run(self, tool: Any) -> bool:
        if str(getattr(tool, "requires_host", "")).lower() in {"linux", "macos", "device"}:
            return False
        return _required_env_present(tool) and tool.resolve_local_binary() is not None

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        binary = tool.resolve_local_binary()
        if binary is None:
            raise BackendUnavailableError(f"local binary unavailable for {tool.tool_name}")
        return await _wrapper_process(tool, [str(binary), *argv], stdin, timeout)


class ProvisionedBinaryBackend(ExecutionBackend):
    key = "provisioned_binary"
    tier = "provisioned"

    def can_run(self, tool: Any) -> bool:
        return _required_env_present(tool) and tool.resolve_provisioned_binary() is not None

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        binary = tool.resolve_provisioned_binary()
        if binary is None:
            raise BackendUnavailableError(f"provisioned binary unavailable for {tool.tool_name}")
        return await _wrapper_process(tool, [str(binary), *argv], stdin, timeout)


class ContainerBackend(ExecutionBackend):
    key = "container"
    tier = "container"
    _health_cache: dict[str, tuple[float, bool]] = {}
    _image_cache: dict[tuple[str, str], tuple[float, bool]] = {}

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
            completed = subprocess.run([runtime, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
            ok = completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        self._health_cache[runtime] = (now, ok)
        return ok

    def _image_present(self, runtime: str, image: str) -> bool:
        key = (runtime, image)
        cached = self._image_cache.get(key)
        now = time.monotonic()
        if cached and now - cached[0] < 15.0:
            return cached[1]
        try:
            completed = subprocess.run([runtime, "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            ok = completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        self._image_cache[key] = (now, ok)
        return ok

    def can_run(self, tool: Any) -> bool:
        image = str(getattr(tool, "container_image", "") or "").strip()
        if not image:
            return False
        if str(getattr(tool, "requires_host", "")).lower() in {"macos", "device"}:
            return False
        runtime = self._runtime(tool)
        return bool(runtime and self._healthy(runtime) and self._image_present(runtime, image))

    def _mount_args(self, tool: Any) -> list[str]:
        root = Path(tool.tools_dir).resolve()
        scratch = root / ".runtime" / "container" / tool.tool_name
        scratch.mkdir(parents=True, exist_ok=True)
        return ["-v", f"{scratch}:/work", "-w", "/work"]

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        runtime = self._runtime(tool)
        image = str(getattr(tool, "container_image", "") or "")
        if runtime is None or not self.can_run(tool):
            raise BackendUnavailableError(f"container runtime/image unavailable for {tool.tool_name}")
        command = str(getattr(tool, "container_command", "") or getattr(tool, "execution_name", "") or tool.binary)
        extra = list(getattr(tool, "container_args", ()) or ())
        return await _exec_process([runtime, "run", "--rm", *self._mount_args(tool), *extra, image, command, *argv], stdin, timeout, env=tool.environment)


class WslBackend(ExecutionBackend):
    key = "wsl"
    tier = "wsl"

    def _launcher(self) -> str | None:
        return shutil.which("wsl.exe") if os.name == "nt" else None

    def _distro_args(self, tool: Any) -> list[str]:
        distro = str(getattr(tool, "wsl_distro", "") or tool.environment.get("WINDEEP_WSL_DISTRO", "")).strip()
        return ["-d", distro] if distro else []

    def _binary(self, tool: Any) -> str:
        return str(getattr(tool, "wsl_binary", "") or getattr(tool, "execution_name", "") or tool.binary)

    def can_run(self, tool: Any) -> bool:
        if self._launcher() is None:
            return False
        if str(getattr(tool, "requires_host", "")).lower() in {"macos", "device"}:
            return False
        try:
            completed = subprocess.run(
                [self._launcher(), *self._distro_args(tool), "--", "sh", "-lc", f"command -v {shlex_quote(self._binary(tool))} >/dev/null 2>&1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        launcher = self._launcher()
        if launcher is None or not self.can_run(tool):
            raise BackendUnavailableError(f"WSL backend unavailable for {tool.tool_name}")
        return await _exec_process([launcher, *self._distro_args(tool), "--", self._binary(tool), *argv], stdin, timeout, env=tool.environment)


class RemoteWorkerBackend(ExecutionBackend):
    key = "remote_worker"
    tier = "remote"

    def _config(self, tool: Any) -> tuple[str, str]:
        url = str(tool.environment.get("WINDEEP_REMOTE_WORKER_URL") or "").strip().rstrip("/")
        token = str(tool.environment.get("WINDEEP_REMOTE_WORKER_TOKEN") or "").strip()
        return url, token

    def can_run(self, tool: Any) -> bool:
        url, token = self._config(tool)
        if not url or not token:
            return False
        if url.startswith("http://") and not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
            return False
        return True

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        url, token = self._config(tool)
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
            response = await client.post(f"{url}/v1/exec", headers={"Authorization": f"Bearer {token}"}, json=payload)
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict):
            raise BackendExecutionError("remote worker returned a non-object response")
        return str(data.get("stdout") or ""), str(data.get("stderr") or ""), int(data.get("rc", 1))


class BuiltinFallbackBackend(ExecutionBackend):
    key = "builtin_fallback"
    tier = "builtin-fallback"

    def _adapter(self, tool: Any) -> str:
        return str(getattr(tool, "builtin_fallback", "") or getattr(tool, "execution_name", "") or tool.tool_name)

    def can_run(self, tool: Any) -> bool:
        adapter = self._adapter(tool)
        supported = builtin_integrations.supports(adapter) or builtin_fallbacks.supports(adapter)
        required = (*builtin_integrations.required_env(adapter), *builtin_fallbacks.required_env(adapter))
        return supported and all(str(tool.environment.get(name) or "").strip() for name in required)

    async def exec(self, tool: Any, argv: Sequence[str], stdin: bytes | None, timeout: float) -> tuple[str, str, int]:
        del argv, stdin
        adapter = self._adapter(tool)
        target = str(getattr(tool, "current_target", "") or "")
        if not target:
            raise BackendExecutionError("builtin fallback requires the active target")
        if builtin_integrations.supports(adapter):
            awaitable = builtin_integrations.run(adapter, target, environment=tool.environment)
        elif builtin_fallbacks.supports(adapter):
            awaitable = builtin_fallbacks.run_adapter(adapter, target, environment=tool.environment, requested_name=tool.tool_name)
        else:
            raise BackendUnavailableError(f"builtin adapter unavailable: {adapter}")
        rows = await asyncio.wait_for(awaitable, timeout=timeout)
        return "\n".join(json.dumps(row, separators=(",", ":"), default=str) for row in rows), "", 0


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


class ExecutionResolver:
    DEFAULT_ORDER = ("local_binary", "provisioned_binary", "container", "wsl", "remote_worker", "builtin_fallback")
    STRATEGY_KEYS = {
        "process": {"local_binary", "provisioned_binary"},
        "builtin": {"builtin_fallback"},
        "container": {"container"},
        "wsl": {"wsl"},
        "remote": {"remote_worker"},
        "auto": set(DEFAULT_ORDER),
    }

    def __init__(self, backends: Iterable[ExecutionBackend] | None = None) -> None:
        items = list(backends or [LocalBinaryBackend(), ProvisionedBinaryBackend(), ContainerBackend(), WslBackend(), RemoteWorkerBackend(), BuiltinFallbackBackend()])
        self.backends = {item.key: item for item in items}

    def ordered_keys(self, tool: Any) -> list[str]:
        strategy = str(getattr(tool, "runtime_strategy", "auto") or "auto").lower()
        if strategy not in self.STRATEGY_KEYS:
            raise ValueError(f"unknown runtime_strategy for {tool.tool_name}: {strategy}")
        preference = list(getattr(tool, "execution_preference", ()) or self.DEFAULT_ORDER)
        aliases = {"local": "local_binary", "provision": "provisioned_binary", "provisioned": "provisioned_binary", "remote": "remote_worker", "builtin": "builtin_fallback"}
        allowed = self.STRATEGY_KEYS[strategy]
        normalized: list[str] = []
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
        raise BackendUnavailableError(f"no execution backend available for {tool.tool_name}; attempted: {attempted}")

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


def _runtime_healthy(name: str) -> bool:
    executable = shutil.which(name)
    if not executable:
        return False
    try:
        return subprocess.run([executable, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


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
        "docker": _runtime_healthy("docker"),
        "podman": _runtime_healthy("podman"),
        "wsl": bool(os.name == "nt" and shutil.which("wsl.exe")),
        "remote": bool(remote_url and remote_token),
    }
