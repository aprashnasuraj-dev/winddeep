"""Lifecycle management for Windeep's isolated mitmproxy capture runtime."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Mapping


class CaptureProcessError(RuntimeError):
    """Raised when the isolated capture process cannot be started safely."""


def _creation_flags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


class CaptureProcess:
    """Start/stop the packaged mitmdump process without shell expansion."""

    def __init__(
        self,
        app_root: str | Path,
        *,
        state_dir: str | Path,
        capture_token: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        app_port: int = 7331,
    ) -> None:
        self.app_root = Path(app_root).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.capture_token = capture_token
        self.host = host
        self.port = int(port)
        self.app_port = int(app_port)
        self.process: subprocess.Popen[bytes] | None = None

    def executable(self) -> Path:
        candidates = [
            self.app_root / "runtime" / "capture-python" / "Scripts" / "mitmdump.exe",
            self.app_root / "runtime" / "capture-python" / "Scripts" / "mitmdump",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise CaptureProcessError("pinned mitmdump capture runtime is not installed")

    def command(self) -> list[str]:
        addon = self.app_root / "app" / "capture" / "standalone.py"
        if not addon.exists():
            raise CaptureProcessError(f"capture addon missing: {addon}")
        return [
            str(self.executable()),
            "--listen-host",
            self.host,
            "--listen-port",
            str(self.port),
            "--set",
            "websocket=true",
            "-s",
            str(addon),
        ]

    def environment(self) -> Mapping[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "WINDEEP_STATE_DIR": str(self.state_dir),
                "WINDEEP_CAPTURE_TOKEN": self.capture_token,
                "WINDEEP_RESOLVE_ENDPOINT": f"http://127.0.0.1:{self.app_port}/api/capture/resolve",
                "WINDEEP_EVENT_ENDPOINT": f"http://127.0.0.1:{self.app_port}/api/capture/events",
                "PYTHONPATH": str(self.app_root) + os.pathsep + env.get("PYTHONPATH", ""),
            }
        )
        return env

    def start(self, *, timeout: float = 10.0) -> None:
        if self.is_running():
            return
        if self._port_open():
            raise CaptureProcessError(f"capture port {self.host}:{self.port} is already in use")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(
            self.command(),
            cwd=str(self.app_root),
            env=self.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_creation_flags(),
        )
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                code = self.process.returncode
                self.process = None
                raise CaptureProcessError(f"mitmdump exited during startup with code {code}")
            if self._port_open():
                return
            time.sleep(0.1)
        self.stop()
        raise CaptureProcessError("mitmdump did not open its loopback proxy port before timeout")

    def stop(self, *, timeout: float = 5.0) -> None:
        process = self.process
        self.process = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=max(0.5, timeout))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def status(self) -> dict[str, object]:
        return {
            "running": self.is_running(),
            "host": self.host,
            "port": self.port,
            "runtime_present": self._runtime_present(),
            "pid": self.process.pid if self.is_running() and self.process is not None else None,
        }

    def _runtime_present(self) -> bool:
        try:
            self.executable()
            return True
        except CaptureProcessError:
            return False

    def _port_open(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2):
                return True
        except OSError:
            return False

    def __enter__(self) -> "CaptureProcess":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
