"""Authenticated remote execution worker for host-locked Windeep integrations.

The worker never executes arbitrary program names: ``tool`` must exist in the
same Windeep catalog and resolves to that catalog entry's local/provisioned
binary. Transport should use TLS for non-loopback deployments; bearer auth is
mandatory in all cases.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import os
import platform
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools.backends import _exec_process


def host_kind() -> str:
    override = os.getenv("WINDEEP_WORKER_HOST_KIND", "").strip().lower()
    if override:
        return override
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def create_worker_app(registry: str | Path, tools_dir: str | Path, token: str) -> Flask:
    if not token:
        raise ValueError("remote worker token must not be empty")
    classes = ToolWrapperFactory(registry).load()
    tools_root = Path(tools_dir)
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024)

    @app.before_request
    def authenticate():
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        if not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "unauthorized"}), 401
        return None

    @app.get("/v1/health")
    def health():
        return jsonify({"status": "ok", "host_kind": host_kind(), "catalog": len(classes)})

    @app.post("/v1/exec")
    def execute():
        data = request.get_json(silent=True) or {}
        name = str(data.get("tool") or "")
        if name not in classes:
            return jsonify({"error": "unknown catalog tool"}), 404
        argv = data.get("argv") or []
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv) or len(argv) > 256:
            return jsonify({"error": "argv must be a bounded list of strings"}), 400
        timeout = max(1.0, min(float(data.get("timeout", 120.0)), 3600.0))
        stdin_raw = data.get("stdin_b64")
        try:
            stdin = base64.b64decode(stdin_raw, validate=True) if isinstance(stdin_raw, str) else None
        except ValueError:
            return jsonify({"error": "invalid stdin_b64"}), 400
        if stdin is not None and len(stdin) > 8 * 1024 * 1024:
            return jsonify({"error": "stdin exceeds worker limit"}), 413

        cls = classes[name]
        required = str(getattr(cls, "requires_host", "") or "").lower()
        actual = host_kind()
        if required and required not in {actual, "device" if actual == "device" else actual}:
            return jsonify({"error": f"tool requires host={required}; worker is {actual}"}), 409
        wrapper = cls(tools_dir=tools_root, scope_validator=lambda _value: True, environment=os.environ)
        binary = wrapper.resolve_local_binary() or wrapper.resolve_provisioned_binary()
        if binary is None:
            return jsonify({"error": "tool binary is not installed on this worker"}), 409
        try:
            stdout, stderr, rc = asyncio.run(_exec_process([str(binary), *argv], stdin, timeout, env=wrapper.environment))
        except asyncio.TimeoutError:
            return jsonify({"error": "tool execution timed out"}), 504
        except OSError as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({"stdout": stdout, "stderr": stderr, "rc": rc, "host_kind": actual, "tool": name})

    return app


def run_worker(registry: str | Path, tools_dir: str | Path, *, token: str, host: str = "127.0.0.1", port: int = 7441) -> None:
    app = create_worker_app(registry, tools_dir, token)
    cert = os.getenv("WINDEEP_WORKER_TLS_CERT", "").strip()
    key = os.getenv("WINDEEP_WORKER_TLS_KEY", "").strip()
    if host not in {"127.0.0.1", "localhost", "::1"} and not (cert and key):
        raise RuntimeError("non-loopback remote worker requires WINDEEP_WORKER_TLS_CERT and WINDEEP_WORKER_TLS_KEY")
    ssl_context: tuple[str, str] | None = (cert, key) if cert and key else None
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True, ssl_context=ssl_context)
