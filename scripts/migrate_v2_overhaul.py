"""Apply the Windeep v2 runtime migration deterministically.

The migration is idempotent so CI can apply it, test the resulting source tree,
and commit only a verified transformation.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"migration anchor missing in {path}: {old[:100]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def migrate_tool_wrapper() -> None:
    path = ROOT / "app" / "engine" / "tool_wrapper.py"
    replace_once(
        path,
        "class ToolExecutionError(RuntimeError):\n    \"\"\"Raised when an external tool cannot complete successfully.\"\"\"\n\n\nclass ToolWrapperBase:\n",
        "class ToolExecutionError(RuntimeError):\n    \"\"\"Raised when an external tool cannot complete successfully.\"\"\"\n\n\nclass ToolCancelledError(ToolExecutionError):\n    \"\"\"Raised when a user-requested scan stop terminates tool execution.\"\"\"\n\n\nclass ToolWrapperBase:\n",
    )
    replace_once(
        path,
        "        environment: Mapping[str, str] | None = None,\n    ) -> None:\n        self.tools_dir = Path(tools_dir)\n        self.scope_validator = scope_validator\n        self.environment = {**os.environ, **dict(environment or {})}\n        self._rate_lock = asyncio.Lock()\n",
        "        environment: Mapping[str, str] | None = None,\n        cancel_check: Callable[[], bool] | None = None,\n    ) -> None:\n        self.tools_dir = Path(tools_dir)\n        self.scope_validator = scope_validator\n        self.environment = {**os.environ, **dict(environment or {})}\n        self.cancel_check = cancel_check\n        self._rate_lock = asyncio.Lock()\n",
    )
    replace_once(
        path,
        "        try:\n            if self.requires_scope and self.scope_validator is None:\n",
        "        try:\n            if self._cancel_requested():\n                raise ToolCancelledError(f\"{self.tool_name} cancelled before execution\")\n            if self.requires_scope and self.scope_validator is None:\n",
    )
    replace_once(
        path,
        "            if builtin_integrations.supports(self.tool_name):\n                rows = await builtin_integrations.run(self.tool_name, target, environment=self.environment)\n                return [Finding.model_validate(row) for row in rows]\n",
        "            if builtin_integrations.supports(self.tool_name):\n                rows = await self._await_with_cancel(\n                    builtin_integrations.run(self.tool_name, target, environment=self.environment),\n                    timeout=self.timeout,\n                )\n                return [Finding.model_validate(row) for row in rows]\n",
    )
    replace_once(
        path,
        "            for attempt in range(self.retries + 1):\n                try:\n                    await self._respect_rate_limit()\n",
        "            for attempt in range(self.retries + 1):\n                try:\n                    if self._cancel_requested():\n                        raise ToolCancelledError(f\"{self.tool_name} cancelled by user\")\n                    await self._respect_rate_limit()\n",
    )
    replace_once(
        path,
        "                except asyncio.CancelledError:\n                    raise\n                except (ToolExecutionError, asyncio.TimeoutError, OSError) as exc:\n",
        "                except (ToolCancelledError, asyncio.CancelledError):\n                    raise\n                except (ToolExecutionError, asyncio.TimeoutError, OSError) as exc:\n",
    )
    replace_once(
        path,
        "    def _render_args(self, values: Mapping[str, Any]) -> list[str]:\n",
        "    def _cancel_requested(self) -> bool:\n        if self.cancel_check is None:\n            return False\n        try:\n            return bool(self.cancel_check())\n        except Exception:\n            return False\n\n    async def _await_with_cancel(self, awaitable: Any, *, timeout: float) -> Any:\n        task = asyncio.create_task(awaitable)\n        started = time.monotonic()\n        try:\n            while True:\n                if self._cancel_requested():\n                    task.cancel()\n                    await asyncio.gather(task, return_exceptions=True)\n                    raise ToolCancelledError(f\"{self.tool_name} cancelled by user\")\n                remaining = timeout - (time.monotonic() - started)\n                if remaining <= 0:\n                    task.cancel()\n                    await asyncio.gather(task, return_exceptions=True)\n                    raise asyncio.TimeoutError\n                done, _pending = await asyncio.wait({task}, timeout=min(0.2, remaining))\n                if task in done:\n                    return await task\n        except asyncio.CancelledError:\n            task.cancel()\n            await asyncio.gather(task, return_exceptions=True)\n            raise\n\n    def _render_args(self, values: Mapping[str, Any]) -> list[str]:\n",
    )
    replace_once(
        path,
        "        try:\n            stdout, stderr = await asyncio.wait_for(process.communicate(stdin_data), timeout=self.timeout)\n        except asyncio.CancelledError:\n            process.kill()\n            await process.wait()\n            raise\n        except asyncio.TimeoutError:\n            process.kill()\n            await process.wait()\n            raise\n",
        "        try:\n            stdout, stderr = await self._await_with_cancel(process.communicate(stdin_data), timeout=self.timeout)\n        except (ToolCancelledError, asyncio.CancelledError):\n            if process.returncode is None:\n                process.kill()\n                await process.wait()\n            raise\n        except asyncio.TimeoutError:\n            if process.returncode is None:\n                process.kill()\n                await process.wait()\n            raise\n",
    )


def migrate_server() -> None:
    path = ROOT / "app" / "server.py"
    replace_once(
        path,
        "from app.tools.release_metadata import apply_release_metadata\n",
        "from app.tools.release_metadata import apply_release_metadata\nfrom app.v2_api import register_v2_api\n",
    )
    # V3-C inserts its registration between the existing v2 registration and
    # the index route, so the old contiguous replacement marker is no longer a
    # reliable idempotency check. Detect the installed registrar directly.
    server_text = path.read_text(encoding="utf-8")
    if "    register_v2_api(\n" not in server_text:
        replace_once(
            path,
            "    @app.get(\"/\")\n    def index() -> Response:\n",
            "    register_v2_api(\n        app,\n        root=root,\n        state=state,\n        tools_dir=tools_dir,\n        crypto=crypto,\n        audit=audit,\n        consent=consent,\n        database=database,\n        wrapper_classes=wrapper_classes,\n        authenticated=authenticated,\n        broadcast=broadcast,\n        target_scope=target_scope,\n        preflight_for=preflight_for,\n    )\n\n    @app.get(\"/\")\n    def index() -> Response:\n",
        )
    replace_once(
        path,
        "    Timer(0.8, lambda: webbrowser.open(f\"http://127.0.0.1:{port}\")).start()\n",
        "    if os.getenv(\"WINDEEP_NO_BROWSER\", \"\").strip().lower() not in {\"1\", \"true\", \"yes\"}:\n        Timer(0.8, lambda: webbrowser.open(f\"http://127.0.0.1:{port}\")).start()\n",
    )


def migrate_catalog_metadata() -> None:
    mappings = {
        "recon_passive.json": ["domain", "url", "host", "web"],
        "recon_active.json": ["domain", "url", "host", "web"],
        "web_vulns.json": ["url", "domain", "host", "web"],
        "mobile.json": ["apk", "ipa", "package", "mobile"],
        "web3.json": ["contract", "repo", "file", "web3"],
        "secrets.json": ["repo", "file", "url", "web"],
        "network.json": ["host", "domain", "url", "web"],
        "utilities.json": ["domain", "url", "host", "repo", "file", "apk", "ipa", "contract", "web", "mobile", "web3"],
    }
    builtin_names = {"crtsh", "shodan", "censys", "etherscan", "corellium", "mobsf", "remix", "custom_regex"}
    interactive = {
        "jadx_gui", "burp", "burpsuite", "zap", "owasp_zap", "wireshark", "metasploit",
        "recon_ng", "remix", "corellium", "frida_server", "checkra1n", "needle", "appmon",
    }
    config_dir = ROOT / "app" / "tools" / "config"
    total = 0
    for filename, target_types in mappings.items():
        path = config_dir / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        tools = data.get("tools")
        if not isinstance(tools, dict):
            raise RuntimeError(f"invalid tools object: {path}")
        for name, definition in tools.items():
            if not isinstance(definition, dict):
                raise RuntimeError(f"invalid tool definition: {name}")
            total += 1
            definition["target_types"] = list(target_types)
            definition["runtime_strategy"] = "builtin" if name in builtin_names else "process"
            definition["ui_group"] = filename.removesuffix(".json")
            support = str(definition.get("release_support") or "runtime")
            default = filename != "utilities.json" and name not in interactive
            if support == "unsupported" and name not in builtin_names:
                default = False
            definition["scan_default"] = bool(default)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if total != 137:
        raise RuntimeError(f"v2 catalog migration expected 137 tools, found {total}")


def main() -> int:
    migrate_tool_wrapper()
    migrate_server()
    migrate_catalog_metadata()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
