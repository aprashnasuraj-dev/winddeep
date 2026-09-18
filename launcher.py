"""Windows/package entry point for Windeep.

With no management subcommand the launcher starts the local dashboard.  Runtime
management commands (doctor, bundle, remote-worker) are routed to the v4 CLI.
"""
from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable
from pathlib import Path


def _application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _configure_packaged_environment() -> None:
    root = _application_root()
    os.chdir(root)
    os.environ.setdefault("WINDEEP_APP_ROOT", str(root))
    path_entries = [root / "tools", root / "tools" / "provisioned" / "bin", root / "runtime" / "python"]
    existing = os.environ.get("PATH", "")
    os.environ["PATH"] = os.pathsep.join([*(str(path) for path in path_entries if path.exists()), existing])
    browsers = root / "runtime" / "playwright-browsers"
    if browsers.exists():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(browsers))
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_GC", "1")
    if os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA", root)) / "Windeep"
        state = local / "state"
        state.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("WINDEEP_STATE_DIR", str(state))


def _resolve_main() -> Callable[[], int | None]:
    try:
        module = importlib.import_module("app.server")
    except ModuleNotFoundError as exc:
        if exc.name != "app.server":
            raise
        raise RuntimeError("Windeep server is not installed in this build.") from exc
    main = getattr(module, "main", None)
    if not callable(main):
        raise RuntimeError("app.server must expose a callable main() entry point")
    return main


def main() -> int:
    try:
        _configure_packaged_environment()
        if len(sys.argv) > 1 and sys.argv[1] in {"doctor", "bundle", "remote-worker"}:
            from app.tools.cli import main as cli_main
            return int(cli_main(sys.argv[1:]) or 0)

        # UI mode selection (WINDEEP_UI): "desktop" (default) opens a native
        # window with no browser tab; "browser" opens the default browser;
        # "server" runs headless (no window, no browser).
        mode = os.getenv("WINDEEP_UI", "desktop").strip().lower()
        if len(sys.argv) > 1 and sys.argv[1] in {"desktop", "browser", "server"}:
            mode = sys.argv[1]
        if mode == "server":
            os.environ["WINDEEP_NO_BROWSER"] = "1"
            result = _resolve_main()()
        elif mode == "browser":
            result = _resolve_main()()
        else:
            # Native desktop window; never launch an external browser tab.
            os.environ.setdefault("WINDEEP_NO_BROWSER", "1")
            from app.desktop import run_desktop
            result = run_desktop()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Windeep failed to start: {exc}", file=sys.stderr)
        return 1
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
