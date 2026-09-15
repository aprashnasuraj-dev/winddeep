"""Windows entry point for Windeep.

The launcher imports the application server lazily so PyInstaller can package a
stable executable while the server implementation evolves independently.
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable
from pathlib import Path


def _application_root() -> Path:
    """Return the source root or the directory containing packaged Windeep.exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _configure_packaged_environment() -> None:
    """Expose bundled tools/browser/runtime paths without modifying machine PATH."""
    root = _application_root()
    os.chdir(root)
    os.environ.setdefault("WINDEEP_APP_ROOT", str(root))

    path_entries = [root / "tools", root / "runtime" / "python"]
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
    """Resolve the application main function or fail with an actionable error."""
    try:
        module = importlib.import_module("app.server")
    except ModuleNotFoundError as exc:
        if exc.name != "app.server":
            raise
        raise RuntimeError(
            "Windeep server is not installed in this build. Run from a complete "
            "release or install the application package before launching."
        ) from exc

    main = getattr(module, "main", None)
    if not callable(main):
        raise RuntimeError("app.server must expose a callable main() entry point")
    return main


def main() -> int:
    """Launch Windeep and return a process exit code."""
    try:
        _configure_packaged_environment()
        result = _resolve_main()()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Windeep failed to start: {exc}", file=sys.stderr)
        return 1
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
