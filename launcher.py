"""Windows entry point for Windeep.

The launcher imports the application server lazily so PyInstaller can package a
stable executable while the server implementation evolves independently.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable


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
        result = _resolve_main()()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Windeep failed to start: {exc}", file=sys.stderr)
        return 1
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
