"""Native desktop shell for Windeep (no external browser tab).

Runs the local Flask workspace on 127.0.0.1 in a background thread and displays
it inside a native OS window via pywebview (WebView2 on Windows, WebKit on
macOS/Linux). This removes the "opens in a browser tab with a generic/python
icon" behavior: the app gets its own titled, icon-bearing window.

If pywebview is not installed or a window cannot be created (e.g. headless CI),
this falls back to serving the app and opening the default browser, so the app
still runs everywhere.
"""

from __future__ import annotations

import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any

WINDOW_TITLE = "Windeep — Authorized Security Workspace"


def _port() -> int:
    port = int(os.getenv("WINDEEP_PORT", "7331"))
    if port < 1 or port > 65535:
        raise ValueError("WINDEEP_PORT must be between 1 and 65535")
    return port


def _serve_in_background(port: int) -> threading.Thread:
    """Start the Flask app in a daemon thread bound to IPv4 loopback."""
    from app.server import create_app

    def _run() -> None:
        create_app().run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)

    thread = threading.Thread(target=_run, name="windeep-server", daemon=True)
    thread.start()
    return thread


def _wait_until_ready(port: int, *, timeout: float = 20.0) -> bool:
    """Poll the health endpoint until the server answers or timeout elapses."""
    url = f"http://127.0.0.1:{port}/api/health"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0):  # noqa: S310 (loopback only)
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.25)
    return False


def _open_browser_fallback(port: int, *, force_browser: bool = False) -> int:
    import webbrowser

    url = f"http://127.0.0.1:{port}"
    if force_browser or os.getenv("WINDEEP_NO_BROWSER", "").strip().lower() not in {"1", "true", "yes"}:
        webbrowser.open(url)
    print(f"Windeep is running at {url} (press Ctrl+C to stop).")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 130


def run_desktop() -> int:
    """Launch the native desktop window, falling back to the browser if needed."""
    port = _port()
    _serve_in_background(port)
    if not _wait_until_ready(port):
        print("Windeep server did not become ready in time; opening browser fallback.")
        return _open_browser_fallback(port, force_browser=True)

    try:
        import webview  # type: ignore
    except Exception:  # pywebview not installed
        return _open_browser_fallback(port, force_browser=True)

    try:
        icon = _icon_path()
        window_kwargs: dict[str, Any] = {"width": 1440, "height": 920, "min_size": (1024, 680)}
        webview.create_window(WINDOW_TITLE, f"http://127.0.0.1:{port}", **window_kwargs)
        start_kwargs: dict[str, Any] = {}
        if icon:
            start_kwargs["icon"] = icon
        try:
            webview.start(**start_kwargs)
        except TypeError:
            # Older pywebview builds do not accept an icon kwarg.
            webview.start()
        return 0
    except Exception as exc:  # any GUI/runtime failure -> browser fallback
        print(f"Native window unavailable ({exc}); opening browser fallback.")
        return _open_browser_fallback(port, force_browser=True)


def _icon_path() -> str | None:
    from pathlib import Path

    root = Path(os.getenv("WINDEEP_APP_ROOT") or Path(__file__).resolve().parents[1])
    for candidate in (root / "app" / "static" / "windeep.ico", root / "installer" / "windeep.ico"):
        if candidate.exists():
            return str(candidate)
    return None


if __name__ == "__main__":
    raise SystemExit(run_desktop())
