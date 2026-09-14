"""Bootstrap local Windeep HTTP server.

This module provides the stable health/bootstrap surface needed by the
repository and packaging pipeline. Application APIs are expanded in later
implementation phases without changing the launcher contract.
"""

from __future__ import annotations

import os
import webbrowser
from threading import Timer

from flask import Flask, jsonify


def create_app() -> Flask:
    """Create the bootstrap Flask application."""
    app = Flask(__name__)

    @app.get("/api/health")
    def health() -> tuple[object, int]:
        return jsonify({"status": "ok", "service": "windeep", "phase": "bootstrap"}), 200

    @app.get("/")
    def index() -> tuple[str, int, dict[str, str]]:
        body = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Windeep</title>"
            "<style>body{background:#0a0e17;color:#e5e7eb;font-family:system-ui;"
            "max-width:760px;margin:10vh auto;padding:24px}code{color:#67e8f9}</style>"
            "</head><body><h1>Windeep</h1><p>Core bootstrap is running.</p>"
            "<p>Health endpoint: <code>/api/health</code></p></body></html>"
        )
        return body, 200, {"Content-Type": "text/html; charset=utf-8"}

    return app


def main() -> int:
    """Run the local-only Windeep bootstrap server."""
    host = os.getenv("WINDEEP_HOST", "127.0.0.1")
    port = int(os.getenv("WINDEEP_PORT", "7331"))
    if host in {"127.0.0.1", "localhost", "::1"}:
        Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    create_app().run(host=host, port=port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
