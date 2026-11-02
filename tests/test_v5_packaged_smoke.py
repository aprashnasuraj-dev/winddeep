"""Exercise the packaged-product smoke client against a local app server."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app.server import create_app
from scripts.audit.windows_product_smoke import run_smoke


def test_smoke_rejects_nonloopback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        run_smoke("https://example.test:443", Path("unused"))


def test_owned_file_scan_and_report_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_smoke(f"http://127.0.0.1:{server.server_port}", tmp_path / "source.txt", timeout=20)
        assert result["status"] == "pass"
        assert len(result["submission_sha256"]) == 64
    finally:
        server.shutdown()
        thread.join(timeout=5)
