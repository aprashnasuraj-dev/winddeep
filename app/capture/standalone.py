"""Standalone mitmdump entry point with encrypted persistence and explicit scope resolution.

Loaded by the dedicated Python 3.12 capture runtime, never by the main Python
3.11 process. Target/scan resolution is delegated to the authenticated local
Windeep server. Any resolver failure returns (None, None), so traffic may pass
through the local proxy but is never persisted without an active authorized
scan context.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from app.capture.mitm_addon import CaptureAddon
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase


def _state_dir() -> Path:
    return Path(os.environ.get("WINDEEP_STATE_DIR") or (Path.home() / ".windeep")).resolve()


def _post_json(url: str, payload: dict[str, Any], token: str, *, timeout: float = 2.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-windeep-capture-token": token,
            "x-windeep-source": "capture-runtime",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if int(response.status) != 200:
                return {}
            value = json.loads(response.read().decode("utf-8"))
            return value if isinstance(value, dict) else {}
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return {}


def build_addon() -> CaptureAddon:
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("WINDEEP_CAPTURE_TOKEN", "").strip()
    resolver_url = os.environ.get("WINDEEP_RESOLVE_ENDPOINT", "").strip()
    event_url = os.environ.get("WINDEEP_EVENT_ENDPOINT", "").strip() or None

    crypto = CryptoManager(wrapped_key_path=state / "crypto" / "dek.bin")
    database = SecureDatabase(state / "windeep.db", crypto=crypto)
    flows = SecureFlowDatabase(database)

    def resolve(url: str) -> tuple[int | None, int | None]:
        if not token or not resolver_url:
            return None, None
        result = _post_json(resolver_url, {"url": url}, token)
        target_id = result.get("target_id")
        scan_id = result.get("scan_id")
        if target_id is None:
            return None, None
        try:
            return int(target_id), int(scan_id) if scan_id is not None else None
        except (TypeError, ValueError):
            return None, None

    return CaptureAddon(
        flows,
        event_endpoint=event_url,
        target_resolver=resolve,
    )


addons = [build_addon()]
