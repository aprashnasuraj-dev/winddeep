"""Subprocess helpers for desktop-safe Windows execution.

Windeep's GUI is packaged as a windowed executable. Any console child spawned
without CREATE_NO_WINDOW can flash a taskbar/console window and, when catalog
probing fans out across many tools, make startup appear frozen.
"""
from __future__ import annotations

import os
import subprocess
from typing import Any


def hidden_process_kwargs(*, windows: bool | None = None) -> dict[str, Any]:
    """Return subprocess kwargs that suppress child console windows on Windows."""
    use_windows = os.name == "nt" if windows is None else bool(windows)
    if not use_windows:
        return {}
    return {"creationflags": int(getattr(subprocess, "CREATE_NO_WINDOW", 0))}
