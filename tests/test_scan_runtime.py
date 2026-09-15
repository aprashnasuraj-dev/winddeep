"""Tests for scheduler-owned Flask scan worker registration."""
from __future__ import annotations

import threading
import time

import pytest

from app.engine.scan_runtime import RegisteredScanRuntime


def test_runtime_registers_and_drains_worker() -> None:
    runtime = RegisteredScanRuntime()
    entered = threading.Event()
    release = threading.Event()

    def worker(value: int) -> None:
        assert value == 7
        entered.set()
        release.wait(timeout=2)

    thread = runtime.start(11, worker, args=(7,))
    assert entered.wait(timeout=1)
    assert thread.name == "windeep-scheduler-scan-11"
    assert runtime.active_scan_ids() == (11,)
    release.set()
    assert runtime.join(11, timeout=1) is True
    # The owned wrapper unregisters itself on the same code path that exits.
    deadline = time.monotonic() + 1
    while runtime.active_scan_ids() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert runtime.active_scan_ids() == ()
    assert runtime.join(11, timeout=0) is True


def test_runtime_rejects_duplicate_live_scan_id() -> None:
    runtime = RegisteredScanRuntime()
    release = threading.Event()
    entered = threading.Event()

    def worker() -> None:
        entered.set()
        release.wait(timeout=2)

    runtime.start(9, worker, args=())
    assert entered.wait(timeout=1)
    with pytest.raises(RuntimeError, match="already has a registered worker"):
        runtime.start(9, worker, args=())
    release.set()
    assert runtime.join(9, timeout=1) is True
