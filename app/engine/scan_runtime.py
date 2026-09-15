"""Registered background scan-thread runtime for Flask request handoff."""
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any


class RegisteredScanRuntime:
    """Own every background scan thread and expose leak diagnostics."""

    def __init__(self) -> None:
        self._threads: dict[int, threading.Thread] = {}
        self._lock = threading.Lock()

    def start(self, scan_id: int, target: Callable[..., Any], *, args: tuple[Any, ...]) -> threading.Thread:
        """Register a scan before starting its thread; duplicate IDs are rejected."""
        with self._lock:
            existing = self._threads.get(scan_id)
            if existing is not None and existing.is_alive():
                raise RuntimeError(f"scan {scan_id} already has a registered worker")

            def owned() -> None:
                try:
                    target(*args)
                finally:
                    with self._lock:
                        current = self._threads.get(scan_id)
                        if current is threading.current_thread():
                            self._threads.pop(scan_id, None)

            thread = threading.Thread(
                target=owned,
                daemon=True,
                name=f"windeep-scheduler-scan-{scan_id}",
            )
            self._threads[scan_id] = thread
            thread.start()
            return thread

    def active_scan_ids(self) -> tuple[int, ...]:
        """Return live registered scan IDs for operational cleanup checks."""
        with self._lock:
            stale = [scan_id for scan_id, thread in self._threads.items() if not thread.is_alive()]
            for scan_id in stale:
                self._threads.pop(scan_id, None)
            return tuple(sorted(self._threads))

    def join(self, scan_id: int, timeout: float | None = None) -> bool:
        """Join one registered thread and report whether it drained."""
        with self._lock:
            thread = self._threads.get(scan_id)
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()
