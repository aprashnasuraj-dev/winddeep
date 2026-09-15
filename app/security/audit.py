"""Append-only tamper-evident audit log for Windeep security actions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Mapping


class AuditLog:
    """Write hash-chained JSON Lines records and verify chain integrity."""

    def __init__(self, path: str | Path = "state/audit/audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.touch()

    @staticmethod
    def _canonical(value: Mapping[str, Any]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def append(self, event: str, data: Mapping[str, Any] | None = None) -> str:
        """Append an event and return the record hash."""
        event = event.strip()
        if not event:
            raise ValueError("event must not be empty")
        payload = dict(data or {})
        with self._lock:
            previous = self._last_hash_unlocked()
            if previous == "INVALID":
                raise RuntimeError("audit log is corrupt; refusing to append")
            record = {"ts": time.time(), "event": event, "data": payload, "prev_hash": previous}
            digest = hashlib.sha256(previous.encode("ascii") + self._canonical(record)).hexdigest()
            record["hash"] = digest
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            return digest

    def _last_hash_unlocked(self) -> str:
        last = "0" * 64
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = str(json.loads(line)["hash"])
                except (json.JSONDecodeError, KeyError, TypeError):
                    return "INVALID"
        return last

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the complete audit chain and return ``(ok, record_count)``."""
        previous = "0" * 64
        count = 0
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    supplied_hash = str(record.pop("hash"))
                except (json.JSONDecodeError, KeyError, TypeError):
                    return False, count
                if record.get("prev_hash") != previous:
                    return False, count
                expected = hashlib.sha256(previous.encode("ascii") + self._canonical(record)).hexdigest()
                if not hmac.compare_digest(expected, supplied_hash):
                    return False, count
                previous = supplied_hash
                count += 1
        return True, count

    def healthcheck(self) -> dict[str, object]:
        """Return audit-log health for the pre-flight gate."""
        ok, count = self.verify_chain()
        return {"ok": ok, "records": count, "path": str(self.path)}
