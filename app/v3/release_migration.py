"""Loader for the single Python-backed v3 release migration."""
from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


@dataclass(frozen=True, slots=True)
class V3MigrationResult:
    version: int
    name: str
    direction: str
    checksum: str


def _path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "migrations" / "0030_v3_release.py"


def _load() -> tuple[ModuleType, str]:
    path = _path()
    raw = path.read_bytes()
    checksum = hashlib.sha256(raw).hexdigest()
    spec = importlib.util.spec_from_file_location("windeep_v3_release_migration", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load v3 release migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if int(getattr(module, "VERSION", -1)) != 30 or str(getattr(module, "NAME", "")) != "v3_release":
        raise RuntimeError("0030_v3_release.py identity mismatch")
    return module, checksum


def apply_v3_release_migration(database_path: str | Path) -> V3MigrationResult:
    module, checksum = _load()
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with sqlite3.connect(path, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.executescript(str(module.UP_SQL))
        row = conn.execute("SELECT checksum, active FROM v3_release_migrations WHERE version = 30").fetchone()
        if row is not None and str(row["checksum"]) != checksum:
            raise RuntimeError("v3 release migration checksum changed after application")
        conn.execute(
            """
            INSERT INTO v3_release_migrations(version, name, checksum, active, applied_at, reverted_at)
            VALUES (30, 'v3_release', ?, 1, ?, NULL)
            ON CONFLICT(version) DO UPDATE SET active=1, applied_at=excluded.applied_at, reverted_at=NULL
            """,
            (checksum, now),
        )
    return V3MigrationResult(30, "v3_release", "up", checksum)


def revert_v3_release_migration(database_path: str | Path) -> V3MigrationResult:
    module, checksum = _load()
    path = Path(database_path)
    if not path.exists():
        raise RuntimeError("cannot revert v3 release migration on a missing database")
    with sqlite3.connect(path, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        row = conn.execute("SELECT checksum FROM v3_release_migrations WHERE version = 30").fetchone()
        if row is None:
            raise RuntimeError("v3 release migration is not applied")
        if str(row["checksum"]) != checksum:
            raise RuntimeError("v3 release migration checksum mismatch")
        conn.executescript(str(module.DOWN_SQL))
    return V3MigrationResult(30, "v3_release", "down", checksum)
