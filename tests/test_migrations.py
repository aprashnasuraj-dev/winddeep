"""Tests for Windeep's forward-only SQLite migration system."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.migrations import MigrationChecksumError, MigrationManager, MigrationOrderError


def _write(directory: Path, name: str, sql: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(sql, encoding="utf-8")


def test_dry_run_does_not_create_database(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    _write(migrations, "0001_first.sql", "CREATE TABLE alpha(id INTEGER PRIMARY KEY);")
    database = tmp_path / "app.db"
    plan = MigrationManager(database, migrations).dry_run()
    assert plan.current_version == 0
    assert plan.target_version == 1
    assert not database.exists()


def test_apply_creates_ledger_and_schema(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    _write(migrations, "0001_first.sql", "CREATE TABLE alpha(id INTEGER PRIMARY KEY);")
    database = tmp_path / "app.db"
    manager = MigrationManager(database, migrations)
    manager.apply()
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT 1 FROM alpha LIMIT 1").fetchone() is None
        row = conn.execute("SELECT version, name FROM schema_migrations").fetchone()
    assert row == (1, "first")


def test_existing_database_is_backed_up_before_change(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE original(value TEXT)")
        conn.execute("INSERT INTO original(value) VALUES (?)", ("keep-me",))
    migrations = tmp_path / "migrations"
    _write(migrations, "0001_new.sql", "CREATE TABLE added(id INTEGER);")
    backups = tmp_path / "backups"
    MigrationManager(database, migrations, backup_dir=backups).apply()
    files = list(backups.glob("*.sqlite3"))
    assert len(files) == 1
    with sqlite3.connect(files[0]) as conn:
        assert conn.execute("SELECT value FROM original").fetchone()[0] == "keep-me"


def test_changed_applied_migration_checksum_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    migrations = tmp_path / "migrations"
    path = migrations / "0001_first.sql"
    _write(migrations, path.name, "CREATE TABLE alpha(id INTEGER PRIMARY KEY);")
    manager = MigrationManager(database, migrations)
    manager.apply()
    path.write_text("CREATE TABLE alpha(id INTEGER PRIMARY KEY, changed TEXT);", encoding="utf-8")
    with pytest.raises(MigrationChecksumError):
        manager.plan()


def test_new_older_version_is_rejected_after_forward_progress(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    migrations = tmp_path / "migrations"
    _write(migrations, "0002_second.sql", "CREATE TABLE beta(id INTEGER);")
    manager = MigrationManager(database, migrations)
    manager.apply()
    _write(migrations, "0001_late.sql", "CREATE TABLE late(id INTEGER);")
    with pytest.raises(MigrationOrderError):
        manager.plan()


def test_second_migration_advances_from_existing_version(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    migrations = tmp_path / "migrations"
    _write(migrations, "0001_first.sql", "CREATE TABLE alpha(id INTEGER);")
    manager = MigrationManager(database, migrations)
    manager.apply()
    _write(migrations, "0002_second.sql", "CREATE TABLE beta(id INTEGER);")
    plan = manager.apply()
    assert plan.current_version == 1
    assert plan.target_version == 2
    with sqlite3.connect(database) as conn:
        versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert versions == [1, 2]
