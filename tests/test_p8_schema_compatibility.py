"""P8 acceptance tests for migration safety, schema compatibility, and API versioning."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.migrations import MigrationManager, MigrationSafetyError
from app.schema_compat import (
    APICompatibility,
    SchemaCompatibilityError,
    SchemaCompatibilityRegistry,
    VersionedEnvelopeCodec,
)
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "app" / "data" / "migrations"
DOWN = ROOT / "app" / "data" / "migrations_down"


def _db(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    manager = MigrationManager(database.path, MIGRATIONS, backup_dir=tmp_path / "backups", down_migrations_dir=DOWN)
    manager.apply()
    return database, manager


def test_versioned_envelope_reads_current_and_previous_but_writes_current_only() -> None:
    codec = VersionedEnvelopeCodec(current_version=2, previous_version=1)
    encoded = codec.encode({"finding_id": 7, "state": "observed"})
    parsed = json.loads(encoded)
    assert parsed["schema_version"] == 2
    assert codec.decode(encoded) == {"finding_id": 7, "state": "observed"}
    previous = json.dumps({"schema_version": 1, "payload": {"finding_id": 6, "state": "observed"}}, sort_keys=True, separators=(",", ":"))
    assert codec.decode(previous) == {"finding_id": 6, "state": "observed"}
    with pytest.raises(SchemaCompatibilityError, match="unsupported schema version"):
        codec.decode(json.dumps({"schema_version": 0, "payload": {}}))
    with pytest.raises(SchemaCompatibilityError, match="writers emit only"):
        codec.encode({"x": 1}, version=1)


def test_api_compatibility_declares_current_previous_and_deprecation_window() -> None:
    contract = APICompatibility.default()
    assert contract.current == "v2"
    assert contract.previous == "v1"
    assert contract.supported_read_versions == ("v1", "v2")
    assert contract.writer_version == "v2"
    assert contract.is_supported("v1") is True
    assert contract.is_supported("v2") is True
    assert contract.is_supported("v0") is False
    metadata = contract.metadata()
    assert metadata["deprecation"]["version"] == "v1"
    assert metadata["deprecation"]["replacement"] == "v2"
    assert metadata["deprecation"]["migration_note"]
    assert "breaking" in metadata["deprecation"]["policy"].casefold()


def test_schema_registry_matches_persisted_p8_contract(tmp_path: Path) -> None:
    database, _manager = _db(tmp_path)
    registry = SchemaCompatibilityRegistry(database)
    contract = registry.get("core")
    assert contract["writer_version"] == 2
    assert contract["min_reader_version"] == 1
    assert contract["current_reader_version"] == 2
    assert contract["api_version"] == "v2"
    assert contract["previous_api_version"] == "v1"
    assert registry.can_read("core", 1)
    assert registry.can_read("core", 2)
    assert not registry.can_read("core", 0)
    assert registry.can_write("core", 2)
    assert not registry.can_write("core", 1)


def test_safe_down_migration_preserves_findings_and_can_be_reapplied(tmp_path: Path) -> None:
    database, manager = _db(tmp_path)
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    finding_id, _ = database.create_finding(
        target_id,
        "Evidence survives rollback",
        "medium",
        vuln_type="fixture",
        tool="fixture",
        endpoint="https://example.test/",
        evidence={"proof": "retained"},
    )
    rollback = manager.rollback(target_version=7)
    assert rollback.from_version == 8
    assert rollback.target_version == 7
    assert rollback.reverted_versions == (8,)
    assert database.get_finding(finding_id) is not None
    with database._connect() as conn:
        applied = [int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
        row = conn.execute("SELECT COUNT(*) FROM schema_compatibility").fetchone()
    assert max(applied) == 7
    assert row[0] == 0

    reapplied = manager.apply()
    assert reapplied.target_version == 8
    assert database.get_finding(finding_id) is not None
    assert SchemaCompatibilityRegistry(database).get("core")["writer_version"] == 2


def test_rollback_requires_paired_down_migration_and_refuses_destructive_sql(tmp_path: Path) -> None:
    database, _manager = _db(tmp_path)
    custom_down = tmp_path / "down"
    custom_down.mkdir()
    (custom_down / "0008_p8_schema_compatibility.sql").write_text("DROP TABLE findings;\n", encoding="utf-8")
    manager = MigrationManager(database.path, MIGRATIONS, backup_dir=tmp_path / "backups2", down_migrations_dir=custom_down)
    with pytest.raises(MigrationSafetyError, match="destructive"):
        manager.rollback(target_version=7)

    empty_down = tmp_path / "empty-down"
    empty_down.mkdir()
    manager = MigrationManager(database.path, MIGRATIONS, backup_dir=tmp_path / "backups3", down_migrations_dir=empty_down)
    with pytest.raises(MigrationSafetyError, match="missing down migration"):
        manager.rollback(target_version=7)


def test_down_validator_blocks_evidence_deletes_and_drop_columns(tmp_path: Path) -> None:
    database, _manager = _db(tmp_path)
    cases = (
        "DELETE FROM findings;",
        "ALTER TABLE findings DROP COLUMN evidence;",
        "TRUNCATE TABLE artifacts;",
        "DROP TABLE scan_events;",
    )
    for index, sql in enumerate(cases):
        down = tmp_path / f"down-{index}"
        down.mkdir()
        (down / "0008_p8_schema_compatibility.sql").write_text(sql, encoding="utf-8")
        manager = MigrationManager(database.path, MIGRATIONS, backup_dir=tmp_path / f"backups-{index}", down_migrations_dir=down)
        with pytest.raises(MigrationSafetyError):
            manager.rollback(target_version=7)


def test_p8_documentation_and_v3_version_contract() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "schema_compatibility.md").read_text(encoding="utf-8").casefold()
    assert version == "3.0.0"
    assert "## [3.0.0]" in changelog
    assert "current + previous" in docs
    assert "writers" in docs and "current" in docs
    assert "deprecation" in docs
    assert "down migration" in docs
    assert "evidence" in docs
