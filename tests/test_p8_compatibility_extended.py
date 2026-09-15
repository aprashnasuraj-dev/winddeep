"""Additional P8 compatibility/migration discipline tests."""
from __future__ import annotations

import pytest

from app.compat import MigrationDiscipline, SchemaCompatibilityRegistry


def test_previous_payload_normalizes_without_changing_reader_acceptance_window() -> None:
    registry = SchemaCompatibilityRegistry()
    payload = registry.normalize("bundle", registry.previous("bundle"), {"finding": 7})
    assert payload["finding"] == 7
    assert payload["_compat"] == {"family": "bundle", "read_version": "1", "writer_version": "2"}


def test_compatibility_manifest_contains_migration_notes_for_every_family() -> None:
    manifest = SchemaCompatibilityRegistry().manifest()
    assert manifest
    assert all(item["migration_note"] for item in manifest.values())
    assert all(item["deprecation"] for item in manifest.values())


def test_migration_discipline_allows_foreign_key_on_delete_but_rejects_destructive_dml() -> None:
    discipline = MigrationDiscipline()
    discipline.validate("CREATE TABLE x(id INTEGER REFERENCES y(id) ON DELETE CASCADE);")
    with pytest.raises(ValueError):
        discipline.validate("DELETE FROM artifacts WHERE scan_id = 1;")
    with pytest.raises(ValueError):
        discipline.validate("DROP TABLE flow_evidence;")
    with pytest.raises(ValueError):
        discipline.validate("ALTER TABLE artifacts DROP COLUMN metadata;")
