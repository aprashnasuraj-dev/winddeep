"""P8 acceptance: versioned evidence/API schemas and non-destructive migration discipline."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.compat import MigrationDiscipline, SchemaCompatibilityRegistry, UnsupportedSchemaVersion

ROOT = Path(__file__).resolve().parents[1]


def test_readers_accept_current_and_previous_writers_emit_current() -> None:
    registry = SchemaCompatibilityRegistry()
    for name in ("artifact", "bundle", "flow", "redaction_map", "sse", "report", "har_extension"):
        current = registry.current(name)
        previous = registry.previous(name)
        assert registry.accepts(name, current)
        assert registry.accepts(name, previous)
        assert registry.writer_version(name) == current
        assert not registry.accepts(name, str(int(previous) - 1)) if previous.isdigit() and int(previous) > 0 else True


def test_unknown_or_too_old_schema_fails_closed() -> None:
    registry = SchemaCompatibilityRegistry()
    with pytest.raises(KeyError):
        registry.current("unknown")
    with pytest.raises(UnsupportedSchemaVersion):
        registry.require("artifact", "99")


def test_public_api_versions_have_deprecation_window_metadata() -> None:
    registry = SchemaCompatibilityRegistry()
    manifest = registry.manifest()
    for name in ("sse", "report", "har_extension"):
        assert manifest[name]["current"]
        assert manifest[name]["previous"]
        assert manifest[name]["deprecation"]


def test_all_migrations_pass_non_destructive_evidence_audit() -> None:
    discipline = MigrationDiscipline()
    for path in sorted((ROOT / "app" / "data" / "migrations").glob("*.sql")):
        discipline.validate(path.read_text(encoding="utf-8"), path=str(path))


def test_v3_down_migration_is_present_and_never_drops_evidence() -> None:
    down = ROOT / "app" / "data" / "migrations_down" / "0006_v3_runtime.sql"
    assert down.exists()
    text = down.read_text(encoding="utf-8")
    MigrationDiscipline().validate(text, path=str(down), down=True)
    lowered = text.casefold()
    assert "drop table" not in lowered
    assert "delete from artifacts" not in lowered
    assert "delete from flow_evidence" not in lowered
