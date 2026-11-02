"""Regression coverage for deterministic legacy-v2 source migrations."""
from __future__ import annotations

from pathlib import Path

from scripts import migrate_v2_overhaul, migrate_v2_ui_selection


def test_migrate_tool_wrapper_noops_on_current_cancellable_runtime(
    monkeypatch,
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "app" / "engine" / "tool_wrapper.py").read_text(encoding="utf-8")
    assert migrate_v2_overhaul._has_cancellable_runtime(source)

    target = tmp_path / "app" / "engine" / "tool_wrapper.py"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")

    monkeypatch.setattr(migrate_v2_overhaul, "ROOT", tmp_path)
    migrate_v2_overhaul.migrate_tool_wrapper()

    assert target.read_text(encoding="utf-8") == source


def test_ui_selection_migration_preserves_current_preview(monkeypatch, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "app" / "static" / "app.js").read_text(encoding="utf-8")
    target = tmp_path / "app.js"
    target.write_text(source, encoding="utf-8")
    monkeypatch.setattr(migrate_v2_ui_selection, "APP_JS", target)

    assert migrate_v2_ui_selection.main() == 0
    assert target.read_text(encoding="utf-8") == source


def test_ui_selection_migration_still_upgrades_legacy_preview(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "app.js"
    target.write_text(
        migrate_v2_ui_selection.OLD_PREVIEW + "\n" + migrate_v2_ui_selection.OLD_START,
        encoding="utf-8",
    )
    monkeypatch.setattr(migrate_v2_ui_selection, "APP_JS", target)
    assert migrate_v2_ui_selection.main() == 0
    migrated = target.read_text(encoding="utf-8")
    assert migrate_v2_ui_selection.NEW_PREVIEW in migrated
    assert migrate_v2_ui_selection.NEW_START in migrated
    assert migrate_v2_ui_selection.main() == 0
    assert target.read_text(encoding="utf-8") == migrated
