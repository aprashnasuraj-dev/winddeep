"""Regression tests for the v3 compatibility audit's version floor."""
from __future__ import annotations

from pathlib import Path

from scripts.audit import release_audit_v3


def _write_release(root: Path, version: str, *, include_phase_map: bool = True) -> None:
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
    markers = ["## [3.0.0]", "### Breaking changes", "P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"]
    body = "\n".join(markers if include_phase_map else markers[:-1])
    (root / "CHANGELOG.md").write_text(body + "\n", encoding="utf-8")


def test_v3_release_audit_accepts_later_semver_with_preserved_phase_map(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _write_release(tmp_path, "4.1.1")
    monkeypatch.setattr(release_audit_v3, "ROOT", tmp_path)

    check = release_audit_v3.version_changelog_check()

    assert check.ok is True
    assert "compatibility floor=satisfied" in check.detail
    assert "v3 phase map=present" in check.detail


def test_v3_release_audit_rejects_pre_v3_or_incomplete_phase_map(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _write_release(tmp_path, "2.9.9")
    monkeypatch.setattr(release_audit_v3, "ROOT", tmp_path)
    assert release_audit_v3.version_changelog_check().ok is False

    _write_release(tmp_path, "4.1.1", include_phase_map=False)
    assert release_audit_v3.version_changelog_check().ok is False
