"""Smoke tests for the bootstrap server and version helper."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.server import create_app
from scripts.bump_version import set_version


def test_health_endpoint() -> None:
    client = create_app().test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_root_is_local_dashboard_bootstrap() -> None:
    client = create_app().test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"Windeep" in response.data


def test_set_version_accepts_semver(tmp_path: Path) -> None:
    set_version("1.2.3", tmp_path)
    assert (tmp_path / "VERSION").read_text(encoding="utf-8") == "1.2.3\n"


def test_set_version_accepts_prerelease(tmp_path: Path) -> None:
    set_version("1.2.3-rc.1", tmp_path)
    assert "1.2.3-rc.1" in (tmp_path / "VERSION").read_text(encoding="utf-8")


def test_set_version_rejects_invalid_semver(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        set_version("v1.2", tmp_path)
