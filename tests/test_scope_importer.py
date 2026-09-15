"""Tests for Windeep bug-bounty program scope importers."""

from __future__ import annotations

import json

import httpx
import pytest

from app.database import Database
from app.migrations import MigrationManager
from app.programs.scope_importer import ProgramAsset, ProgramScopeImporter, ProgramScopeRepository, ScopeSnapshotStore
from app.security.crypto import CryptoManager, FileProtector


def _parts(tmp_path, handler):
    database = Database(tmp_path / "windeep.db")
    MigrationManager(database.path, "app/data/migrations", backup_dir=tmp_path / "backups").apply()
    crypto = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=FileProtector(tmp_path / "master.key"))
    snapshots = ScopeSnapshotStore(crypto, tmp_path / "snapshots")
    repository = ProgramScopeRepository(database)
    importer = ProgramScopeImporter(repository, snapshots, transport=httpx.MockTransport(handler))
    return repository, snapshots, importer


@pytest.mark.asyncio
async def test_hackerone_structured_scope_import(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/hackers/programs/demo"):
            return httpx.Response(200, json={"data": {"id": "demo", "attributes": {"name": "Demo"}}})
        if path.endswith("/structured_scopes"):
            return httpx.Response(200, json={"data": [
                {"attributes": {"asset_identifier": "*.example.com", "asset_type": "WILDCARD", "eligible_for_submission": True, "max_severity": "critical", "instruction": "Web only"}},
                {"attributes": {"asset_identifier": "admin.example.com", "asset_type": "DOMAIN", "eligible_for_submission": False}},
            ], "links": {"next": None}})
        if path.endswith("/scope_exclusions"):
            return httpx.Response(200, json={"data": []})
        return httpx.Response(404)

    repository, snapshots, importer = _parts(tmp_path, handler)
    result = await importer.import_hackerone("demo", api_username="user", api_token="token")
    assert len(result.assets) == 2
    assert result.assets[0].max_severity == "critical"
    scope = repository.to_scope_enforcer("hackerone", "demo")
    assert scope.is_allowed("api.example.com")
    assert not scope.is_allowed("admin.example.com")
    snapshot = snapshots.load(result.snapshot_path)
    assert "structured_scopes" in snapshot


@pytest.mark.asyncio
async def test_intigriti_import_preserves_testing_requirements(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        return httpx.Response(200, json={
            "handle": "intigriti-demo",
            "name": "Demo",
            "domains": {"content": [
                {"endpoint": "https://app.example.com", "type": {"value": "url"}, "description": "Primary app"}
            ]},
            "rulesOfEngagement": {"content": {"testingRequirements": {"automatedTooling": {"allowed": True, "maxRequestsPerSecond": 5}}}},
            "webLinks": {"detail": "https://app.intigriti.com/programs/demo"},
        })

    repository, _, importer = _parts(tmp_path, handler)
    result = await importer.import_intigriti("program-id", bearer_token="secret")
    assert result.program_handle == "intigriti-demo"
    assert result.testing_requirements["automatedTooling"]["maxRequestsPerSecond"] == 5
    assert repository.list("intigriti", "intigriti-demo")[0].identifier == "https://app.example.com"


@pytest.mark.asyncio
async def test_bugcrowd_jsonapi_targets_are_normalized(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Token name:password"
        return httpx.Response(200, json={
            "data": {"type": "program", "attributes": {"code": "bc-demo"}},
            "included": [
                {"type": "target", "attributes": {"name": "api.example.com", "category": "domain"}},
                {"type": "reward_range", "attributes": {"name": "not-a-target"}},
            ],
        })

    repository, _, importer = _parts(tmp_path, handler)
    result = await importer.import_bugcrowd("123", token_username="name", token_password="password")
    assert [asset.identifier for asset in result.assets] == ["api.example.com"]
    assert repository.list("bugcrowd", "bc-demo")[0].asset_type == "domain"


def test_repository_replace_removes_stale_assets(tmp_path) -> None:
    repository, _, _ = _parts(tmp_path, lambda request: httpx.Response(500))
    repository.replace(platform="manual", program_handle="p", assets=[ProgramAsset("old.example.com", "domain")], tos_url="https://example.com/policy", snapshot_sha256="a" * 64)
    repository.replace(platform="manual", program_handle="p", assets=[ProgramAsset("new.example.com", "domain")], tos_url="https://example.com/policy", snapshot_sha256="b" * 64)
    assert [asset.identifier for asset in repository.list("manual", "p")] == ["new.example.com"]


def test_snapshot_is_encrypted_and_hashes_plaintext_policy(tmp_path) -> None:
    _, snapshots, _ = _parts(tmp_path, lambda request: httpx.Response(500))
    payload = {"policy": "confidential-snapshot-text", "scope": ["example.com"]}
    digest, path = snapshots.save("manual", "p", payload)
    raw = open(path, "r", encoding="utf-8").read()
    assert raw.startswith("enc:v1:")
    assert "confidential-snapshot-text" not in raw
    restored = snapshots.load(path)
    assert restored == payload
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    import hashlib
    assert digest == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
