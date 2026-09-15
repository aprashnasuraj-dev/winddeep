"""V3-A validation depth for fail-closed target declarations."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.release_migration import apply_v3_release_migration
from app.v3.targets import CIDRPlanner, IPLiteralHTTPSProbe, TargetClassError, TargetDeclarationStore, build_ip_pinned_replay

ROOT = Path(__file__).resolve().parents[1]


class Guard:
    def authorize_scan(self, *, target: str, consent_id: str):
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0):
        return None


def fixture(tmp_path: Path, *, artifacts: bool = False):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    apply_v3_release_migration(database.path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    artifact_store = RawArtifactStore(database, crypto, audit)
    target_id = database.create_target("root", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v3:validation", ["fixture"])
    return database, audit, TargetDeclarationStore(database, audit, Guard(), artifacts=artifact_store if artifacts else None), scan_id


def declare(store: TargetDeclarationStore, scan_id: int, target_class: str, value: str, **kwargs) -> int:
    return store.declare(
        scan_id=scan_id,
        target_class=target_class,
        value=value,
        ports=kwargs.pop("ports", [443]),
        sni=kwargs.pop("sni", []),
        host_headers=kwargs.pop("host_headers", []),
        consent_token_id=kwargs.pop("consent_token_id", "consent"),
        justification=kwargs.pop("justification", "validation fixture"),
        max_hosts=kwargs.pop("max_hosts", None),
        **kwargs,
    )


@pytest.mark.parametrize(
    ("target_class", "value", "message"),
    [
        ("ipv4", "2001:db8::1", "IPv4"),
        ("ipv6", "198.51.100.1", "IPv6"),
        ("cidr", "not-a-range", "CIDR"),
        ("ip_range", "198.51.100.9", "start-end"),
        ("ip_range", "198.51.100.9-198.51.100.1", "ascending"),
        ("ip_range", "198.51.100.1-2001:db8::1", "family"),
        ("ip_url", "https://example.test/", "invalid IP"),
        ("url", "example.test/path", "absolute"),
        ("source_repo", "ftp://example.test/repo", "absolute"),
        ("service", "198.51.100.1", "explicit port"),
        ("service", "198.51.100.1:notnum", "numeric"),
        ("service", "198.51.100.1:70000", "between 1 and 65535"),
        ("service", "[2001:db8::1", "IPv6 service"),
        ("contract", "0x1234", "20-byte"),
        ("domain", "https://example.test", "invalid domain"),
        ("subdomain", "api.example.test/path", "invalid subdomain"),
    ],
)
def test_invalid_target_shapes_fail_closed(tmp_path: Path, target_class: str, value: str, message: str) -> None:
    _database, _audit, store, scan_id = fixture(tmp_path)
    with pytest.raises(TargetClassError, match=message):
        declare(store, scan_id, target_class, value, max_hosts=2 if target_class == "ip_range" else None)


def test_declaration_meta_validation_fail_closed(tmp_path: Path) -> None:
    _database, _audit, store, scan_id = fixture(tmp_path)
    with pytest.raises(TargetClassError, match="unsupported"):
        declare(store, scan_id, "unknown", "x")
    with pytest.raises(TargetClassError, match="consent_token_id"):
        declare(store, scan_id, "ipv4", "198.51.100.1", consent_token_id="")
    with pytest.raises(TargetClassError, match="target value"):
        declare(store, scan_id, "domain", "   ")
    with pytest.raises(TargetClassError, match="declared port"):
        declare(store, scan_id, "ipv4", "198.51.100.1", ports=[])
    with pytest.raises(TargetClassError, match="declared port"):
        declare(store, scan_id, "ipv4", "198.51.100.1", ports=[0])
    with pytest.raises(TargetClassError, match="positive max_hosts"):
        declare(store, scan_id, "cidr", "198.51.100.0/30", max_hosts=None)
    with pytest.raises(TargetClassError, match="positive max_hosts"):
        declare(store, scan_id, "ip_range", "198.51.100.1-198.51.100.2", max_hosts=0)
    with pytest.raises(TargetClassError, match="applies only"):
        declare(store, scan_id, "ipv4", "198.51.100.1", max_hosts=1)


def test_missing_rows_ptr_store_and_wrong_planner_class_fail_closed(tmp_path: Path) -> None:
    _database, _audit, store, scan_id = fixture(tmp_path)
    with pytest.raises(KeyError, match="not found"):
        store.get(999999)
    with pytest.raises(TargetClassError, match="scan not found"):
        store.root_target_id(999999)
    declaration_id = declare(store, scan_id, "ipv4", "198.51.100.1")
    with pytest.raises(TargetClassError, match="PTR evidence"):
        store.record_ptr(declaration_id, ptr_name="ptr.example.test")
    planner = CIDRPlanner(store, Guard(), _audit)
    with pytest.raises(TargetClassError, match="requires a cidr or ip_range"):
        asyncio.run(planner.expand_and_authorize(declaration_id, seed="fixture"))


def test_range_budget_refuses_overlarge_auditable_sets(tmp_path: Path) -> None:
    _database, _audit, store, scan_id = fixture(tmp_path)
    cidr_id = declare(store, scan_id, "cidr", "198.51.96.0/19", max_hosts=10)
    planner = CIDRPlanner(store, Guard(), _audit)
    with pytest.raises(TargetClassError, match="split it"):
        asyncio.run(planner.expand_and_authorize(cidr_id, seed="fixture"))
    range_id = declare(store, scan_id, "ip_range", "198.51.0.1-198.51.31.255", max_hosts=10)
    with pytest.raises(TargetClassError, match="split it"):
        asyncio.run(planner.expand_and_authorize(range_id, seed="fixture"))


def test_probe_and_replay_fail_closed_on_wrong_target_or_mismatched_ip(tmp_path: Path) -> None:
    _database, audit, store, scan_id = fixture(tmp_path)
    declaration_id = declare(store, scan_id, "ipv4", "198.51.100.1")

    async def connector(**kwargs):
        return {}

    probe = IPLiteralHTTPSProbe(store=store, forensic=None, guard=Guard(), audit=audit, connector=connector)
    with pytest.raises(TargetClassError, match="requires an ip_url"):
        asyncio.run(probe.probe_ip_url(declaration_id))
    with pytest.raises(TargetClassError, match="https target"):
        asyncio.run(probe.probe_once(declaration_id, port=443, sni=None, host_header=None, verification_attempt="ip-san"))
    with pytest.raises(TargetClassError, match="no authority"):
        build_ip_pinned_replay({"id": 1, "url": ""})
    with pytest.raises(TargetClassError, match="does not match"):
        build_ip_pinned_replay({"id": 1, "url": "https://198.51.100.1/", "server_ip": "198.51.100.2"})
