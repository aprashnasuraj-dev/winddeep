"""V3-A acceptance tests for IP/CIDR/HTTPS-by-IP target classes."""
from __future__ import annotations

import asyncio
import ipaddress
import json
from pathlib import Path

import pytest

from app.capture.forensic import ForensicFlowStore
from app.evidence.raw_store import RawArtifactStore
from app.evidence.redaction import EvidenceRedactor
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.release_migration import apply_v3_release_migration
from app.v3.targets import (
    CIDRPlanner,
    IPLiteralHTTPSProbe,
    TargetClassError,
    TargetDeclarationStore,
    build_ip_pinned_replay,
)

ROOT = Path(__file__).resolve().parents[1]


class Guard:
    def __init__(self):
        self.authorized: list[tuple[str, str]] = []
        self.rate: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str):
        self.authorized.append((target, consent_id))
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0):
        self.rate.append(key)



def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    apply_v3_release_migration(database.path)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    artifacts = RawArtifactStore(database, crypto, audit)
    target_id = database.create_target("root", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v3:fixture", ["fixture"])
    return crypto, database, audit, artifacts, scan_id


def test_all_target_classes_require_consent_and_justification(tmp_path: Path) -> None:
    _crypto, database, audit, _artifacts, scan_id = _fixture(tmp_path)
    guard = Guard()
    store = TargetDeclarationStore(database, audit, guard)
    samples = {
        "domain": "example.test",
        "subdomain": "api.example.test",
        "ipv4": "198.51.100.7",
        "ipv6": "2001:db8::7",
        "cidr": "198.51.100.0/30",
        "ip_range": "198.51.100.10-198.51.100.12",
        "url": "https://example.test:8443/a",
        "ip_url": "https://198.51.100.7:8443/a",
        "service": "198.51.100.7:9443",
        "contract": "0x00000000000000000000000000000000000000aa",
        "source_repo": "https://github.com/example/repo",
    }
    ids = []
    for klass, value in samples.items():
        ids.append(
            store.declare(
                scan_id=scan_id,
                target_class=klass,
                value=value,
                ports=[8443] if klass in {"ip_url", "service"} else [443],
                sni=["api.example.test"] if klass == "ipv4" else [],
                host_headers=["api.example.test"] if klass == "ipv4" else [],
                consent_token_id=f"consent-{klass}",
                justification=f"fixture {klass}",
                max_hosts=2 if klass in {"cidr", "ip_range"} else None,
            )
        )
    assert len(ids) == len(samples)
    assert len(guard.authorized) == len(samples)
    assert all(consent.startswith("consent-") for _target, consent in guard.authorized)
    with pytest.raises(TargetClassError, match="justification"):
        store.declare(scan_id=scan_id, target_class="ipv4", value="198.51.100.8", ports=[443], sni=[], host_headers=[], consent_token_id="c", justification="")


def test_ipv6_zone_id_and_undeclared_route_are_denied_before_send(tmp_path: Path) -> None:
    _crypto, database, audit, _artifacts, scan_id = _fixture(tmp_path)
    guard = Guard()
    store = TargetDeclarationStore(database, audit, guard)
    with pytest.raises(TargetClassError, match="zone"):
        store.declare(scan_id=scan_id, target_class="ipv6", value="fe80::1%eth0", ports=[443], sni=[], host_headers=[], consent_token_id="c", justification="fixture")
    declaration_id = store.declare(
        scan_id=scan_id,
        target_class="ipv4",
        value="198.51.100.7",
        ports=[8443],
        sni=["api.example.test"],
        host_headers=["api.example.test"],
        consent_token_id="c-ip",
        justification="fixture",
    )
    sent: list[dict] = []

    async def connector(**kwargs):
        sent.append(kwargs)
        return {}

    probe = IPLiteralHTTPSProbe(store=store, forensic=None, guard=guard, audit=audit, connector=connector)
    with pytest.raises(TargetClassError, match="SNI"):
        asyncio.run(probe.probe_once(declaration_id, port=8443, sni="undeclared.example", host_header="api.example.test", verification_attempt="ip-san"))
    with pytest.raises(TargetClassError, match="Host"):
        asyncio.run(probe.probe_once(declaration_id, port=8443, sni="api.example.test", host_header="other.example", verification_attempt="ip-san"))
    with pytest.raises(TargetClassError, match="port"):
        asyncio.run(probe.probe_once(declaration_id, port=443, sni="api.example.test", host_header="api.example.test", verification_attempt="ip-san"))
    assert sent == []


def test_cidr_expansion_is_deterministic_capped_rate_governed_and_audited(tmp_path: Path) -> None:
    _crypto, database, audit, _artifacts, scan_id = _fixture(tmp_path)
    guard = Guard()
    store = TargetDeclarationStore(database, audit, guard)
    declaration_id = store.declare(
        scan_id=scan_id,
        target_class="cidr",
        value="198.51.100.0/29",
        ports=[443],
        sni=[],
        host_headers=[],
        consent_token_id="cidr-consent",
        justification="fixture range",
        max_hosts=3,
    )
    planner = CIDRPlanner(store, guard, audit)
    first = asyncio.run(planner.expand_and_authorize(declaration_id, seed="scan-42"))
    second = asyncio.run(planner.expand_and_authorize(declaration_id, seed="scan-42"))
    assert first["selected"] == second["selected"]
    assert len(first["selected"]) == 3
    assert len(first["skipped"]) == 3
    assert all(ipaddress.ip_address(value) in ipaddress.ip_network("198.51.100.0/29") for value in first["selected"])
    assert any(key == "cidr:198.51.100.0/29" for key in guard.rate)
    assert all(f"ip:{value}" in guard.rate for value in first["selected"])
    records = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    host_events = [row for row in records if row["event"] == "v3.target.cidr_host"]
    assert len(host_events) >= 12
    assert {row["data"]["status"] for row in host_events} == {"attempted", "skipped"}


def test_ptr_is_recon_artifact_only_and_does_not_expand_targets(tmp_path: Path) -> None:
    _crypto, database, audit, artifacts, scan_id = _fixture(tmp_path)
    guard = Guard()
    store = TargetDeclarationStore(database, audit, guard, artifacts=artifacts)
    declaration_id = store.declare(scan_id=scan_id, target_class="ipv4", value="198.51.100.7", ports=[443], sni=[], host_headers=[], consent_token_id="c", justification="fixture")
    before = store.list(scan_id)
    ref = store.record_ptr(declaration_id, ptr_name="outside.example.net")
    after = store.list(scan_id)
    assert ref.kind == "recon.ptr"
    assert len(before) == len(after) == 1
    assert after[0]["value"] == "198.51.100.7"


def test_ip_literal_https_yields_two_cert_backed_flows_and_ip_pinned_replay(tmp_path: Path) -> None:
    crypto, database, audit, artifacts, scan_id = _fixture(tmp_path)
    guard = Guard()
    store = TargetDeclarationStore(database, audit, guard)
    declaration_id = store.declare(
        scan_id=scan_id,
        target_class="ip_url",
        value="https://198.51.100.7:8443/health",
        ports=[8443],
        sni=[],
        host_headers=["198.51.100.7:8443"],
        consent_token_id="c-ipurl",
        justification="fixture ip-url",
    )
    forensic = ForensicFlowStore(database, artifacts, audit)

    async def connector(**kwargs):
        mode = kwargs["verification_attempt"]
        outcome = "verified_ip_san" if mode == "ip-san" else "name_mismatch_observed"
        return {
            "status": 200,
            "response_headers": {"Content-Type": "text/plain"},
            "response_body": b"ok",
            "raw_response": b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok",
            "timings": {"connect": 1.0, "tls": 2.0, "ttfb": 3.0, "total": 4.0},
            "peer_ip": "198.51.100.7",
            "server_ip": "198.51.100.7",
            "tls": {
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "cert_fingerprint_sha256": "a" * 64,
                "cert_chain": ["leaf", "issuer"],
                "verification_attempt": mode,
                "verification_outcome": outcome,
            },
        }

    probe = IPLiteralHTTPSProbe(store=store, forensic=forensic, guard=guard, audit=audit, connector=connector)
    flow_ids = asyncio.run(probe.probe_ip_url(declaration_id))
    assert len(flow_ids) == 2
    flows = [forensic.get(flow_id) for flow_id in flow_ids]
    assert {flow["tls"]["verification_outcome"] for flow in flows} == {"verified_ip_san", "name_mismatch_observed"}
    assert all(flow["tls"]["cert_fingerprint_sha256"] == "a" * 64 for flow in flows)
    replay = build_ip_pinned_replay(flows[0])
    assert replay["pinned_ip"] == "198.51.100.7"
    assert replay["url"].startswith("https://198.51.100.7:8443/")
    redactor = EvidenceRedactor(artifacts)
    har = json.loads(probe.export_har(scan_id=scan_id, redactor=redactor))
    metadata = [entry["_windeep"] for entry in har["log"]["entries"]]
    assert all(item["target_class"] == "ip_url" for item in metadata)
    assert all(item["server_ip"] == "198.51.100.7" for item in metadata)
    assert {item["verification_outcome"] for item in metadata} == {"verified_ip_san", "name_mismatch_observed"}
