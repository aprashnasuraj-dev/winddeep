"""Targeted P5 validation/compatibility coverage for web3 modules."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.web3.audit import ReadOnlyRPC, VerifiedSourceResolver, normalize_mythril as legacy_mythril, normalize_slither as legacy_slither
from app.web3.store import Web3EvidenceStore

ROOT = Path(__file__).resolve().parents[1]


class _Preflight:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def authorize_scan(self, *, target: str, consent_id: str) -> None:
        self.calls.append((target, consent_id))


async def _rpc(method: str, _params: list[object]):
    return {
        "eth_chainId": "0x1",
        "eth_getBlockByNumber": {"number": "0x10"},
        "eth_getCode": "0x6001",
    }.get(method)


def _db(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    target_id = database.create_target("contract", "web3", "0xaa", scope=["0xaa"])
    scan_id = database.create_scan(target_id, "v2:web3", ["slither"])
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    artifacts = RawArtifactStore(database, crypto, audit)
    return database, audit, artifacts, scan_id, target_id


def test_legacy_resolver_fallback_and_artifact_sink_are_covered() -> None:
    preflight = _Preflight()
    captured: list[dict] = []

    async def sourcify(**_kwargs):
        return None

    def etherscan(**_kwargs):
        return "contract Vault {}"

    resolver = VerifiedSourceResolver(
        preflight=preflight,
        rpc=ReadOnlyRPC(_rpc),
        sourcify_fetcher=sourcify,
        etherscan_fetcher=etherscan,
        artifact_sink=lambda **kwargs: captured.append(kwargs),
    )
    snapshot = asyncio.run(resolver.resolve(address="0xaa", consent_id="c1"))
    assert snapshot.origin == "etherscan"
    assert snapshot.chain_id == 1
    assert snapshot.block_number == 16
    assert snapshot.source == b"contract Vault {}"
    assert snapshot.bytecode == b"\x60\x01"
    assert len(snapshot.source_sha256) == 64
    assert len(snapshot.bytecode_sha256) == 64
    assert len(snapshot.identity_sha256) == 64
    assert preflight.calls == [("0xaa", "c1")]
    assert [row["kind"] for row in captured] == ["web3-source", "web3-bytecode"]


def test_legacy_resolver_bytecode_only_and_sync_read_rpc() -> None:
    preflight = _Preflight()

    def sync_rpc(method: str, _params: list[object]):
        return {
            "eth_chainId": 1,
            "eth_getBlockByNumber": {"number": 16},
            "eth_getCode": "6002",
        }.get(method)

    resolver = VerifiedSourceResolver(preflight=preflight, rpc=ReadOnlyRPC(sync_rpc))
    snapshot = asyncio.run(resolver.resolve(address="0xaa", consent_id="c2"))
    assert snapshot.origin == "bytecode-only"
    assert snapshot.source == b""
    assert snapshot.bytecode == b"\x60\x02"
    with pytest.raises(PermissionError):
        asyncio.run(resolver.rpc.call("eth_sendTransaction", []))


def test_legacy_normalizers_cover_aliases_invalid_records_and_defaults() -> None:
    slither = legacy_slither(
        {
            "results": {
                "detectors": [
                    "ignore-me",
                    {
                        "check": "optimization-note",
                        "impact": "Optimization",
                        "confidence": "Medium",
                        "description": "Optimization note\nsecond line",
                        "elements": [{"name": "f", "source_mapping": {"filename_absolute": "/tmp/Vault.sol", "lines": [7]}}],
                    },
                    {"description": "Unknown severity", "impact": "mystery"},
                ]
            }
        },
        target="0xaa",
        version="legacy",
        chain_id=1,
        block_number=16,
    )
    assert [item.severity for item in slither] == ["low", "info"]
    assert slither[0].evidence["source_location"]["file"] == "/tmp/Vault.sol"

    mythril = legacy_mythril(
        {
            "issues": [
                "ignore-me",
                {"swc_id": "SWC-104", "severity": "Informational", "description": "unchecked", "lineno": 9},
                {"title": "No SWC", "severity": "weird"},
            ]
        },
        target="0xaa",
        version="legacy",
        chain_id=1,
        block_number=16,
        bytecode_sha256="a" * 64,
    )
    assert mythril[0].evidence["swc_id"] == "SWC-104"
    assert mythril[0].severity == "info"
    assert mythril[1].evidence["swc_id"] == "SWC-unknown"


def test_web3_store_validation_latest_resolution_and_reverse_ranges(tmp_path: Path) -> None:
    database, audit, artifacts, scan_id, target_id = _db(tmp_path)
    store = Web3EvidenceStore(database, artifacts, audit)
    source = artifacts.put(
        scan_id=scan_id,
        tool_run_id=None,
        kind="web3-source-tree",
        media_type="application/json",
        content=b"{}",
        reason="fixture",
    )
    with pytest.raises(ValueError, match="SHA-256"):
        store.record_source_resolution(
            scan_id=scan_id,
            contract_address="0xaa",
            chain_id=1,
            block_number=16,
            resolver="sourcify",
            resolver_response_hash="bad",
            solc_version="0.8.24",
            optimizer_runs=200,
            evm_version="paris",
            abi_hash="b" * 64,
            source_artifact_id=source.id,
            bytecode_artifact_id=None,
            disassembly_artifact_id=None,
        )
    record_id = store.record_source_resolution(
        scan_id=scan_id,
        contract_address="0xaa",
        chain_id=1,
        block_number=16,
        resolver="sourcify",
        resolver_response_hash="a" * 64,
        solc_version="0.8.24",
        optimizer_runs=200,
        evm_version="paris",
        abi_hash="b" * 64,
        source_artifact_id=source.id,
        bytecode_artifact_id=None,
        disassembly_artifact_id=None,
    )
    assert store.latest_source_resolution(scan_id=scan_id, contract_address="0xaa", chain_id=1)["id"] == record_id
    assert store.latest_source_resolution(scan_id=scan_id, contract_address="0xff", chain_id=1) is None

    raw = artifacts.put(
        scan_id=scan_id,
        tool_run_id=None,
        kind="web3-engine-output",
        media_type="application/json",
        content=b"{}",
        reason="fixture",
    )
    with pytest.raises(ValueError, match="required"):
        store.record_engine_run(
            scan_id=scan_id,
            tool_run_id=None,
            engine_name="",
            engine_version="",
            detector_set_version=None,
            source_artifact_id=source.id,
            raw_output_artifact_id=raw.id,
            started_at=1,
            ended_at=2,
            exit_code=0,
        )
    with pytest.raises(ValueError, match="end precedes"):
        store.record_engine_run(
            scan_id=scan_id,
            tool_run_id=None,
            engine_name="slither",
            engine_version="0.11.6",
            detector_set_version=None,
            source_artifact_id=source.id,
            raw_output_artifact_id=raw.id,
            started_at=2,
            ended_at=1,
            exit_code=0,
        )
    run_id = store.record_engine_run(
        scan_id=scan_id,
        tool_run_id=None,
        engine_name="slither",
        engine_version="0.11.6",
        detector_set_version="builtin",
        source_artifact_id=source.id,
        raw_output_artifact_id=raw.id,
        started_at=1,
        ended_at=2,
        exit_code=0,
    )
    finding_id, _ = database.create_finding(
        target_id,
        "fixture",
        "medium",
        scan_id=scan_id,
        vuln_type="web3_static",
        tool="slither",
        endpoint="0xaa",
        evidence={},
    )
    base = dict(
        finding_id=finding_id,
        engine_run_id=run_id,
        detector_id="d",
        swc_id=None,
        affected_function="f",
        source_file="Vault.sol",
        corroborated=False,
        corroborating_engine_run_id=None,
        upstream_source="maintained",
    )
    with pytest.raises(ValueError, match="source line"):
        store.record_finding_provenance(
            **base,
            line_start=10,
            line_end=9,
            bytecode_offset_start=None,
            bytecode_offset_end=None,
        )
    with pytest.raises(ValueError, match="bytecode offset"):
        store.record_finding_provenance(
            **base,
            line_start=1,
            line_end=1,
            bytecode_offset_start=10,
            bytecode_offset_end=9,
        )
    with pytest.raises(ValueError, match="required"):
        store.record_finding_provenance(
            **{**base, "detector_id": "", "upstream_source": ""},
            line_start=1,
            line_end=1,
            bytecode_offset_start=None,
            bytecode_offset_end=None,
        )
