"""Expanded P5 acceptance: fallback, disassembly, corroboration and provenance."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from app.engine.tool_wrapper import Finding, ToolWrapperFactory
from app.migrations import MigrationManager
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.web3.audit import (
    VerifiedSourceProvider,
    Web3AuditService,
    corroborate_findings,
    deterministic_web3_report,
    disassemble_bytecode,
    normalize_aderyn,
    normalize_slither,
)
from app.web3.catalog import WEB3_ENGINE_PINS, validate_web3_catalog
from app.web3.provenance import Web3ProvenanceStore

ROOT = Path(__file__).resolve().parents[1]


class Store:
    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}
        self.metadata: dict[str, dict[str, Any]] = {}

    def put(self, *, content: bytes, metadata=None, **kwargs: Any):
        digest = hashlib.sha256(content).hexdigest()
        self.items[digest] = bytes(content)
        self.metadata[digest] = dict(metadata or {})
        return type("Ref", (), {"sha256": digest})()


@pytest.mark.asyncio
async def test_sourcify_404_falls_back_to_etherscan_and_compiler_pin_divergence_is_explicit() -> None:
    calls: list[str] = []

    async def sourcify(address: str, chain_id: int):
        calls.append("sourcify")
        return None

    async def etherscan(address: str, chain_id: int):
        calls.append("etherscan")
        return {
            "source": "contract Vault {}",
            "source_name": "Vault.sol",
            "compiler_version": "v0.8.19+commit.7dd6d404",
            "block_number": 123,
        }

    async def bytecode(address: str, chain_id: int, block_number: int | None):
        raise AssertionError("verified source fallback succeeded")

    provider = VerifiedSourceProvider(sourcify_fetch=sourcify, etherscan_fetch=etherscan, bytecode_fetch=bytecode)
    resolved = await provider.fetch_verified_source("0x" + "1" * 40, 1)
    assert resolved is not None
    assert resolved["provider"] == "etherscan"
    assert calls == ["sourcify", "etherscan"]
    assert provider.compiler_divergence(resolved["compiler_version"], "0.8.20")["diverged"] is True
    assert provider.compiler_divergence(resolved["compiler_version"], "0.8.19")["diverged"] is False


def test_slither_aderyn_corroboration_only_annotates_primary_finding() -> None:
    source_sha = "a" * 64
    slither = normalize_slither(
        {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "description": "external call before write",
                    "elements": [{"name": "withdraw", "source_mapping": {"filename_relative": "Vault.sol", "lines": [42]}}],
                }
            ]
        },
        target="Vault.sol",
        tool_version=WEB3_ENGINE_PINS["slither"],
        source_sha256=source_sha,
    )
    aderyn = normalize_aderyn(
        {
            "issues": [
                {
                    "detector": "reentrancy",
                    "title": "Reentrancy",
                    "severity": "High",
                    "vuln_type": "reentrancy",
                    "function": "withdraw",
                    "file": "Vault.sol",
                    "line": 42,
                }
            ]
        },
        target="Vault.sol",
        tool_version=WEB3_ENGINE_PINS["aderyn"],
        source_sha256=source_sha,
    )
    result = corroborate_findings(slither, aderyn)
    assert len(result) == 1
    assert result[0].tool == "slither"
    assert result[0].evidence["corroborated"] is True
    assert result[0].evidence["corroborated_by"] == ["aderyn"]


@pytest.mark.asyncio
async def test_bytecode_only_audit_stores_bytecode_disassembly_and_offset_range_deterministically() -> None:
    store = Store()

    class Provider:
        async def fetch_verified_source(self, address: str, chain_id: int):
            return None

        async def fetch_bytecode(self, address: str, chain_id: int, block_number: int | None = None):
            return "0x6001600055"

    async def runner(name: str, target: str, options: dict[str, Any]):
        assert name == "mythril"
        assert options["bytecode"] is True
        assert options["read_only"] is True
        return {
            "issues": [
                {
                    "swc-id": "SWC-101",
                    "title": "Fixture bytecode observation",
                    "severity": "Medium",
                    "function": "fallback",
                    "address": 0,
                    "description": "fixture",
                }
            ]
        }

    service = Web3AuditService(store=store, source_provider=Provider(), tool_runner=runner)
    first = await service.audit(scan_id=8, contract_address="0x" + "4" * 40, chain_id=1)
    second = await service.audit(scan_id=8, contract_address="0x" + "4" * 40, chain_id=1)
    assert first["bytecode_artifact_sha256"] in store.items
    assert first["disassembly_artifact_sha256"] in store.items
    finding = first["findings"][0]
    assert finding.evidence["bytecode_offset_range"] == [0, 2]
    assert finding.evidence["exploitability"] == "needs-human-review"
    assert deterministic_web3_report(first) == deterministic_web3_report(second)


def test_disassembly_rejects_invalid_hex_and_preserves_exact_offsets() -> None:
    instructions = disassemble_bytecode("0x6001600055")
    assert instructions == [
        {"offset_start": 0, "offset_end": 2, "opcode": "PUSH1", "operand": "01"},
        {"offset_start": 2, "offset_end": 4, "opcode": "PUSH1", "operand": "00"},
        {"offset_start": 4, "offset_end": 5, "opcode": "SSTORE", "operand": ""},
    ]
    with pytest.raises(ValueError):
        disassemble_bytecode("0x123")
    with pytest.raises(ValueError):
        disassemble_bytecode("0xzz")


def test_catalog_contract_keeps_slither_and_mythril_scope_bound_pinned_web3_engines() -> None:
    wrappers = ToolWrapperFactory(ROOT / "tools_config.json").load()
    result = validate_web3_catalog(wrappers)
    assert set(result["engines"]) == {"slither", "mythril"}
    assert result["engines"]["slither"]["version_pin"] == "0.11.3"
    assert result["engines"]["mythril"]["version_pin"] == "0.24.8"
    assert all(item["resource_class"] == "web3" for item in result["engines"].values())
    assert all(item["requires_scope"] for item in result["engines"].values())


def test_provenance_corrections_are_append_only_with_supersedes_link(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    db = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(db.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    target_id = db.create_target("vault", "contract", "0x" + "1" * 40, scope=["0x" + "1" * 40])
    scan_id = db.create_scan(target_id, "v3:web3", ["slither"])
    with db._connect() as conn:
        source_id = int(
            conn.execute(
                "INSERT INTO web3_source_artifact(scan_id, contract_address, chain_id, block_number, provider, source_sha256, compiler_version, supersedes_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1.0)",
                (scan_id, "0x" + "1" * 40, 1, 1, "sourcify", "a" * 64, "0.8.19"),
            ).lastrowid
        )
        engine_id = int(
            conn.execute(
                "INSERT INTO web3_engine_run(scan_id, source_artifact_id, engine, engine_version, input_sha256, output_sha256, supersedes_id, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, 1.0)",
                (scan_id, source_id, "slither", "0.11.3", "a" * 64, "b" * 64),
            ).lastrowid
        )
    store = Web3ProvenanceStore(db)
    first = store.record_finding(
        finding_id=None,
        scan_id=scan_id,
        engine_run_id=engine_id,
        detector_id="reentrancy-eth",
        function_name="withdraw",
        source_location={"file": "Vault.sol", "lines": [42]},
        corroborated=False,
    )
    second = store.record_finding(
        finding_id=None,
        scan_id=scan_id,
        engine_run_id=engine_id,
        detector_id="reentrancy-eth",
        function_name="withdraw",
        source_location={"file": "Vault.sol", "lines": [42]},
        corroborated=True,
    )
    assert second != first
    one = store.resolve(first)
    two = store.resolve(second)
    assert one["corroborated"] is False
    assert two["corroborated"] is True
    assert two["supersedes_id"] == first
    assert store.fingerprint(two) == store.fingerprint(store.resolve(second))
    with pytest.raises(ValueError):
        store.validate_hash("xyz", field="source_sha256")
