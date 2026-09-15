"""Expanded P5 acceptance tests for deep, read-only multi-chain web3 auditing."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.web3.audit import ReadOnlyRPC
from app.web3.engines import corroborate_findings, mythril_plan, normalize_aderyn, normalize_mythril, normalize_slither
from app.web3.reporting import render_web3_markdown
from app.web3.resolution import RESOLVER_ORDER, MultiChainSourceResolver
from app.web3.store import Web3EvidenceStore

ROOT = Path(__file__).resolve().parents[1]


class _Preflight:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def authorize_scan(self, *, target: str, consent_id: str) -> None:
        self.calls.append((target, consent_id))


class _RPC:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[object]]] = []

    async def __call__(self, method: str, params: list[object]):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getBlockByNumber":
            return {"number": "0x10"}
        if method == "eth_getCode":
            return "0x60016000556002600055"
        if method == "eth_getStorageAt":
            return "0x" + "00" * 32
        return None


def _db(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    target_id = database.create_target("contract", "web3", "0x00000000000000000000000000000000000000aa", scope=["0x00000000000000000000000000000000000000aa"])
    scan_id = database.create_scan(target_id, "v2:web3", ["slither", "aderyn", "mythril"])
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    artifacts = RawArtifactStore(database, crypto, audit)
    return crypto, database, audit, artifacts, scan_id


def _verified_payload(solc: str = "0.8.24") -> dict:
    return {
        "source_tree": {
            "Vault.sol": "pragma solidity ^0.8.24; contract Vault { mapping(address=>uint) public balances; function withdraw() external {} }"
        },
        "compiler": {
            "solc_version": solc,
            "optimizer_enabled": True,
            "optimizer_runs": 200,
            "evm_version": "paris",
        },
        "abi": [{"type": "function", "name": "withdraw", "stateMutability": "nonpayable", "inputs": [], "outputs": []}],
        "response": {"status": "1", "message": "OK"},
    }


def test_resolver_order_fallback_is_audited_and_verified_metadata_wins(tmp_path: Path) -> None:
    _crypto, database, audit, artifacts, scan_id = _db(tmp_path)
    preflight = _Preflight()
    raw_rpc = _RPC()
    calls: list[str] = []

    async def empty(**_kwargs):
        calls.append("sourcify")
        return None

    async def etherscan(**_kwargs):
        calls.append("etherscan")
        return _verified_payload("0.8.24")

    resolver = MultiChainSourceResolver(
        preflight=preflight,
        rpc=ReadOnlyRPC(raw_rpc),
        artifacts=artifacts,
        audit=audit,
        fetchers={"sourcify": empty, "etherscan": etherscan},
    )
    result = asyncio.run(
        resolver.resolve(
            scan_id=scan_id,
            tool_run_id=None,
            address="0x00000000000000000000000000000000000000aa",
            consent_id="consent-1",
            project_solc_version="0.7.6",
        )
    )
    assert RESOLVER_ORDER == ("sourcify", "etherscan", "blockscout", "routescout")
    assert calls == ["sourcify", "etherscan"]
    assert result.resolver == "etherscan"
    assert result.verified is True
    assert result.solc_version == "0.8.24"
    assert result.project_solc_version == "0.7.6"
    assert result.compiler_divergence is True
    assert result.source_artifact_id is not None
    assert result.bytecode_artifact_id is not None
    assert result.resolver_response_hash and len(result.resolver_response_hash) == 64
    assert preflight.calls == [("0x00000000000000000000000000000000000000aa", "consent-1")]
    records = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    attempts = [row for row in records if row["event"] == "p5.resolver.attempt"]
    assert [row["data"]["resolver"] for row in attempts] == ["sourcify", "etherscan"]
    assert attempts[0]["data"]["outcome"] == "miss"
    assert attempts[1]["data"]["outcome"] == "verified"


def test_full_resolver_fallback_reaches_blockscout_then_routescout(tmp_path: Path) -> None:
    _crypto, _database, audit, artifacts, scan_id = _db(tmp_path)
    order: list[str] = []

    def miss_factory(name: str):
        async def miss(**_kwargs):
            order.append(name)
            return None
        return miss

    async def route(**_kwargs):
        order.append("routescout")
        return _verified_payload()

    resolver = MultiChainSourceResolver(
        preflight=_Preflight(),
        rpc=ReadOnlyRPC(_RPC()),
        artifacts=artifacts,
        audit=audit,
        fetchers={
            "sourcify": miss_factory("sourcify"),
            "etherscan": miss_factory("etherscan"),
            "blockscout": miss_factory("blockscout"),
            "routescout": route,
        },
    )
    result = asyncio.run(resolver.resolve(scan_id=scan_id, tool_run_id=None, address="0x00000000000000000000000000000000000000aa", consent_id="c"))
    assert order == list(RESOLVER_ORDER)
    assert result.resolver == "routescout"


def test_bytecode_only_resolution_creates_disassembly_artifact_and_never_writes_rpc(tmp_path: Path) -> None:
    _crypto, _database, audit, artifacts, scan_id = _db(tmp_path)
    raw_rpc = _RPC()
    resolver = MultiChainSourceResolver(
        preflight=_Preflight(),
        rpc=ReadOnlyRPC(raw_rpc),
        artifacts=artifacts,
        audit=audit,
        fetchers={},
    )
    result = asyncio.run(resolver.resolve(scan_id=scan_id, tool_run_id=None, address="0x00000000000000000000000000000000000000aa", consent_id="c"))
    assert result.verified is False
    assert result.resolver == "bytecode-only"
    assert result.disassembly_artifact_id is not None
    assert result.source_artifact_id is None
    assert result.bytecode_artifact_id is not None
    forbidden = {"eth_sendRawTransaction", "eth_sendTransaction", "personal_sendTransaction", "wallet_sendCalls"}
    assert forbidden.isdisjoint({method for method, _params in raw_rpc.calls})


def test_slither_and_aderyn_corroboration_is_preserved_and_single_engine_not_dropped() -> None:
    slither_payload = {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "High",
                    "description": "Reentrancy in Vault.withdraw",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {"filename_relative": "Vault.sol", "lines": [42, 43]},
                        }
                    ],
                },
                {
                    "check": "unused-state",
                    "impact": "Low",
                    "confidence": "Medium",
                    "description": "Unused state variable",
                    "elements": [
                        {
                            "type": "variable",
                            "name": "legacy",
                            "source_mapping": {"filename_relative": "Vault.sol", "lines": [8]},
                        }
                    ],
                },
            ]
        }
    }
    aderyn_payload = {
        "issues": [
            {
                "detector_id": "reentrancy",
                "severity": "high",
                "title": "Reentrancy",
                "function": "withdraw",
                "source_file": "Vault.sol",
                "line_start": 42,
                "line_end": 43,
                "swc_id": "SWC-107",
            }
        ]
    }
    observations = normalize_slither(slither_payload, target="0xaa", version="0.11.6", chain_id=1, block_number=16)
    observations += normalize_aderyn(aderyn_payload, target="0xaa", version="operator-pinned", chain_id=1, block_number=16)
    merged = corroborate_findings(observations)
    assert len(merged) == 2
    reentrancy = next(item for item in merged if item.evidence.get("swc_id") == "SWC-107")
    unused = next(item for item in merged if item.evidence.get("detector_id") == "unused-state")
    assert reentrancy.evidence["corroborated"] is True
    assert {row["engine"] for row in reentrancy.evidence["engine_observations"]} == {"slither", "aderyn"}
    assert reentrancy.confidence > 0.9
    assert unused.evidence["corroborated"] is False


def test_mythril_plan_is_bounded_and_bytecode_findings_require_human_review() -> None:
    plan = mythril_plan(bytecode_hex="6001600055", timeout_seconds=300, max_depth=128)
    assert "--execution-timeout" in plan and "300" in plan
    assert "--max-depth" in plan and "128" in plan
    assert all("send" not in arg.casefold() and "transaction" not in arg.casefold() for arg in plan)
    payload = {
        "issues": [
            {
                "swc-id": "SWC-107",
                "title": "Potential reentrancy",
                "severity": "High",
                "description-head": "External call before state update",
                "function": "withdraw()",
                "address": 12,
            }
        ]
    }
    finding = normalize_mythril(
        payload,
        target="0xaa",
        version="0.24.8",
        chain_id=1,
        block_number=16,
        bytecode_sha256="a" * 64,
        source_verified=False,
        disassembly_artifact_sha256="b" * 64,
    )[0]
    assert finding.evidence["exploitability"] == "needs-human-review"
    assert finding.evidence["bytecode_offset_start"] == 12
    assert finding.evidence["disassembly_artifact_sha256"] == "b" * 64
    assert "calldata" not in " ".join(finding.evidence["reproduction_plan"]).casefold()


def test_web3_provenance_store_requires_block_and_records_supersession(tmp_path: Path) -> None:
    _crypto, database, audit, artifacts, scan_id = _db(tmp_path)
    store = Web3EvidenceStore(database, artifacts, audit)
    source = artifacts.put(
        scan_id=scan_id,
        tool_run_id=None,
        kind="web3-source-tree",
        media_type="application/json",
        content=b'{"Vault.sol":"contract Vault{}"}',
        reason="fixture",
    )
    first = store.record_source_resolution(
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
    second = store.record_source_resolution(
        scan_id=scan_id,
        contract_address="0xaa",
        chain_id=1,
        block_number=16,
        resolver="sourcify",
        resolver_response_hash="c" * 64,
        solc_version="0.8.24",
        optimizer_runs=200,
        evm_version="paris",
        abi_hash="b" * 64,
        source_artifact_id=source.id,
        bytecode_artifact_id=None,
        disassembly_artifact_id=None,
        supersedes_id=first,
    )
    assert second != first
    with database._connect() as conn:
        row = conn.execute("SELECT supersedes_id, block_number FROM web3_source_artifact WHERE id = ?", (second,)).fetchone()
    assert row["supersedes_id"] == first
    assert row["block_number"] == 16
    with pytest.raises(ValueError, match="block_number"):
        store.record_source_resolution(
            scan_id=scan_id,
            contract_address="0xaa",
            chain_id=1,
            block_number=0,
            resolver="sourcify",
            resolver_response_hash="d" * 64,
            solc_version="0.8.24",
            optimizer_runs=200,
            evm_version="paris",
            abi_hash="e" * 64,
            source_artifact_id=source.id,
            bytecode_artifact_id=None,
            disassembly_artifact_id=None,
        )


def test_engine_run_and_finding_provenance_form_traceable_graph(tmp_path: Path) -> None:
    _crypto, database, audit, artifacts, scan_id = _db(tmp_path)
    store = Web3EvidenceStore(database, artifacts, audit)
    raw = artifacts.put(scan_id=scan_id, tool_run_id=None, kind="web3-engine-output", media_type="application/json", content=b'{"issues":[]}', reason="fixture")
    engine_run = store.record_engine_run(
        scan_id=scan_id,
        tool_run_id=None,
        engine_name="aderyn",
        engine_version="operator-pinned",
        detector_set_version="ruleset-1",
        source_artifact_id=None,
        raw_output_artifact_id=raw.id,
        started_at=1.0,
        ended_at=2.0,
        exit_code=0,
    )
    target_id = database.create_target("contract-2", "web3", "0xbb", scope=["0xbb"])
    finding_id, _ = database.create_finding(
        target_id,
        "Reentrancy observation",
        "high",
        scan_id=scan_id,
        vuln_type="web3_static",
        tool="aderyn",
        endpoint="0xbb",
        description="Static detector observation",
        evidence={},
        confidence=0.8,
    )
    provenance_id = store.record_finding_provenance(
        finding_id=finding_id,
        engine_run_id=engine_run,
        detector_id="reentrancy",
        swc_id="SWC-107",
        affected_function="withdraw",
        source_file="Vault.sol",
        line_start=42,
        line_end=43,
        bytecode_offset_start=None,
        bytecode_offset_end=None,
        corroborated=False,
        corroborating_engine_run_id=None,
        upstream_source="aderyn-maintained-rules",
    )
    assert provenance_id > 0
    graph = store.provenance_graph(finding_id)
    assert graph["finding_id"] == finding_id
    assert graph["nodes"][0]["engine_name"] == "aderyn"
    assert graph["nodes"][0]["detector_id"] == "reentrancy"
    assert graph["nodes"][0]["swc_id"] == "SWC-107"


def test_web3_markdown_is_deterministic_and_states_source_resolution() -> None:
    context = {
        "contract_address": "0xaa",
        "chain_id": 1,
        "block_number": 16,
        "resolver": "etherscan",
        "resolver_response_hash": "a" * 64,
        "solc_version": "0.8.24",
        "project_solc_version": "0.7.6",
        "optimizer_runs": 200,
        "evm_version": "paris",
        "source_artifact_sha256": "b" * 64,
        "bytecode_artifact_sha256": "c" * 64,
        "disassembly_artifact_sha256": None,
        "verified": True,
        "engine_observations": [
            {"engine": "slither", "version": "0.11.6", "detector_id": "reentrancy-eth", "swc_id": "SWC-107", "upstream_source": "slither-maintained-detectors"},
            {"engine": "aderyn", "version": "operator-pinned", "detector_id": "reentrancy", "swc_id": "SWC-107", "upstream_source": "aderyn-maintained-rules"},
        ],
        "corroborated": True,
        "affected_function": "withdraw",
        "source_file": "Vault.sol",
        "line_start": 42,
        "line_end": 43,
        "exploitability": "observed",
        "reproduction_plan": ["Re-run the pinned static engines against the cached source artifact and inspect Vault.sol:42-43."],
    }
    first = render_web3_markdown(context)
    second = render_web3_markdown(dict(context))
    assert first == second
    assert "## Source Resolution" in first
    assert "etherscan" in first
    assert "0.8.24" in first and "0.7.6" in first
    assert "## Detector Provenance" in first
    assert "corroborated: `true`" in first.casefold()
    assert "transaction" not in first.casefold()


def test_bytecode_only_report_explicitly_says_source_not_verified() -> None:
    context = {
        "contract_address": "0xaa",
        "chain_id": 1,
        "block_number": 16,
        "resolver": "bytecode-only",
        "resolver_response_hash": None,
        "solc_version": None,
        "project_solc_version": None,
        "optimizer_runs": None,
        "evm_version": "unknown",
        "source_artifact_sha256": None,
        "bytecode_artifact_sha256": "c" * 64,
        "disassembly_artifact_sha256": "d" * 64,
        "verified": False,
        "engine_observations": [{"engine": "mythril", "version": "0.24.8", "detector_id": "SWC-107", "swc_id": "SWC-107", "upstream_source": "mythril-swc"}],
        "corroborated": False,
        "affected_function": "withdraw()",
        "bytecode_offset_start": 12,
        "bytecode_offset_end": 18,
        "exploitability": "needs-human-review",
        "reproduction_plan": ["Re-run the pinned symbolic engine against the cached bytecode artifact and inspect the referenced disassembly range."],
    }
    report = render_web3_markdown(context)
    assert "source not verified" in report.casefold()
    assert "needs-human-review" in report
    assert "disassembly" in report.casefold()
