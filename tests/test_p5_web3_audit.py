"""P5 acceptance: Web3 auditing is static/read-only and provenance complete."""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from app.web3.audit import ReadOnlyWeb3Adapter, Web3AuditService, normalize_mythril, normalize_slither


class Store:
    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def put(self, *, scan_id: int, tool_run_id: int | None, kind: str, media_type: str, content: bytes, reason: str, **_: Any):
        digest = hashlib.sha256(content).hexdigest()
        self.items[digest] = bytes(content)
        return type("Ref", (), {"sha256": digest})()


def test_read_only_adapter_never_invokes_write_rpc() -> None:
    calls: list[str] = []

    def rpc(method: str, params: list[Any]) -> Any:
        calls.append(method)
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getCode":
            return "0x6001600055"
        if method == "eth_getBlockByNumber":
            return {"number": "0x10", "hash": "0xabc"}
        raise AssertionError(method)

    adapter = ReadOnlyWeb3Adapter(rpc)
    assert adapter.call("eth_chainId", []) == "0x1"
    assert adapter.call("eth_getCode", ["0x123", "latest"]).startswith("0x")
    with pytest.raises(PermissionError):
        adapter.call("eth_sendTransaction", [{"to": "0x123"}])
    with pytest.raises(PermissionError):
        adapter.call("personal_sign", ["0x00", "0x123"])
    assert calls == ["eth_chainId", "eth_getCode"]


def test_slither_and_mythril_normalize_detector_identity_and_code_location() -> None:
    slither = normalize_slither(
        {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "description": "External call before state update",
                    "elements": [{"name": "withdraw", "source_mapping": {"filename_relative": "Vault.sol", "lines": [42, 43]}}],
                }
            ]
        },
        target="Vault.sol",
        tool_version="0.11.3",
        source_sha256="a" * 64,
    )
    mythril = normalize_mythril(
        {
            "issues": [
                {
                    "swc-id": "SWC-107",
                    "title": "Reentrancy",
                    "severity": "High",
                    "function": "withdraw()",
                    "lineno": 42,
                    "description": "State update follows external call",
                }
            ]
        },
        target="0x123",
        tool_version="0.24.8",
        source_sha256="a" * 64,
    )
    assert slither[0].evidence["detector_id"] == "reentrancy-eth"
    assert slither[0].evidence["function"] == "withdraw"
    assert slither[0].evidence["source_location"]["lines"] == [42, 43]
    assert mythril[0].evidence["swc_id"] == "SWC-107"
    assert mythril[0].evidence["function"] == "withdraw()"
    assert mythril[0].evidence["source_location"]["line"] == 42


@pytest.mark.asyncio
async def test_verified_source_fixture_yields_rankable_findings_and_cached_source() -> None:
    store = Store()

    class Provider:
        async def fetch_verified_source(self, address: str, chain_id: int) -> dict[str, Any] | None:
            return {
                "source": "contract Vault { function withdraw() public {} }",
                "source_name": "Vault.sol",
                "block_number": 123456,
                "provider": "sourcify",
            }

        async def fetch_bytecode(self, address: str, chain_id: int, block_number: int | None = None) -> str:
            raise AssertionError("bytecode fallback should not run for verified source")

    async def tool_runner(name: str, target: str, options: dict[str, Any]) -> Any:
        if name == "slither":
            return {"detectors": [{"check": "reentrancy-eth", "impact": "High", "description": "fixture", "elements": [{"name": "withdraw", "source_mapping": {"filename_relative": "Vault.sol", "lines": [1]}}]}]}
        if name == "mythril":
            return {"issues": [{"swc-id": "SWC-107", "title": "Reentrancy", "severity": "High", "function": "withdraw()", "lineno": 1, "description": "fixture"}]}
        raise AssertionError(name)

    result = await Web3AuditService(store=store, source_provider=Provider(), tool_runner=tool_runner).audit(
        scan_id=4,
        contract_address="0x0000000000000000000000000000000000000123",
        chain_id=1,
    )
    assert result["source_artifact_sha256"] in store.items
    assert result["block_number"] == 123456
    assert {finding.evidence.get("detector_id") or finding.evidence.get("swc_id") for finding in result["findings"]} == {"reentrancy-eth", "SWC-107"}
    assert all(finding.evidence["chain_id"] == 1 for finding in result["findings"])


@pytest.mark.asyncio
async def test_bytecode_only_contract_still_runs_mythril_without_write_rpc() -> None:
    store = Store()
    rpc_methods: list[str] = []

    class Provider:
        async def fetch_verified_source(self, address: str, chain_id: int) -> None:
            return None

        async def fetch_bytecode(self, address: str, chain_id: int, block_number: int | None = None) -> str:
            rpc_methods.append("eth_getCode")
            return "0x6001600055"

    names: list[str] = []

    async def tool_runner(name: str, target: str, options: dict[str, Any]) -> Any:
        names.append(name)
        assert options.get("bytecode") is True
        return {"issues": [{"swc-id": "SWC-101", "title": "Integer Arithmetic", "severity": "Medium", "function": "fallback", "lineno": 0, "description": "fixture"}]}

    result = await Web3AuditService(store=store, source_provider=Provider(), tool_runner=tool_runner).audit(
        scan_id=8,
        contract_address="0x0000000000000000000000000000000000000456",
        chain_id=1,
    )
    assert names == ["mythril"]
    assert rpc_methods == ["eth_getCode"]
    assert result["findings"][0].evidence["swc_id"] == "SWC-101"
