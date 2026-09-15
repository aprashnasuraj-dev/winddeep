"""P5 acceptance tests for static, read-only web3 auditing."""
from __future__ import annotations

import asyncio
import hashlib

import pytest

from app.web3.audit import ReadOnlyRPC, SourceSnapshot, normalize_mythril, normalize_slither


class _RPC:
    def __init__(self) -> None:
        self.calls = []
    async def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId": return "0x1"
        if method == "eth_getBlockByNumber": return {"number":"0x10"}
        if method == "eth_getCode": return "0x6001600055"
        return None


def test_read_only_rpc_rejects_every_write_method() -> None:
    raw = _RPC(); rpc = ReadOnlyRPC(raw)
    assert asyncio.run(rpc.call("eth_chainId", [])) == "0x1"
    for method in ("eth_sendTransaction", "eth_sendRawTransaction", "personal_sendTransaction", "wallet_sendCalls"):
        with pytest.raises(PermissionError):
            asyncio.run(rpc.call(method, []))
    assert all(not method.startswith(("eth_send", "personal_", "wallet_")) for method, _ in raw.calls)


def test_slither_normalization_carries_detector_and_location() -> None:
    payload = {"results":{"detectors":[{"check":"reentrancy-eth","impact":"High","confidence":"High","description":"Reentrancy in withdraw","elements":[{"type":"function","name":"withdraw","source_mapping":{"filename_relative":"Vault.sol","lines":[42,43]}}]}]}}
    findings = normalize_slither(payload, target="0xabc", version="0.11.6", chain_id=1, block_number=16)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.evidence["detector_id"] == "reentrancy-eth"
    assert finding.evidence["affected_function"] == "withdraw"
    assert finding.evidence["source_location"]["lines"] == [42,43]
    assert finding.evidence["chain_id"] == 1 and finding.evidence["block_number"] == 16


def test_mythril_bytecode_only_normalization_still_produces_swc_findings() -> None:
    payload = {"issues":[{"swc-id":"SWC-107","title":"Reentrancy","severity":"High","description-head":"External call before state update","function":"withdraw()","lineno":0}]}
    findings = normalize_mythril(payload, target="0xabc", version="0.24.8", chain_id=1, block_number=16, bytecode_sha256="a"*64)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["swc_id"] == "SWC-107"
    assert finding.evidence["bytecode_sha256"] == "a"*64
    assert finding.evidence["affected_function"] == "withdraw()"


def test_source_snapshot_identity_is_reproducible() -> None:
    snapshot = SourceSnapshot(address="0xabc", chain_id=1, block_number=16, source=b"contract A{}", bytecode=b"\x60\x01", origin="sourcify")
    assert snapshot.source_sha256 == hashlib.sha256(b"contract A{}").hexdigest()
    assert snapshot.bytecode_sha256 == hashlib.sha256(b"\x60\x01").hexdigest()
    assert snapshot.identity_sha256 == SourceSnapshot(address="0xabc", chain_id=1, block_number=16, source=b"contract A{}", bytecode=b"\x60\x01", origin="sourcify").identity_sha256
