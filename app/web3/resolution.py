"""Read-only multi-chain verified-source resolution for P5.

Network access is injected by the caller.  This module never opens sockets,
launches subprocesses, or performs state-changing RPC calls itself.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Sequence

from app.evidence.raw_store import ArtifactRef, RawArtifactStore
from app.web3.audit import ReadOnlyRPC

RESOLVER_ORDER = ("sourcify", "etherscan", "blockscout", "routescout")
ResolverFetcher = Callable[..., Awaitable[Any] | Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_hex(value: Any) -> bytes:
    text = str(value or "0x")
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2:
        text = "0" + text
    return bytes.fromhex(text) if text else b""


def _basic_disassembly(bytecode: bytes) -> bytes:
    """Return a deterministic offset-oriented byte view when no external disassembler is injected."""
    lines = [f"{offset:08x}: {byte:02x}" for offset, byte in enumerate(bytecode)]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SourceResolution:
    address: str
    chain_id: int
    block_number: int
    resolver: str
    resolver_response_hash: str | None
    verified: bool
    solc_version: str | None
    optimizer_enabled: bool | None
    optimizer_runs: int | None
    evm_version: str | None
    abi_hash: str | None
    project_solc_version: str | None
    compiler_divergence: bool
    source_artifact_id: int | None
    source_artifact_sha256: str | None
    bytecode_artifact_id: int | None
    bytecode_artifact_sha256: str | None
    disassembly_artifact_id: int | None
    disassembly_artifact_sha256: str | None


class MultiChainSourceResolver:
    """Resolve verified source in a fixed audited order, then fall back to bytecode."""

    def __init__(
        self,
        *,
        preflight: Any,
        rpc: ReadOnlyRPC,
        artifacts: RawArtifactStore,
        audit: Any,
        fetchers: Mapping[str, ResolverFetcher] | None = None,
        disassembler: Callable[[bytes], Awaitable[bytes | str] | bytes | str] | None = None,
    ) -> None:
        self.preflight = preflight
        self.rpc = rpc
        self.artifacts = artifacts
        self.audit = audit
        self.fetchers = dict(fetchers or {})
        self.disassembler = disassembler

    async def _call_fetcher(self, resolver: str, **kwargs: Any) -> Any:
        fetcher = self.fetchers.get(resolver)
        if fetcher is None:
            return None
        value = fetcher(**kwargs)
        return await value if inspect.isawaitable(value) else value

    async def _disassemble(self, bytecode: bytes) -> bytes:
        if self.disassembler is None:
            return _basic_disassembly(bytecode)
        value = self.disassembler(bytecode)
        value = await value if inspect.isawaitable(value) else value
        return value if isinstance(value, bytes) else str(value).encode("utf-8")

    @staticmethod
    def _normalized_verified_payload(value: Any) -> tuple[bytes, dict[str, Any], bytes, bytes]:
        if not isinstance(value, Mapping):
            raise ValueError("verified source resolver must return an object")
        source_tree = value.get("source_tree")
        if source_tree is None:
            raise ValueError("verified source payload missing source_tree")
        source_bytes = source_tree if isinstance(source_tree, bytes) else _canonical(source_tree)
        compiler = dict(value.get("compiler") or {})
        abi = value.get("abi") or []
        abi_bytes = abi if isinstance(abi, bytes) else _canonical(abi)
        response = value.get("response", value)
        response_bytes = response if isinstance(response, bytes) else _canonical(response)
        return source_bytes, compiler, abi_bytes, response_bytes

    def _artifact(
        self,
        *,
        scan_id: int,
        tool_run_id: int | None,
        kind: str,
        media_type: str,
        content: bytes,
        reason: str,
        metadata: Mapping[str, Any],
    ) -> ArtifactRef:
        return self.artifacts.put(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind=kind,
            media_type=media_type,
            content=content,
            reason=reason,
            metadata=metadata,
        )

    async def resolve(
        self,
        *,
        scan_id: int,
        tool_run_id: int | None,
        address: str,
        consent_id: str,
        project_solc_version: str | None = None,
    ) -> SourceResolution:
        """Resolve source/bytecode at a pinned block under live preflight authorization."""
        self.preflight.authorize_scan(target=address, consent_id=consent_id)
        chain_raw = await self.rpc.call("eth_chainId", [])
        chain_id = int(str(chain_raw), 16) if str(chain_raw).startswith("0x") else int(chain_raw)
        block = await self.rpc.call("eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, Mapping) or block.get("number") is None:
            raise RuntimeError("web3 source resolution requires a pinned block number")
        block_raw = block["number"]
        block_number = int(str(block_raw), 16) if str(block_raw).startswith("0x") else int(block_raw)
        if block_number <= 0:
            raise RuntimeError("web3 source resolution requires a positive pinned block number")
        code_raw = await self.rpc.call("eth_getCode", [address, hex(block_number)])
        bytecode = _decode_hex(code_raw)
        bytecode_ref = self._artifact(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind="web3-bytecode",
            media_type="application/octet-stream",
            content=bytecode,
            reason="p5 deployed bytecode snapshot",
            metadata={"address": address, "chain_id": chain_id, "block_number": block_number},
        )

        selected_resolver = "bytecode-only"
        selected_hash: str | None = None
        source_ref: ArtifactRef | None = None
        compiler: dict[str, Any] = {}
        abi_hash: str | None = None
        for resolver in RESOLVER_ORDER:
            fetcher = self.fetchers.get(resolver)
            if fetcher is None:
                continue
            self.preflight.authorize_scan(target=address, consent_id=consent_id)
            try:
                payload = await self._call_fetcher(
                    resolver,
                    address=address,
                    chain_id=chain_id,
                    block_number=block_number,
                )
            except Exception as exc:
                self.audit.append(
                    "p5.resolver.attempt",
                    {
                        "scan_id": scan_id,
                        "resolver": resolver,
                        "address": address,
                        "chain_id": chain_id,
                        "block_number": block_number,
                        "outcome": "error",
                        "error_type": type(exc).__name__,
                        "response_hash": None,
                    },
                )
                continue
            if payload is None:
                self.audit.append(
                    "p5.resolver.attempt",
                    {
                        "scan_id": scan_id,
                        "resolver": resolver,
                        "address": address,
                        "chain_id": chain_id,
                        "block_number": block_number,
                        "outcome": "miss",
                        "response_hash": None,
                    },
                )
                continue
            source_bytes, compiler, abi_bytes, response_bytes = self._normalized_verified_payload(payload)
            selected_hash = _sha256(response_bytes)
            abi_hash = _sha256(abi_bytes)
            source_ref = self._artifact(
                scan_id=scan_id,
                tool_run_id=tool_run_id,
                kind="web3-source-tree",
                media_type="application/json",
                content=source_bytes,
                reason=f"p5 verified source from {resolver}",
                metadata={
                    "address": address,
                    "chain_id": chain_id,
                    "block_number": block_number,
                    "resolver": resolver,
                    "resolver_response_hash": selected_hash,
                    "compiler": compiler,
                    "abi_hash": abi_hash,
                },
            )
            selected_resolver = resolver
            self.audit.append(
                "p5.resolver.attempt",
                {
                    "scan_id": scan_id,
                    "resolver": resolver,
                    "address": address,
                    "chain_id": chain_id,
                    "block_number": block_number,
                    "outcome": "verified",
                    "response_hash": selected_hash,
                },
            )
            break

        disassembly_ref: ArtifactRef | None = None
        if bytecode:
            disassembly = await self._disassemble(bytecode)
            disassembly_ref = self._artifact(
                scan_id=scan_id,
                tool_run_id=tool_run_id,
                kind="web3-disassembly",
                media_type="text/plain",
                content=disassembly,
                reason="p5 deterministic deployed-bytecode disassembly",
                metadata={"address": address, "chain_id": chain_id, "block_number": block_number},
            )

        solc_version = str(compiler.get("solc_version") or compiler.get("version") or "").strip() or None
        optimizer_runs_raw = compiler.get("optimizer_runs")
        optimizer_runs = int(optimizer_runs_raw) if optimizer_runs_raw is not None else None
        optimizer_enabled_raw = compiler.get("optimizer_enabled")
        optimizer_enabled = bool(optimizer_enabled_raw) if optimizer_enabled_raw is not None else None
        evm_version = str(compiler.get("evm_version") or "").strip() or None
        divergence = bool(project_solc_version and solc_version and project_solc_version != solc_version)
        return SourceResolution(
            address=address,
            chain_id=chain_id,
            block_number=block_number,
            resolver=selected_resolver,
            resolver_response_hash=selected_hash,
            verified=source_ref is not None,
            solc_version=solc_version,
            optimizer_enabled=optimizer_enabled,
            optimizer_runs=optimizer_runs,
            evm_version=evm_version,
            abi_hash=abi_hash,
            project_solc_version=project_solc_version,
            compiler_divergence=divergence,
            source_artifact_id=source_ref.id if source_ref else None,
            source_artifact_sha256=source_ref.sha256 if source_ref else None,
            bytecode_artifact_id=bytecode_ref.id,
            bytecode_artifact_sha256=bytecode_ref.sha256,
            disassembly_artifact_id=disassembly_ref.id if disassembly_ref else None,
            disassembly_artifact_sha256=disassembly_ref.sha256 if disassembly_ref else None,
        )
