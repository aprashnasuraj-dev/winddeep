"""Static, read-only web3 audit primitives for Windeep P5."""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Sequence

from app.engine.tool_wrapper import Finding

_READ_ONLY_RPC = {
    "eth_chainId",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getCode",
    "eth_call",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
}

ENGINE_PINS = {"slither": "0.11.6", "mythril": "0.24.8"}


class ReadOnlyRPC:
    """Fail closed on every JSON-RPC method that can submit or sign state changes."""

    def __init__(self, caller: Callable[[str, Sequence[Any]], Awaitable[Any] | Any]) -> None:
        self._caller = caller

    async def call(self, method: str, params: Sequence[Any]) -> Any:
        if method not in _READ_ONLY_RPC:
            raise PermissionError(f"web3 write/unknown RPC method is forbidden: {method}")
        result = self._caller(method, list(params))
        return await result if inspect.isawaitable(result) else result


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """Exact source/bytecode identity for a contract at one chain/block point."""

    address: str
    chain_id: int
    block_number: int
    source: bytes
    bytecode: bytes
    origin: str

    @property
    def source_sha256(self) -> str:
        return hashlib.sha256(self.source).hexdigest()

    @property
    def bytecode_sha256(self) -> str:
        return hashlib.sha256(self.bytecode).hexdigest()

    @property
    def identity_sha256(self) -> str:
        payload = {
            "address": self.address.casefold(),
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "source_sha256": self.source_sha256,
            "bytecode_sha256": self.bytecode_sha256,
            "origin": self.origin,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class VerifiedSourceResolver:
    """Resolve verified source when available and always bind it to on-chain bytecode."""

    def __init__(
        self,
        *,
        preflight: Any,
        rpc: ReadOnlyRPC,
        sourcify_fetcher: Callable[..., Awaitable[bytes | str | None] | bytes | str | None] | None = None,
        etherscan_fetcher: Callable[..., Awaitable[bytes | str | None] | bytes | str | None] | None = None,
        artifact_sink: Callable[..., Any] | None = None,
    ) -> None:
        self.preflight = preflight
        self.rpc = rpc
        self.sourcify_fetcher = sourcify_fetcher
        self.etherscan_fetcher = etherscan_fetcher
        self.artifact_sink = artifact_sink

    @staticmethod
    async def _invoke(fetcher: Callable[..., Any] | None, **kwargs: Any) -> bytes | None:
        if fetcher is None:
            return None
        value = fetcher(**kwargs)
        value = await value if inspect.isawaitable(value) else value
        if value is None:
            return None
        return value if isinstance(value, bytes) else str(value).encode("utf-8")

    async def resolve(self, *, address: str, consent_id: str) -> SourceSnapshot:
        self.preflight.authorize_scan(target=address, consent_id=consent_id)
        chain_raw = await self.rpc.call("eth_chainId", [])
        chain_id = int(str(chain_raw), 16) if str(chain_raw).startswith("0x") else int(chain_raw)
        block = await self.rpc.call("eth_getBlockByNumber", ["latest", False])
        block_raw = (block or {}).get("number", "0x0") if isinstance(block, Mapping) else "0x0"
        block_number = int(str(block_raw), 16) if str(block_raw).startswith("0x") else int(block_raw)
        code_raw = await self.rpc.call("eth_getCode", [address, hex(block_number)])
        code_hex = str(code_raw or "0x")
        bytecode = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)

        source = await self._invoke(
            self.sourcify_fetcher,
            address=address,
            chain_id=chain_id,
            block_number=block_number,
        )
        origin = "sourcify"
        if source is None:
            source = await self._invoke(
                self.etherscan_fetcher,
                address=address,
                chain_id=chain_id,
                block_number=block_number,
            )
            origin = "etherscan"
        if source is None:
            source = b""
            origin = "bytecode-only"
        snapshot = SourceSnapshot(address, chain_id, block_number, source, bytecode, origin)
        if self.artifact_sink is not None:
            self.artifact_sink(kind="web3-source", content=source, sha256=snapshot.source_sha256, metadata={"address": address, "chain_id": chain_id, "block_number": block_number, "origin": origin})
            self.artifact_sink(kind="web3-bytecode", content=bytecode, sha256=snapshot.bytecode_sha256, metadata={"address": address, "chain_id": chain_id, "block_number": block_number})
        return snapshot


def _severity(value: Any) -> str:
    normalized = str(value or "info").strip().casefold()
    return {"informational": "info", "optimization": "low"}.get(normalized, normalized if normalized in {"info", "low", "medium", "high", "critical"} else "info")


def normalize_slither(payload: Mapping[str, Any], *, target: str, version: str, chain_id: int, block_number: int) -> list[Finding]:
    """Normalize maintained Slither detector output without authoring new detectors."""
    findings: list[Finding] = []
    results = payload.get("results") if isinstance(payload, Mapping) else None
    detectors = results.get("detectors", []) if isinstance(results, Mapping) else []
    for detector in detectors if isinstance(detectors, list) else []:
        if not isinstance(detector, Mapping):
            continue
        elements = detector.get("elements") if isinstance(detector.get("elements"), list) else []
        first = next((item for item in elements if isinstance(item, Mapping)), {})
        source_mapping = first.get("source_mapping") if isinstance(first.get("source_mapping"), Mapping) else {}
        detector_id = str(detector.get("check") or "slither-detector")
        findings.append(Finding(
            title=str(detector.get("description") or detector_id).splitlines()[0],
            severity=_severity(detector.get("impact")),
            vuln_type="web3_static",
            tool="slither",
            endpoint=target,
            description=str(detector.get("description") or ""),
            evidence={
                "engine": "slither",
                "engine_version": version,
                "detector_id": detector_id,
                "confidence_label": str(detector.get("confidence") or ""),
                "affected_function": first.get("name"),
                "source_location": {
                    "file": source_mapping.get("filename_relative") or source_mapping.get("filename_absolute"),
                    "lines": list(source_mapping.get("lines") or []),
                },
                "chain_id": chain_id,
                "block_number": block_number,
            },
            confidence=0.9 if str(detector.get("confidence")).casefold() == "high" else 0.7,
        ))
    return findings


def normalize_mythril(
    payload: Mapping[str, Any],
    *,
    target: str,
    version: str,
    chain_id: int,
    block_number: int,
    bytecode_sha256: str,
) -> list[Finding]:
    """Normalize maintained Mythril SWC output for source or bytecode-only analysis."""
    findings: list[Finding] = []
    issues = payload.get("issues", []) if isinstance(payload, Mapping) else []
    for issue in issues if isinstance(issues, list) else []:
        if not isinstance(issue, Mapping):
            continue
        swc_id = str(issue.get("swc-id") or issue.get("swc_id") or "SWC-unknown")
        findings.append(Finding(
            title=str(issue.get("title") or swc_id),
            severity=_severity(issue.get("severity")),
            vuln_type="web3_static",
            tool="mythril",
            endpoint=target,
            description=str(issue.get("description-head") or issue.get("description") or ""),
            evidence={
                "engine": "mythril",
                "engine_version": version,
                "swc_id": swc_id,
                "affected_function": issue.get("function"),
                "source_location": {"line": issue.get("lineno")},
                "bytecode_sha256": bytecode_sha256,
                "chain_id": chain_id,
                "block_number": block_number,
            },
            confidence=0.8,
        ))
    return findings
