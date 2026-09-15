"""P5 expert Web3 audit support: static, read-only, evidence-addressed.

The service never signs or sends transactions.  It retrieves verified source or
bytecode using read-only providers, stores every analysis input/output by hash,
and normalizes only findings emitted by approved engines.  Aderyn is used as a
corroborator; it does not invent a new detector family.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.engine.tool_wrapper import Finding

_READ_ONLY_RPC = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getBlockByHash",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_call",
    }
)
_WRITEISH_PREFIXES = ("eth_send", "personal_", "wallet_", "miner_", "debug_set", "anvil_", "hardhat_set")
_WRITEISH_EXACT = frozenset({"eth_sign", "eth_signTransaction", "personal_sign", "evm_mine", "evm_setAccountCode"})
_SEVERITIES = {"critical", "high", "medium", "low", "informational", "info"}
_COMPILER_RE = re.compile(r"v?(\d+\.\d+\.\d+)(?:\+commit\.[0-9a-f]+)?", re.I)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _severity(value: Any) -> str:
    text = str(value or "info").strip().lower()
    return text if text in _SEVERITIES else "info"


def _compiler_core(value: str | None) -> str:
    if not value:
        return ""
    match = _COMPILER_RE.search(value)
    return match.group(1) if match else str(value).strip()


class ReadOnlyWeb3Adapter:
    """Hard allow-list around an Ethereum JSON-RPC callable."""

    def __init__(self, rpc: Callable[[str, list[Any]], Any]) -> None:
        self.rpc = rpc

    def call(self, method: str, params: list[Any]) -> Any:
        normalized = str(method).strip()
        if normalized in _WRITEISH_EXACT or normalized.startswith(_WRITEISH_PREFIXES):
            raise PermissionError(f"write/signing RPC is forbidden: {normalized}")
        if normalized not in _READ_ONLY_RPC:
            raise PermissionError(f"RPC method is not on the read-only allow-list: {normalized}")
        return self.rpc(normalized, list(params))


@dataclass(frozen=True, slots=True)
class VerifiedSource:
    source: str
    source_name: str
    block_number: int | None
    provider: str
    compiler_version: str | None = None
    metadata: Mapping[str, Any] | None = None


class VerifiedSourceProvider:
    """Sourcify-first, Etherscan-second verified-source resolver."""

    def __init__(
        self,
        *,
        sourcify_fetch: Callable[[str, int], Awaitable[Mapping[str, Any] | None]],
        etherscan_fetch: Callable[[str, int], Awaitable[Mapping[str, Any] | None]],
        bytecode_fetch: Callable[[str, int, int | None], Awaitable[str]],
    ) -> None:
        self.sourcify_fetch = sourcify_fetch
        self.etherscan_fetch = etherscan_fetch
        self.bytecode_fetch = bytecode_fetch

    async def fetch_verified_source(self, address: str, chain_id: int) -> dict[str, Any] | None:
        for name, fetcher in (("sourcify", self.sourcify_fetch), ("etherscan", self.etherscan_fetch)):
            value = await fetcher(address, chain_id)
            if value:
                item = dict(value)
                item.setdefault("provider", name)
                return item
        return None

    async def fetch_bytecode(self, address: str, chain_id: int, block_number: int | None = None) -> str:
        return await self.bytecode_fetch(address, chain_id, block_number)

    @staticmethod
    def compiler_divergence(metadata_compiler: str | None, observed_compiler: str | None) -> dict[str, Any]:
        expected = _compiler_core(metadata_compiler)
        observed = _compiler_core(observed_compiler)
        return {
            "expected": expected,
            "observed": observed,
            "diverged": bool(expected and observed and expected != observed),
        }


def normalize_slither(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    values = raw.get("detectors") if isinstance(raw, Mapping) else None
    findings: list[Finding] = []
    for detector in values if isinstance(values, list) else []:
        if not isinstance(detector, Mapping):
            continue
        elements = detector.get("elements") if isinstance(detector.get("elements"), list) else []
        first = elements[0] if elements and isinstance(elements[0], Mapping) else {}
        source = first.get("source_mapping") if isinstance(first.get("source_mapping"), Mapping) else {}
        function = str(first.get("name") or detector.get("function") or "")
        detector_id = str(detector.get("check") or detector.get("id") or "slither.unknown")
        findings.append(
            Finding(
                title=str(detector.get("title") or detector.get("description") or detector_id).splitlines()[0][:300],
                severity=_severity(detector.get("impact")),
                vuln_type=str(detector.get("vuln_type") or detector_id),
                tool="slither",
                endpoint=target,
                description=str(detector.get("description") or ""),
                evidence={
                    "engine": "slither",
                    "engine_version": tool_version,
                    "detector_id": detector_id,
                    "function": function,
                    "source_sha256": source_sha256,
                    "source_location": {
                        "file": str(source.get("filename_relative") or source.get("filename_absolute") or target),
                        "lines": [int(value) for value in source.get("lines", []) if isinstance(value, int)],
                    },
                },
                confidence=0.75,
            )
        )
    return findings


def normalize_mythril(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    values = raw.get("issues") if isinstance(raw, Mapping) else None
    findings: list[Finding] = []
    for issue in values if isinstance(values, list) else []:
        if not isinstance(issue, Mapping):
            continue
        swc = str(issue.get("swc-id") or issue.get("swc_id") or "SWC-UNKNOWN")
        line = issue.get("lineno")
        location: dict[str, Any] = {"file": target}
        if isinstance(line, int):
            location["line"] = line
        if isinstance(issue.get("address"), int):
            location["bytecode_offset"] = int(issue["address"])
        findings.append(
            Finding(
                title=str(issue.get("title") or swc),
                severity=_severity(issue.get("severity")),
                vuln_type=str(issue.get("vuln_type") or swc),
                tool="mythril",
                endpoint=target,
                description=str(issue.get("description") or issue.get("description_head") or ""),
                evidence={
                    "engine": "mythril",
                    "engine_version": tool_version,
                    "swc_id": swc,
                    "function": str(issue.get("function") or ""),
                    "source_sha256": source_sha256,
                    "source_location": location,
                },
                confidence=0.72,
            )
        )
    return findings


def normalize_aderyn(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    values = raw.get("issues") if isinstance(raw, Mapping) else None
    findings: list[Finding] = []
    for issue in values if isinstance(values, list) else []:
        if not isinstance(issue, Mapping):
            continue
        detector_id = str(issue.get("detector") or issue.get("id") or issue.get("title") or "aderyn.unknown")
        line = issue.get("line")
        location: dict[str, Any] = {"file": str(issue.get("file") or target)}
        if isinstance(line, int):
            location["line"] = line
        findings.append(
            Finding(
                title=str(issue.get("title") or detector_id),
                severity=_severity(issue.get("severity")),
                vuln_type=str(issue.get("vuln_type") or detector_id),
                tool="aderyn",
                endpoint=target,
                description=str(issue.get("description") or ""),
                evidence={
                    "engine": "aderyn",
                    "engine_version": tool_version,
                    "detector_id": detector_id,
                    "function": str(issue.get("function") or ""),
                    "source_sha256": source_sha256,
                    "source_location": location,
                },
                confidence=0.68,
            )
        )
    return findings


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    evidence = finding.evidence
    function = str(evidence.get("function") or "").casefold()
    location = evidence.get("source_location") if isinstance(evidence.get("source_location"), Mapping) else {}
    line: Any = location.get("line")
    if line is None:
        lines = location.get("lines") if isinstance(location.get("lines"), list) else []
        line = lines[0] if lines else ""
    vuln = str(finding.vuln_type or finding.title).casefold()
    # Map common reentrancy labels without creating a detector/signature.
    if "reentr" in vuln:
        vuln = "reentrancy"
    return vuln, function, str(line)


def corroborate_findings(primary: Sequence[Finding], corroborator: Sequence[Finding]) -> list[Finding]:
    """Annotate existing primary findings when an independent engine agrees."""
    corroborator_keys = {_finding_key(item): item for item in corroborator}
    output: list[Finding] = []
    for finding in primary:
        data = finding.model_dump()
        evidence = dict(data.get("evidence") or {})
        match = corroborator_keys.get(_finding_key(finding))
        evidence["corroborated"] = match is not None
        evidence["corroborated_by"] = [str(match.tool)] if match is not None else []
        data["evidence"] = evidence
        output.append(Finding.model_validate(data))
    return output


_OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x10: "LT", 0x11: "GT",
    0x14: "EQ", 0x15: "ISZERO", 0x20: "SHA3", 0x30: "ADDRESS", 0x31: "BALANCE", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x50: "POP", 0x51: "MLOAD",
    0x52: "MSTORE", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x5B: "JUMPDEST",
    0xF1: "CALL", 0xF3: "RETURN", 0xFD: "REVERT", 0xFF: "SELFDESTRUCT",
}


def disassemble_bytecode(bytecode: str) -> list[dict[str, Any]]:
    text = str(bytecode).strip()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2:
        raise ValueError("EVM bytecode hex must have an even length")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("invalid EVM bytecode hex") from exc
    output: list[dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        opcode = raw[offset]
        start = offset
        offset += 1
        operand = b""
        if 0x60 <= opcode <= 0x7F:
            width = opcode - 0x5F
            operand = raw[offset : offset + width]
            offset += len(operand)
            name = f"PUSH{width}"
        else:
            name = _OPCODES.get(opcode, f"OP_{opcode:02X}")
        output.append({"offset_start": start, "offset_end": offset, "opcode": name, "operand": operand.hex()})
    return output


def deterministic_web3_report(result: Mapping[str, Any]) -> bytes:
    findings = []
    for item in result.get("findings", []):
        finding = item.model_dump() if isinstance(item, Finding) else dict(item)
        findings.append(finding)
    findings.sort(key=lambda item: (str(item.get("tool")), str(item.get("vuln_type")), str(item.get("title")), str(item.get("endpoint"))))
    payload = {
        "schema": "windeep.web3-report.v1",
        "contract_address": result.get("contract_address"),
        "chain_id": result.get("chain_id"),
        "block_number": result.get("block_number"),
        "source_artifact_sha256": result.get("source_artifact_sha256"),
        "bytecode_artifact_sha256": result.get("bytecode_artifact_sha256"),
        "disassembly_artifact_sha256": result.get("disassembly_artifact_sha256"),
        "compiler_divergence": result.get("compiler_divergence"),
        "findings": findings,
        "provenance": sorted(result.get("provenance") or [], key=lambda item: _canonical(item)),
    }
    return _canonical(payload) + b"\n"


class Web3AuditService:
    """Orchestrate verified-source or bytecode-only Web3 analysis."""

    def __init__(
        self,
        *,
        store: Any,
        source_provider: Any,
        tool_runner: Callable[[str, str, dict[str, Any]], Awaitable[Any]],
        preflight: Callable[[str], None] | None = None,
        audit: Any | None = None,
        database: Any | None = None,
        engine_versions: Mapping[str, str] | None = None,
        enable_aderyn: bool = False,
    ) -> None:
        self.store = store
        self.source_provider = source_provider
        self.tool_runner = tool_runner
        self.preflight = preflight
        self.audit = audit
        self.database = database
        self.engine_versions = {"slither": "0.11.3", "mythril": "0.24.8", "aderyn": "0.3.2", **dict(engine_versions or {})}
        self.enable_aderyn = enable_aderyn

    def _authorize(self, action: str) -> None:
        if self.preflight is not None:
            self.preflight(action)

    def _persist_source_row(
        self,
        *,
        scan_id: int,
        address: str,
        chain_id: int,
        block_number: int | None,
        provider: str,
        source_sha256: str,
        compiler_version: str | None,
    ) -> int | None:
        if self.database is None:
            return None
        now = time.time()
        with self.database._connect() as conn:
            previous = conn.execute(
                "SELECT id FROM web3_source_artifact WHERE scan_id = ? AND contract_address = ? AND chain_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id, address, chain_id),
            ).fetchone()
            cursor = conn.execute(
                """
                INSERT INTO web3_source_artifact(
                    scan_id, contract_address, chain_id, block_number, provider,
                    source_sha256, compiler_version, supersedes_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, address, chain_id, block_number, provider, source_sha256, compiler_version,
                    int(previous["id"]) if previous is not None else None, now,
                ),
            )
            return int(cursor.lastrowid)

    def _persist_engine_run(
        self,
        *,
        scan_id: int,
        source_artifact_id: int | None,
        engine: str,
        input_sha256: str,
        output: Any,
    ) -> int | None:
        if self.database is None:
            return None
        output_bytes = _canonical(output)
        now = time.time()
        with self.database._connect() as conn:
            previous = conn.execute(
                "SELECT id FROM web3_engine_run WHERE scan_id = ? AND engine = ? ORDER BY id DESC LIMIT 1",
                (scan_id, engine),
            ).fetchone()
            cursor = conn.execute(
                """
                INSERT INTO web3_engine_run(
                    scan_id, source_artifact_id, engine, engine_version,
                    input_sha256, output_sha256, supersedes_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, source_artifact_id, engine, self.engine_versions.get(engine, "unknown"),
                    input_sha256, _sha256(output_bytes), int(previous["id"]) if previous is not None else None, now,
                ),
            )
            return int(cursor.lastrowid)

    async def _run_engine(self, name: str, target: str, options: dict[str, Any]) -> Any:
        self._authorize(f"engine:{name}")
        return await self.tool_runner(name, target, options)

    async def audit(self, *, scan_id: int, contract_address: str, chain_id: int) -> dict[str, Any]:
        address = str(contract_address).strip()
        if not (address.startswith("0x") and len(address) == 42):
            raise ValueError("contract_address must be a 20-byte hex address")
        if chain_id <= 0:
            raise ValueError("chain_id must be positive")
        self._authorize("source:verified")
        verified = await self.source_provider.fetch_verified_source(address, chain_id)
        findings: list[Finding] = []
        provenance: list[dict[str, Any]] = []
        source_sha = None
        bytecode_sha = None
        disassembly_sha = None
        block_number: int | None = None
        compiler_divergence: dict[str, Any] | None = None

        if verified:
            source_text = str(verified.get("source") or "")
            if not source_text:
                raise ValueError("verified source provider returned an empty source")
            source_name = str(verified.get("source_name") or "Contract.sol")
            block_number = int(verified["block_number"]) if verified.get("block_number") is not None else None
            provider_name = str(verified.get("provider") or "verified")
            compiler_version = str(verified.get("compiler_version") or "") or None
            source_ref = self.store.put(
                scan_id=scan_id,
                tool_run_id=None,
                kind="web3.verified_source",
                media_type="text/plain",
                content=source_text.encode("utf-8"),
                reason=f"cache verified Web3 source from {provider_name}",
                metadata={"source_name": source_name, "provider": provider_name, "chain_id": chain_id, "contract_address": address},
            )
            source_sha = str(source_ref.sha256)
            source_row = self._persist_source_row(
                scan_id=scan_id,
                address=address,
                chain_id=chain_id,
                block_number=block_number,
                provider=provider_name,
                source_sha256=source_sha,
                compiler_version=compiler_version,
            )
            slither_raw = await self._run_engine(
                "slither",
                source_name,
                {"source": source_text, "source_sha256": source_sha, "compiler_version": compiler_version, "read_only": True},
            )
            self._persist_engine_run(scan_id=scan_id, source_artifact_id=source_row, engine="slither", input_sha256=source_sha, output=slither_raw)
            slither = normalize_slither(slither_raw if isinstance(slither_raw, Mapping) else {}, target=source_name, tool_version=self.engine_versions["slither"], source_sha256=source_sha)
            mythril_raw = await self._run_engine(
                "mythril",
                source_name,
                {"source": source_text, "source_sha256": source_sha, "compiler_version": compiler_version, "bytecode": False, "read_only": True},
            )
            self._persist_engine_run(scan_id=scan_id, source_artifact_id=source_row, engine="mythril", input_sha256=source_sha, output=mythril_raw)
            mythril = normalize_mythril(mythril_raw if isinstance(mythril_raw, Mapping) else {}, target=source_name, tool_version=self.engine_versions["mythril"], source_sha256=source_sha)
            if self.enable_aderyn:
                aderyn_raw = await self._run_engine(
                    "aderyn",
                    source_name,
                    {"source": source_text, "source_sha256": source_sha, "compiler_version": compiler_version, "read_only": True, "corroboration_only": True},
                )
                self._persist_engine_run(scan_id=scan_id, source_artifact_id=source_row, engine="aderyn", input_sha256=source_sha, output=aderyn_raw)
                aderyn = normalize_aderyn(aderyn_raw if isinstance(aderyn_raw, Mapping) else {}, target=source_name, tool_version=self.engine_versions["aderyn"], source_sha256=source_sha)
                slither = corroborate_findings(slither, aderyn)
            findings = [*slither, *mythril]
            observed_compiler = None
            if isinstance(slither_raw, Mapping):
                observed_compiler = slither_raw.get("compiler_version") or slither_raw.get("compiler")
            if hasattr(self.source_provider, "compiler_divergence"):
                compiler_divergence = self.source_provider.compiler_divergence(compiler_version, str(observed_compiler or "") or None)
            else:
                compiler_divergence = VerifiedSourceProvider.compiler_divergence(compiler_version, str(observed_compiler or "") or None)
        else:
            self._authorize("source:bytecode")
            bytecode = await self.source_provider.fetch_bytecode(address, chain_id, None)
            text = str(bytecode or "")
            if text in {"", "0x"}:
                raise ValueError("contract has no retrievable bytecode")
            raw_bytecode = bytes.fromhex(text[2:] if text.startswith("0x") else text)
            bytecode_ref = self.store.put(
                scan_id=scan_id,
                tool_run_id=None,
                kind="web3.bytecode",
                media_type="application/octet-stream",
                content=raw_bytecode,
                reason="cache read-only contract bytecode",
                metadata={"chain_id": chain_id, "contract_address": address},
            )
            bytecode_sha = str(bytecode_ref.sha256)
            disassembly = disassemble_bytecode(text)
            disassembly_bytes = _canonical({"schema": "windeep.evm-disassembly.v1", "instructions": disassembly}) + b"\n"
            disassembly_ref = self.store.put(
                scan_id=scan_id,
                tool_run_id=None,
                kind="web3.disassembly",
                media_type="application/json",
                content=disassembly_bytes,
                reason="cache deterministic EVM disassembly",
                metadata={"bytecode_sha256": bytecode_sha},
            )
            disassembly_sha = str(disassembly_ref.sha256)
            mythril_raw = await self._run_engine(
                "mythril",
                address,
                {
                    "bytecode": True,
                    "bytecode_hex": text,
                    "bytecode_sha256": bytecode_sha,
                    "disassembly_sha256": disassembly_sha,
                    "read_only": True,
                },
            )
            self._persist_engine_run(scan_id=scan_id, source_artifact_id=None, engine="mythril", input_sha256=bytecode_sha, output=mythril_raw)
            findings = normalize_mythril(
                mythril_raw if isinstance(mythril_raw, Mapping) else {},
                target=address,
                tool_version=self.engine_versions["mythril"],
                source_sha256=bytecode_sha,
            )
            for index, finding in enumerate(findings):
                data = finding.model_dump()
                evidence = dict(data.get("evidence") or {})
                evidence["bytecode_sha256"] = bytecode_sha
                evidence["disassembly_sha256"] = disassembly_sha
                location = evidence.get("source_location") if isinstance(evidence.get("source_location"), Mapping) else {}
                if "bytecode_offset" in location:
                    offset = int(location["bytecode_offset"])
                    instruction = next((item for item in disassembly if item["offset_start"] <= offset < item["offset_end"]), None)
                    if instruction:
                        evidence["bytecode_offset_range"] = [instruction["offset_start"], instruction["offset_end"]]
                data["evidence"] = evidence
                findings[index] = Finding.model_validate(data)

        enriched: list[Finding] = []
        for finding in findings:
            data = finding.model_dump()
            evidence = dict(data.get("evidence") or {})
            evidence.update(
                {
                    "contract_address": address,
                    "chain_id": chain_id,
                    "block_number": block_number,
                    "exploitability": "needs-human-review",
                }
            )
            data["evidence"] = evidence
            enriched.append(Finding.model_validate(data))
            provenance.append(
                {
                    "engine": evidence.get("engine"),
                    "engine_version": evidence.get("engine_version"),
                    "detector_id": evidence.get("detector_id") or evidence.get("swc_id"),
                    "function": evidence.get("function"),
                    "source_location": evidence.get("source_location"),
                    "source_sha256": evidence.get("source_sha256"),
                    "corroborated": bool(evidence.get("corroborated", False)),
                }
            )

        result = {
            "schema": "windeep.web3-audit.v1",
            "scan_id": scan_id,
            "contract_address": address,
            "chain_id": chain_id,
            "block_number": block_number,
            "source_artifact_sha256": source_sha,
            "bytecode_artifact_sha256": bytecode_sha,
            "disassembly_artifact_sha256": disassembly_sha,
            "compiler_divergence": compiler_divergence,
            "findings": enriched,
            "provenance": provenance,
        }
        if self.audit is not None:
            self.audit.append(
                "p5.web3.audit_completed",
                {
                    "scan_id": scan_id,
                    "contract_address": address,
                    "chain_id": chain_id,
                    "findings": len(enriched),
                    "verified_source": bool(source_sha),
                },
            )
        return result


__all__ = [
    "ReadOnlyWeb3Adapter",
    "VerifiedSource",
    "VerifiedSourceProvider",
    "Web3AuditService",
    "corroborate_findings",
    "deterministic_web3_report",
    "disassemble_bytecode",
    "normalize_aderyn",
    "normalize_mythril",
    "normalize_slither",
]
