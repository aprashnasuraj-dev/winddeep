"""P5 static/read-only Web3 audit service with hash-addressed provenance."""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

from app.engine.tool_wrapper import Finding

_READ_ONLY_RPC = frozenset({
    "eth_chainId", "eth_blockNumber", "eth_getBalance", "eth_getBlockByHash",
    "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt",
    "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_call",
})
_COMPILER_RE = re.compile(r"v?(\d+\.\d+\.\d+)", re.I)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _severity(value: Any) -> str:
    text = str(value or "info").strip().lower()
    return text if text in {"critical", "high", "medium", "low", "info", "informational"} else "info"


def _compiler(value: str | None) -> str:
    match = _COMPILER_RE.search(str(value or ""))
    return match.group(1) if match else str(value or "").strip()


class ReadOnlyWeb3Adapter:
    """Hard allow-list around a JSON-RPC callable; signing/writes never pass through."""

    def __init__(self, rpc: Callable[[str, list[Any]], Any]) -> None:
        self.rpc = rpc

    def call(self, method: str, params: list[Any]) -> Any:
        name = str(method).strip()
        if name not in _READ_ONLY_RPC:
            raise PermissionError(f"RPC method is not read-only: {name}")
        return self.rpc(name, list(params))


class VerifiedSourceProvider:
    """Sourcify-first, Etherscan-second resolver with bytecode fallback support."""

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
        for provider, fetcher in (("sourcify", self.sourcify_fetch), ("etherscan", self.etherscan_fetch)):
            result = await fetcher(address, chain_id)
            if result:
                item = dict(result)
                item.setdefault("provider", provider)
                return item
        return None

    async def fetch_bytecode(self, address: str, chain_id: int, block_number: int | None = None) -> str:
        return await self.bytecode_fetch(address, chain_id, block_number)

    @staticmethod
    def compiler_divergence(expected: str | None, observed: str | None) -> dict[str, Any]:
        left, right = _compiler(expected), _compiler(observed)
        return {"expected": left, "observed": right, "diverged": bool(left and right and left != right)}


def normalize_slither(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    output: list[Finding] = []
    for item in raw.get("detectors", []) if isinstance(raw.get("detectors"), list) else []:
        if not isinstance(item, Mapping):
            continue
        elements = item.get("elements") if isinstance(item.get("elements"), list) else []
        first = elements[0] if elements and isinstance(elements[0], Mapping) else {}
        mapping = first.get("source_mapping") if isinstance(first.get("source_mapping"), Mapping) else {}
        detector_id = str(item.get("check") or item.get("id") or "slither.unknown")
        output.append(Finding(
            title=str(item.get("title") or item.get("description") or detector_id).splitlines()[0][:300],
            severity=_severity(item.get("impact")), vuln_type=detector_id, tool="slither", endpoint=target,
            description=str(item.get("description") or ""), confidence=0.75,
            evidence={"engine": "slither", "engine_version": tool_version, "detector_id": detector_id,
                      "function": str(first.get("name") or ""), "source_sha256": source_sha256,
                      "source_location": {"file": str(mapping.get("filename_relative") or target),
                                          "lines": [int(v) for v in mapping.get("lines", []) if isinstance(v, int)]}},
        ))
    return output


def normalize_mythril(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    output: list[Finding] = []
    for item in raw.get("issues", []) if isinstance(raw.get("issues"), list) else []:
        if not isinstance(item, Mapping):
            continue
        swc = str(item.get("swc-id") or item.get("swc_id") or "SWC-UNKNOWN")
        location: dict[str, Any] = {"file": target}
        if isinstance(item.get("lineno"), int):
            location["line"] = int(item["lineno"])
        if isinstance(item.get("address"), int):
            location["bytecode_offset"] = int(item["address"])
        output.append(Finding(
            title=str(item.get("title") or swc), severity=_severity(item.get("severity")), vuln_type=swc,
            tool="mythril", endpoint=target, description=str(item.get("description") or ""), confidence=0.72,
            evidence={"engine": "mythril", "engine_version": tool_version, "swc_id": swc,
                      "function": str(item.get("function") or ""), "source_sha256": source_sha256,
                      "source_location": location},
        ))
    return output


def normalize_aderyn(raw: Mapping[str, Any], *, target: str, tool_version: str, source_sha256: str) -> list[Finding]:
    output: list[Finding] = []
    for item in raw.get("issues", []) if isinstance(raw.get("issues"), list) else []:
        if not isinstance(item, Mapping):
            continue
        detector = str(item.get("detector") or item.get("id") or item.get("title") or "aderyn.unknown")
        location: dict[str, Any] = {"file": str(item.get("file") or target)}
        if isinstance(item.get("line"), int):
            location["line"] = int(item["line"])
        output.append(Finding(
            title=str(item.get("title") or detector), severity=_severity(item.get("severity")),
            vuln_type=str(item.get("vuln_type") or detector), tool="aderyn", endpoint=target,
            description=str(item.get("description") or ""), confidence=0.68,
            evidence={"engine": "aderyn", "engine_version": tool_version, "detector_id": detector,
                      "function": str(item.get("function") or ""), "source_sha256": source_sha256,
                      "source_location": location},
        ))
    return output


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    evidence = finding.evidence
    location = evidence.get("source_location") if isinstance(evidence.get("source_location"), Mapping) else {}
    line = location.get("line")
    if line is None:
        lines = location.get("lines") if isinstance(location.get("lines"), list) else []
        line = lines[0] if lines else ""
    vuln = str(finding.vuln_type).casefold()
    if "reentr" in vuln:
        vuln = "reentrancy"
    return vuln, str(evidence.get("function") or "").casefold().removesuffix("()"), str(line)


def corroborate_findings(primary: Sequence[Finding], corroborator: Sequence[Finding]) -> list[Finding]:
    matches = {_finding_key(item): item for item in corroborator}
    output: list[Finding] = []
    for item in primary:
        data = item.model_dump()
        evidence = dict(data.get("evidence") or {})
        match = matches.get(_finding_key(item))
        evidence.update({"corroborated": match is not None, "corroborated_by": [match.tool] if match else []})
        data["evidence"] = evidence
        output.append(Finding.model_validate(data))
    return output


_OPCODES = {0x00: "STOP", 0x01: "ADD", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
            0x5B: "JUMPDEST", 0xF1: "CALL", 0xF3: "RETURN", 0xFD: "REVERT", 0xFF: "SELFDESTRUCT"}


def disassemble_bytecode(bytecode: str) -> list[dict[str, Any]]:
    text = str(bytecode).strip().removeprefix("0x")
    if len(text) % 2:
        raise ValueError("EVM bytecode hex must have an even length")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("invalid EVM bytecode hex") from exc
    output, offset = [], 0
    while offset < len(raw):
        start, opcode = offset, raw[offset]
        offset += 1
        width = opcode - 0x5F if 0x60 <= opcode <= 0x7F else 0
        operand = raw[offset:offset + width]
        offset += len(operand)
        output.append({"offset_start": start, "offset_end": offset,
                       "opcode": f"PUSH{width}" if width else _OPCODES.get(opcode, f"OP_{opcode:02X}"),
                       "operand": operand.hex()})
    return output


def deterministic_web3_report(result: Mapping[str, Any]) -> bytes:
    findings = [item.model_dump() if isinstance(item, Finding) else dict(item) for item in result.get("findings", [])]
    findings.sort(key=lambda item: (str(item.get("tool")), str(item.get("vuln_type")), str(item.get("title"))))
    return _canonical({
        "schema": "windeep.web3-report.v1", "contract_address": result.get("contract_address"),
        "chain_id": result.get("chain_id"), "block_number": result.get("block_number"),
        "source_artifact_sha256": result.get("source_artifact_sha256"),
        "bytecode_artifact_sha256": result.get("bytecode_artifact_sha256"),
        "disassembly_artifact_sha256": result.get("disassembly_artifact_sha256"),
        "compiler_divergence": result.get("compiler_divergence"), "findings": findings,
        "provenance": sorted(result.get("provenance") or [], key=_canonical),
    }) + b"\n"


class Web3AuditService:
    """Run Slither/Mythril over verified source, or Mythril over read-only bytecode."""

    def __init__(self, *, store: Any, source_provider: Any,
                 tool_runner: Callable[[str, str, dict[str, Any]], Awaitable[Any]],
                 preflight: Callable[[str], None] | None = None, audit: Any | None = None,
                 database: Any | None = None, engine_versions: Mapping[str, str] | None = None,
                 enable_aderyn: bool = False) -> None:
        self.store, self.source_provider, self.tool_runner = store, source_provider, tool_runner
        self.preflight, self.audit_log, self.database = preflight, audit, database
        self.engine_versions = {"slither": "0.11.3", "mythril": "0.24.8", "aderyn": "0.3.2", **dict(engine_versions or {})}
        self.enable_aderyn = enable_aderyn

    def _authorize(self, action: str) -> None:
        if self.preflight:
            self.preflight(action)

    async def _run(self, name: str, target: str, options: dict[str, Any]) -> Any:
        self._authorize(f"engine:{name}")
        return await self.tool_runner(name, target, options)

    def _persist_source(self, scan_id: int, address: str, chain_id: int, block: int | None,
                        provider: str, digest: str, compiler: str | None) -> int | None:
        if self.database is None:
            return None
        with self.database._connect() as conn:
            prev = conn.execute("SELECT id FROM web3_source_artifact WHERE scan_id=? AND contract_address=? AND chain_id=? ORDER BY id DESC LIMIT 1",
                                (scan_id, address, chain_id)).fetchone()
            cur = conn.execute("INSERT INTO web3_source_artifact(scan_id,contract_address,chain_id,block_number,provider,source_sha256,compiler_version,supersedes_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                               (scan_id, address, chain_id, block, provider, digest, compiler, int(prev["id"]) if prev else None, time.time()))
            return int(cur.lastrowid)

    def _persist_run(self, scan_id: int, source_id: int | None, engine: str, input_sha: str, output: Any) -> None:
        if self.database is None:
            return
        with self.database._connect() as conn:
            prev = conn.execute("SELECT id FROM web3_engine_run WHERE scan_id=? AND engine=? ORDER BY id DESC LIMIT 1", (scan_id, engine)).fetchone()
            conn.execute("INSERT INTO web3_engine_run(scan_id,source_artifact_id,engine,engine_version,input_sha256,output_sha256,supersedes_id,created_at) VALUES (?,?,?,?,?,?,?,?)",
                         (scan_id, source_id, engine, self.engine_versions.get(engine, "unknown"), input_sha,
                          _sha256(_canonical(output)), int(prev["id"]) if prev else None, time.time()))

    async def audit(self, *, scan_id: int, contract_address: str, chain_id: int) -> dict[str, Any]:
        address = str(contract_address).strip()
        if not (address.startswith("0x") and len(address) == 42):
            raise ValueError("contract_address must be a 20-byte hex address")
        if chain_id <= 0:
            raise ValueError("chain_id must be positive")
        self._authorize("source:verified")
        verified = await self.source_provider.fetch_verified_source(address, chain_id)
        source_sha = bytecode_sha = disassembly_sha = None
        block_number = None
        divergence = None
        findings: list[Finding]

        if verified:
            source = str(verified.get("source") or "")
            if not source:
                raise ValueError("verified source provider returned an empty source")
            name = str(verified.get("source_name") or "Contract.sol")
            provider = str(verified.get("provider") or "verified")
            compiler = str(verified.get("compiler_version") or "") or None
            block_number = int(verified["block_number"]) if verified.get("block_number") is not None else None
            ref = self.store.put(scan_id=scan_id, tool_run_id=None, kind="web3.verified_source", media_type="text/plain",
                                 content=source.encode(), reason=f"cache verified Web3 source from {provider}",
                                 metadata={"source_name": name, "provider": provider, "chain_id": chain_id, "contract_address": address})
            source_sha = str(ref.sha256)
            source_id = self._persist_source(scan_id, address, chain_id, block_number, provider, source_sha, compiler)
            slither_raw = await self._run("slither", name, {"source": source, "source_sha256": source_sha, "compiler_version": compiler, "read_only": True})
            mythril_raw = await self._run("mythril", name, {"source": source, "source_sha256": source_sha, "compiler_version": compiler, "bytecode": False, "read_only": True})
            self._persist_run(scan_id, source_id, "slither", source_sha, slither_raw)
            self._persist_run(scan_id, source_id, "mythril", source_sha, mythril_raw)
            slither = normalize_slither(slither_raw if isinstance(slither_raw, Mapping) else {}, target=name, tool_version=self.engine_versions["slither"], source_sha256=source_sha)
            if self.enable_aderyn:
                aderyn_raw = await self._run("aderyn", name, {"source": source, "source_sha256": source_sha, "compiler_version": compiler, "read_only": True, "corroboration_only": True})
                self._persist_run(scan_id, source_id, "aderyn", source_sha, aderyn_raw)
                slither = corroborate_findings(slither, normalize_aderyn(aderyn_raw if isinstance(aderyn_raw, Mapping) else {}, target=name, tool_version=self.engine_versions["aderyn"], source_sha256=source_sha))
            findings = slither + normalize_mythril(mythril_raw if isinstance(mythril_raw, Mapping) else {}, target=name, tool_version=self.engine_versions["mythril"], source_sha256=source_sha)
            observed = slither_raw.get("compiler_version") if isinstance(slither_raw, Mapping) else None
            divergence_fn = getattr(self.source_provider, "compiler_divergence", VerifiedSourceProvider.compiler_divergence)
            divergence = divergence_fn(compiler, str(observed or "") or None)
        else:
            self._authorize("source:bytecode")
            bytecode = str(await self.source_provider.fetch_bytecode(address, chain_id, None) or "")
            if bytecode in {"", "0x"}:
                raise ValueError("contract has no retrievable bytecode")
            raw = bytes.fromhex(bytecode.removeprefix("0x"))
            ref = self.store.put(scan_id=scan_id, tool_run_id=None, kind="web3.bytecode", media_type="application/octet-stream",
                                 content=raw, reason="cache read-only contract bytecode", metadata={"chain_id": chain_id, "contract_address": address})
            bytecode_sha = str(ref.sha256)
            disassembly = disassemble_bytecode(bytecode)
            dis_ref = self.store.put(scan_id=scan_id, tool_run_id=None, kind="web3.disassembly", media_type="application/json",
                                     content=_canonical({"schema": "windeep.evm-disassembly.v1", "instructions": disassembly}) + b"\n",
                                     reason="cache deterministic EVM disassembly", metadata={"bytecode_sha256": bytecode_sha})
            disassembly_sha = str(dis_ref.sha256)
            mythril_raw = await self._run("mythril", address, {"bytecode": True, "bytecode_hex": bytecode, "bytecode_sha256": bytecode_sha,
                                                                "disassembly_sha256": disassembly_sha, "read_only": True})
            self._persist_run(scan_id, None, "mythril", bytecode_sha, mythril_raw)
            findings = normalize_mythril(mythril_raw if isinstance(mythril_raw, Mapping) else {}, target=address,
                                         tool_version=self.engine_versions["mythril"], source_sha256=bytecode_sha)
            for finding in findings:
                finding.evidence.update({"bytecode_sha256": bytecode_sha, "disassembly_sha256": disassembly_sha})
                offset = (finding.evidence.get("source_location") or {}).get("bytecode_offset")
                if isinstance(offset, int):
                    ins = next((row for row in disassembly if row["offset_start"] <= offset < row["offset_end"]), None)
                    if ins:
                        finding.evidence["bytecode_offset_range"] = [ins["offset_start"], ins["offset_end"]]

        provenance = []
        for finding in findings:
            finding.evidence.update({"contract_address": address, "chain_id": chain_id, "block_number": block_number,
                                     "exploitability": "needs-human-review"})
            provenance.append({"engine": finding.evidence.get("engine"), "engine_version": finding.evidence.get("engine_version"),
                               "detector_id": finding.evidence.get("detector_id") or finding.evidence.get("swc_id"),
                               "function": finding.evidence.get("function"), "source_location": finding.evidence.get("source_location"),
                               "source_sha256": finding.evidence.get("source_sha256"),
                               "corroborated": bool(finding.evidence.get("corroborated", False))})
        result = {"schema": "windeep.web3-audit.v1", "scan_id": scan_id, "contract_address": address, "chain_id": chain_id,
                  "block_number": block_number, "source_artifact_sha256": source_sha, "bytecode_artifact_sha256": bytecode_sha,
                  "disassembly_artifact_sha256": disassembly_sha, "compiler_divergence": divergence,
                  "findings": findings, "provenance": provenance}
        if self.audit_log is not None:
            self.audit_log.append("p5.web3.audit_completed", {"scan_id": scan_id, "contract_address": address, "chain_id": chain_id,
                                                               "findings": len(findings), "verified_source": bool(source_sha)})
        return result


__all__ = ["ReadOnlyWeb3Adapter", "VerifiedSourceProvider", "Web3AuditService", "corroborate_findings",
           "deterministic_web3_report", "disassemble_bytecode", "normalize_aderyn", "normalize_mythril", "normalize_slither"]
