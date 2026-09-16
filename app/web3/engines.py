"""Maintained-engine normalization and cross-engine corroboration for P5."""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from app.engine.tool_wrapper import Finding

_SLITHER_SWC = {
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "unchecked-transfer": "SWC-104",
    "unchecked-lowlevel": "SWC-104",
    "tx-origin": "SWC-115",
    "controlled-delegatecall": "SWC-112",
    "unprotected-upgrade": "SWC-105",
}


def _severity(value: Any) -> str:
    normalized = str(value or "info").strip().casefold()
    aliases = {"informational": "info", "optimization": "low", "warning": "medium"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"info", "low", "medium", "high", "critical"} else "info"


def _confidence(value: Any, *, default: float) -> float:
    text = str(value or "").casefold()
    if text == "high":
        return 0.90
    if text == "medium":
        return 0.72
    if text == "low":
        return 0.50
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _line_bounds(lines: Sequence[Any]) -> tuple[int | None, int | None]:
    values = sorted({int(value) for value in lines if isinstance(value, (int, str)) and str(value).isdigit()})
    return (values[0], values[-1]) if values else (None, None)


def _family(detector_id: str, swc_id: str | None) -> str:
    if swc_id and swc_id.upper().startswith("SWC-"):
        return swc_id.upper()
    text = re.sub(r"[^a-z0-9]+", "-", detector_id.casefold()).strip("-")
    for suffix in ("-eth", "-no-eth", "-high", "-medium", "-low"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return text


def normalize_slither(
    payload: Mapping[str, Any],
    *,
    target: str,
    version: str,
    chain_id: int,
    block_number: int,
    upstream_source: str = "slither-maintained-detectors",
) -> list[Finding]:
    """Normalize Slither JSON/SARIF-derived detector records without authoring detectors."""
    findings: list[Finding] = []
    results = payload.get("results") if isinstance(payload, Mapping) else None
    detectors = results.get("detectors", []) if isinstance(results, Mapping) else []
    for detector in detectors if isinstance(detectors, list) else []:
        if not isinstance(detector, Mapping):
            continue
        elements = detector.get("elements") if isinstance(detector.get("elements"), list) else []
        first = next((item for item in elements if isinstance(item, Mapping)), {})
        source_mapping = first.get("source_mapping") if isinstance(first.get("source_mapping"), Mapping) else {}
        lines = list(source_mapping.get("lines") or [])
        line_start, line_end = _line_bounds(lines)
        detector_id = str(detector.get("check") or "slither-detector")
        swc_id = str(detector.get("swc_id") or _SLITHER_SWC.get(detector_id, "")).strip() or None
        reproduction = [
            f"Re-run Slither {version} against the cached verified source artifact and inspect the detector location.",
        ]
        findings.append(
            Finding(
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
                    "detector_family": _family(detector_id, swc_id),
                    "swc_id": swc_id,
                    "confidence_label": str(detector.get("confidence") or ""),
                    "affected_function": first.get("name"),
                    "source_location": {
                        "file": source_mapping.get("filename_relative") or source_mapping.get("filename_absolute"),
                        "lines": lines,
                        "line_start": line_start,
                        "line_end": line_end,
                    },
                    "chain_id": int(chain_id),
                    "block_number": int(block_number),
                    "upstream_source": upstream_source,
                    "exploitability": "observed",
                    "reproduction_plan": reproduction,
                },
                confidence=_confidence(detector.get("confidence"), default=0.70),
            )
        )
    return findings


def normalize_aderyn(
    payload: Mapping[str, Any],
    *,
    target: str,
    version: str,
    chain_id: int,
    block_number: int,
    upstream_source: str = "aderyn-maintained-rules",
) -> list[Finding]:
    """Normalize Aderyn rule output using engine-supplied detector identity/location."""
    findings: list[Finding] = []
    issues = payload.get("issues", []) if isinstance(payload, Mapping) else []
    for issue in issues if isinstance(issues, list) else []:
        if not isinstance(issue, Mapping):
            continue
        detector_id = str(issue.get("detector_id") or issue.get("rule_id") or issue.get("id") or "aderyn-rule")
        swc_id = str(issue.get("swc_id") or issue.get("swc-id") or "").strip() or None
        start = issue.get("line_start")
        end = issue.get("line_end", start)
        line_start = int(start) if start is not None else None
        line_end = int(end) if end is not None else line_start
        source_file = issue.get("source_file") or issue.get("file")
        findings.append(
            Finding(
                title=str(issue.get("title") or detector_id),
                severity=_severity(issue.get("severity")),
                vuln_type="web3_static",
                tool="aderyn",
                endpoint=target,
                description=str(issue.get("description") or issue.get("message") or ""),
                evidence={
                    "engine": "aderyn",
                    "engine_version": version,
                    "detector_id": detector_id,
                    "detector_family": _family(detector_id, swc_id),
                    "swc_id": swc_id,
                    "affected_function": issue.get("function") or issue.get("affected_function"),
                    "source_location": {
                        "file": source_file,
                        "line_start": line_start,
                        "line_end": line_end,
                        "lines": list(range(line_start, line_end + 1)) if line_start is not None and line_end is not None and line_end - line_start <= 100 else [],
                    },
                    "chain_id": int(chain_id),
                    "block_number": int(block_number),
                    "upstream_source": upstream_source,
                    "exploitability": "observed",
                    "reproduction_plan": [
                        f"Re-run Aderyn {version} against the cached verified source artifact and inspect the recorded source range.",
                    ],
                },
                confidence=_confidence(issue.get("confidence"), default=0.78),
            )
        )
    return findings


def normalize_mythril(
    payload: Mapping[str, Any],
    *,
    target: str,
    version: str,
    chain_id: int,
    block_number: int,
    bytecode_sha256: str,
    source_verified: bool = True,
    disassembly_artifact_sha256: str | None = None,
    upstream_source: str = "mythril-swc",
) -> list[Finding]:
    """Normalize Mythril symbolic results and mark bytecode-only cases for human review."""
    findings: list[Finding] = []
    issues = payload.get("issues", []) if isinstance(payload, Mapping) else []
    for issue in issues if isinstance(issues, list) else []:
        if not isinstance(issue, Mapping):
            continue
        swc_id = str(issue.get("swc-id") or issue.get("swc_id") or "SWC-unknown")
        detector_id = swc_id if swc_id != "SWC-unknown" else str(issue.get("title") or "mythril-issue")
        offset = issue.get("address")
        offset_start = int(offset) if isinstance(offset, int) or (isinstance(offset, str) and offset.isdigit()) else None
        offset_end = offset_start
        exploitability = "observed" if source_verified else "needs-human-review"
        if source_verified:
            plan = [
                f"Re-run Mythril {version} with the recorded timeout/depth against the cached source/bytecode and inspect the normalized SWC location.",
            ]
        else:
            plan = [
                f"Re-run Mythril {version} with the recorded timeout/depth against the cached deployed bytecode artifact.",
                "Inspect the referenced disassembly offset range and static SWC evidence; stop before any state-changing validation.",
            ]
        evidence = {
            "engine": "mythril",
            "engine_version": version,
            "detector_id": detector_id,
            "detector_family": _family(detector_id, swc_id),
            "swc_id": swc_id,
            "affected_function": issue.get("function"),
            "source_location": {"line": issue.get("lineno")},
            "bytecode_sha256": bytecode_sha256,
            "bytecode_offset_start": offset_start,
            "bytecode_offset_end": offset_end,
            "chain_id": int(chain_id),
            "block_number": int(block_number),
            "upstream_source": upstream_source,
            "exploitability": exploitability,
            "reproduction_plan": plan,
        }
        if disassembly_artifact_sha256:
            evidence["disassembly_artifact_sha256"] = disassembly_artifact_sha256
        findings.append(
            Finding(
                title=str(issue.get("title") or swc_id),
                severity=_severity(issue.get("severity")),
                vuln_type="web3_static",
                tool="mythril",
                endpoint=target,
                description=str(issue.get("description-head") or issue.get("description") or ""),
                evidence=evidence,
                confidence=_confidence(issue.get("confidence"), default=0.80),
            )
        )
    return findings


def mythril_plan(*, bytecode_hex: str, timeout_seconds: int = 300, max_depth: int = 128) -> list[str]:
    """Build bounded argv for the maintained Mythril wrapper; no shell or transaction action."""
    if timeout_seconds < 1 or timeout_seconds > 1800:
        raise ValueError("Mythril execution timeout must be between 1 and 1800 seconds")
    if max_depth < 1 or max_depth > 4096:
        raise ValueError("Mythril max depth must be between 1 and 4096")
    clean = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    if not clean or any(char not in "0123456789abcdefABCDEF" for char in clean):
        raise ValueError("bytecode_hex must contain hexadecimal deployed bytecode")
    return [
        "myth",
        "analyze",
        "--code",
        clean,
        "--execution-timeout",
        str(int(timeout_seconds)),
        "--max-depth",
        str(int(max_depth)),
        "-o",
        "json",
    ]


def _location_key(evidence: Mapping[str, Any]) -> tuple[str, int | None, int | None, int | None, int | None]:
    location = evidence.get("source_location") if isinstance(evidence.get("source_location"), Mapping) else {}
    return (
        str(location.get("file") or ""),
        location.get("line_start") if isinstance(location.get("line_start"), int) else location.get("line") if isinstance(location.get("line"), int) else None,
        location.get("line_end") if isinstance(location.get("line_end"), int) else location.get("line") if isinstance(location.get("line"), int) else None,
        evidence.get("bytecode_offset_start") if isinstance(evidence.get("bytecode_offset_start"), int) else None,
        evidence.get("bytecode_offset_end") if isinstance(evidence.get("bytecode_offset_end"), int) else None,
    )


def corroborate_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Merge equivalent observations while preserving every independent engine record."""
    groups: dict[tuple[Any, ...], list[Finding]] = defaultdict(list)
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, Mapping) else {}
        family = str(evidence.get("swc_id") or evidence.get("detector_family") or evidence.get("detector_id") or finding.title)
        key = (family, str(evidence.get("affected_function") or ""), *_location_key(evidence))
        groups[key].append(finding)

    merged: list[Finding] = []
    for key in sorted(groups, key=lambda item: tuple("" if value is None else str(value) for value in item)):
        observations = groups[key]
        first = observations[0]
        engines = {str(item.evidence.get("engine") or item.tool) for item in observations}
        corroborated = len(engines) >= 2
        observation_rows = [
            {
                "engine": str(item.evidence.get("engine") or item.tool),
                "version": str(item.evidence.get("engine_version") or ""),
                "detector_id": str(item.evidence.get("detector_id") or ""),
                "swc_id": item.evidence.get("swc_id"),
                "confidence": float(item.confidence),
                "upstream_source": str(item.evidence.get("upstream_source") or ""),
            }
            for item in sorted(observations, key=lambda item: (str(item.evidence.get("engine") or item.tool), str(item.evidence.get("detector_id") or "")))
        ]
        best = max(observations, key=lambda item: (float(item.confidence), {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(item.severity, 0)))
        evidence = dict(best.evidence)
        evidence["corroborated"] = corroborated
        evidence["engine_observations"] = observation_rows
        evidence["engine_disagreement"] = len(observations) != len(engines) or len({item.severity for item in observations}) > 1
        confidence = min(0.99, max(float(item.confidence) for item in observations) + (0.08 if corroborated else 0.0))
        severity = best.severity
        location = evidence.get("source_location") if isinstance(evidence.get("source_location"), Mapping) else {}
        inspectable_source = bool(location.get("file") and (location.get("line_start") or location.get("line")))
        if severity in {"high", "critical"} and not corroborated and not inspectable_source:
            severity = "medium"
        merged.append(
            Finding(
                title=best.title,
                severity=severity,
                vuln_type=best.vuln_type,
                tool="+".join(sorted(engines)),
                endpoint=best.endpoint,
                description=best.description,
                evidence=evidence,
                confidence=confidence,
            )
        )
    return merged
