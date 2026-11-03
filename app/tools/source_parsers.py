"""Structured parsers for source-code audit integrations.

The parsers preserve rule IDs, locations and native evidence so the reasoning
layer can distinguish a scanner diagnostic from a confirmed system-level flaw.
"""
from __future__ import annotations

import json
from typing import Any


def _severity(value: str, *, default: str = "info") -> str:
    raw = str(value or default).strip().lower()
    if raw in {"critical", "high", "medium", "low", "info"}:
        return raw
    if raw in {"error", "warning", "warn"}:
        return "medium" if raw == "error" else "low"
    return default


def _confidence(value: str) -> float:
    return {"high": 0.92, "medium": 0.78, "low": 0.62}.get(str(value or "").lower(), 0.7)


def parse_gosec_json(raw: str, tool: str, target: str) -> list[Any]:
    from app.engine.tool_wrapper import Finding

    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return []
    issues = payload.get("Issues") if isinstance(payload, dict) else None
    if not isinstance(issues, list):
        return []

    findings: list[Finding] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        rule = str(issue.get("rule_id") or issue.get("RuleID") or "gosec").strip()
        details = str(issue.get("details") or issue.get("Details") or "Go security diagnostic").strip()
        filename = str(issue.get("file") or issue.get("File") or "").strip()
        try:
            line = int(issue.get("line") or issue.get("Line") or 0)
        except (TypeError, ValueError):
            line = 0
        try:
            column = int(issue.get("column") or issue.get("Column") or 0)
        except (TypeError, ValueError):
            column = 0
        sev = _severity(str(issue.get("severity") or issue.get("Severity") or "medium"), default="medium")
        conf = _confidence(str(issue.get("confidence") or issue.get("Confidence") or "medium"))
        cwe = issue.get("cwe") or issue.get("CWE") or {}
        findings.append(Finding(
            title=f"{rule}: {details}",
            severity=sev,
            vuln_type=f"gosec_{rule.lower()}",
            tool=tool,
            endpoint=target,
            description=details,
            evidence={"rule_id": rule, "cwe": cwe, "issue": issue, "source": {"file": filename, "line": line, "column": column}},
            confidence=conf,
            source_file=filename or None,
            source_line=line or None,
            source_column=column or None,
        ))
    return findings


def _trace_level(trace: list[dict[str, Any]]) -> int:
    best = 0
    for frame in trace:
        if not isinstance(frame, dict):
            continue
        if str(frame.get("function") or frame.get("Function") or "").strip():
            best = max(best, 3)
        elif str(frame.get("package") or frame.get("Package") or "").strip():
            best = max(best, 2)
        elif str(frame.get("module") or frame.get("Module") or "").strip():
            best = max(best, 1)
    return best


def parse_govulncheck_json(raw: str, tool: str, target: str) -> list[Any]:
    """Prefer symbol-reachable findings over package/module-only duplicates."""
    from app.engine.tool_wrapper import Finding

    osv: dict[str, dict[str, Any]] = {}
    selected: dict[str, tuple[int, dict[str, Any]]] = {}
    config: dict[str, Any] = {}
    sbom: dict[str, Any] = {}
    for raw_line in (raw or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("config"), dict):
            config = item["config"]
        if isinstance(item.get("SBOM"), dict):
            sbom = item["SBOM"]
        record = item.get("osv")
        if isinstance(record, dict):
            osv_id = str(record.get("id") or record.get("ID") or "").strip()
            if osv_id:
                osv[osv_id] = record
        finding = item.get("finding")
        if not isinstance(finding, dict):
            continue
        osv_id = str(finding.get("osv") or finding.get("OSV") or "").strip()
        if not osv_id:
            continue
        trace = finding.get("trace") if isinstance(finding.get("trace"), list) else []
        level = _trace_level(trace)
        previous = selected.get(osv_id)
        if previous is None or level > previous[0]:
            selected[osv_id] = (level, finding)

    findings: list[Finding] = []
    for osv_id, (level, finding) in selected.items():
        record = osv.get(osv_id, {})
        aliases = record.get("aliases") if isinstance(record.get("aliases"), list) else []
        summary = str(record.get("summary") or record.get("details") or osv_id).strip()
        fixed = str(finding.get("fixed_version") or finding.get("fixedVersion") or "").strip()
        trace = finding.get("trace") if isinstance(finding.get("trace"), list) else []
        symbol = next((f for f in trace if isinstance(f, dict) and str(f.get("function") or f.get("Function") or "").strip()), None)
        package = next((f for f in trace if isinstance(f, dict) and str(f.get("package") or f.get("Package") or "").strip()), None)
        frame = symbol or package or (trace[0] if trace and isinstance(trace[0], dict) else {})
        pos = frame.get("position") or frame.get("Position") or {}
        if not isinstance(pos, dict):
            pos = {}
        filename = str(pos.get("filename") or pos.get("Filename") or "").strip()
        try:
            line = int(pos.get("line") or pos.get("Line") or 0)
        except (TypeError, ValueError):
            line = 0
        reachability = {3: "symbol", 2: "package", 1: "module"}.get(level, "unknown")
        findings.append(Finding(
            title=f"{osv_id}: {summary}",
            severity="high" if level >= 3 else "medium",
            vuln_type="go_known_vulnerability",
            tool=tool,
            endpoint=target,
            description=summary,
            evidence={
                "osv_id": osv_id,
                "aliases": aliases,
                "reachability": reachability,
                "fixed_version": fixed,
                "trace": trace,
                "osv": record,
                "govulncheck_config": config,
                "sbom": sbom,
            },
            confidence=0.94 if level >= 3 else 0.82,
            source_file=filename or None,
            source_line=line or None,
        ))
    return findings


def parse_staticcheck_jsonl(raw: str, tool: str, target: str) -> list[Any]:
    from app.engine.tool_wrapper import Finding

    findings: list[Finding] = []
    for raw_line in (raw or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "staticcheck").strip()
        message = str(item.get("message") or "Go correctness diagnostic").strip()
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        filename = str(location.get("file") or "").strip()
        try:
            lineno = int(location.get("line") or 0)
        except (TypeError, ValueError):
            lineno = 0
        try:
            column = int(location.get("column") or 0)
        except (TypeError, ValueError):
            column = 0
        raw_severity = str(item.get("severity") or "warning")
        findings.append(Finding(
            title=f"{code}: {message}",
            severity=_severity(raw_severity, default="low"),
            vuln_type=f"staticcheck_{code.lower()}",
            tool=tool,
            endpoint=target,
            description=message,
            evidence={"check": code, "diagnostic": item, "source": {"file": filename, "line": lineno, "column": column}},
            confidence=0.86 if code.startswith("SA") else 0.72,
            source_file=filename or None,
            source_line=lineno or None,
            source_column=column or None,
        ))
    return findings
