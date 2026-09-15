"""Release-blocking v3.0.0 audit for the tester-first all-findings contract.

The audit is structural/deterministic and performs no external target activity.
Legacy release phases remain in ``release_audit_legacy.py``.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "reports" / "v3_release_audit.md"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contains(path: str, *needles: str) -> Check:
    body = text(path)
    missing = [needle for needle in needles if needle not in body]
    return Check(path, not missing, "present" if not missing else "missing: " + ", ".join(missing))


def forbidden_patterns() -> Check:
    paths = [
        *sorted((ROOT / "app" / "v3").glob("*.py")),
        ROOT / "app" / "capture" / "ip_tls.py",
    ]
    patterns = {
        "subprocess outside wrapper": re.compile(r"\b(?:subprocess\.|Popen\s*\(|os\.system\s*\()"),
        "shell=True": re.compile(r"shell\s*=\s*True"),
        "direct target HTTP client": re.compile(r"\b(?:requests|httpx|aiohttp)\."),
        "unregistered thread": re.compile(r"\bthreading\.Thread\s*\(|\bThread\s*\("),
        "remote dashboard bind": re.compile(r"0\.0\.0\.0"),
        "plaintext tempfile": re.compile(r"\btempfile\.(?:NamedTemporaryFile|mkstemp|mkdtemp)\b"),
        "literal secret assignment": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*=\s*['\"][^'\"]{8,}['\"]"),
    }
    hits: list[str] = []
    for path in paths:
        if not path.exists():
            hits.append(f"missing:{path.relative_to(ROOT)}")
            continue
        body = path.read_text(encoding="utf-8")
        for name, pattern in patterns.items():
            if pattern.search(body):
                hits.append(f"{path.relative_to(ROOT)}:{name}")
    return Check("C7 forbidden-pattern scan", not hits, "clean" if not hits else "; ".join(hits))


def migration_check() -> Check:
    body = text("app/data/migrations/0030_v3_release.py")
    required = [
        "CREATE TABLE IF NOT EXISTS v3_targets",
        "CREATE TABLE IF NOT EXISTS handling_classification",
        "CREATE TABLE IF NOT EXISTS verification_record",
        "CREATE TABLE IF NOT EXISTS verification_claim",
        "asset_class IN ('http','https','ipv4','ipv6')",
    ]
    forbidden = ["handling_policy", "handling_rule", "DROP TABLE evidence", "ALTER TABLE evidence", "UPDATE evidence SET"]
    missing = [item for item in required if item not in body]
    bad = [item for item in forbidden if item in body]
    ok = not missing and not bad
    detail = "0030 is additive and tester-triage based" if ok else f"missing={missing}; forbidden={bad}"
    return Check("0030 migration discipline", ok, detail)


def contract_check() -> Check:
    namespace: dict[str, object] = {}
    exec(compile(text("app/v3/contracts.py"), "app/v3/contracts.py", "exec"), namespace)
    contracts = namespace.get("PUBLIC_CONTRACTS")
    events = namespace.get("V3_EVENT_TYPES")
    expected_contracts = {
        "sse": "windeep.sse.v1",
        "har_extension": "windeep.har-extension.v1",
        "evidence_bundle": "windeep.evidence-bundle.v1",
        "artifact": "windeep.artifact.v1",
        "report": "windeep.report.v1",
        "verification": "windeep.verification.v1",
    }
    expected_events = (
        "finding", "progress", "log", "evidence", "chain", "ranked", "verification", "disposition", "target"
    )
    ok = contracts == expected_contracts and events == expected_events
    return Check("frozen v3 public contracts", ok, "schemas/event vocabulary unchanged" if ok else f"contracts={contracts!r}; events={events!r}")


def all_findings_check() -> Check:
    triage = text("app/v3/triage.py")
    report = text("app/v3/reporting.py")
    api = text("app/v3/api.py")
    policy_terms = ("handling_policy", "handling_rule", "policy: unspecified")
    ok = (
        "SELECT id FROM findings WHERE scan_id = ?" in triage
        and '"disposition": "needs-review"' in triage
        and "for index, item in enumerate(ranked" in report
        and "not-recorded" in report
        and not any(term in report for term in policy_terms)
        and '"report_inclusion": "all-findings"' in api
        and '"policy_required": False' in api
        and '"verification_required_for_inclusion": False' in api
    )
    return Check("all-findings non-suppression", ok, "classification/verification affect display, never inclusion" if ok else "all-findings markers are incomplete")


def preflight_check() -> Check:
    api = text("app/v3/api.py")
    server = text("app/server.py")
    ok = (
        "SELECT target_id, consent_ref FROM scan_authorizations" in api
        and "preflight_for(target, consent_id)" in api
        and "scan_access(scan_id)" in api
        and "register_v3_api(" in server
        and "preflight_for=preflight_for" in server
        and "V3EventPublisher(database, crypto, audit, broadcast=broadcast)" in server
    )
    return Check("v3 stored-consent preflight wiring", ok, "v3 reads/triage/report share the existing live preflight boundary" if ok else "preflight/server registration markers missing")


def sse_check() -> Check:
    events = text("app/v3/events.py")
    v2 = text("app/v2_api.py")
    ok = (
        '"schema": "windeep.sse.v1"' in events
        and "BEGIN IMMEDIATE" in events
        and "MAX(seq)" in events
        and "sanitize_export" in events
        and "self.replay.list_after" in events
        and 'request.headers.get("Last-Event-ID"' in v2
        and "scan event gap detected" in text("app/v2_pipeline.py")
    )
    return Check("frozen gap-free SSE integration", ok, "v3 writes the encrypted v1 sequence and P0 replays it with Last-Event-ID" if ok else "SSE persistence/replay markers missing")


def export_redaction_check() -> Check:
    events = text("app/v3/events.py")
    reporting = text("app/v3/reporting.py")
    ok = "sanitize_export" in events and "redact_text" in reporting and "redact_url" in reporting
    return Check("export redaction surface", ok, "SSE/report surfaces invoke existing redaction helpers" if ok else "redaction helper missing")


def ui_docs_check() -> Check:
    required = [
        "docs/handling_alignment.md",
        "docs/target_classes.md",
        "docs/verification_model.md",
        "docs/threat_model.md",
        "docs/glossary.md",
        "docs/operator_runbook.md",
        "RELEASE_CHECKLIST.md",
        "app/static/v3.js",
    ]
    missing = [path for path in required if not (ROOT / path).exists()]
    ui = text("app/static/v3.js") if not missing else ""
    markers = ["Actionable", "Needs-review", "Not-actionable", "Why this rank", "verification"]
    missing_markers = [marker for marker in markers if marker not in ui]
    ok = not missing and not missing_markers
    return Check("v3 docs/UI surface", ok, "required docs and triage UI present" if ok else f"missing={missing}; ui={missing_markers}")


def version_changelog_check() -> Check:
    version = text("VERSION").strip()
    changelog = text("CHANGELOG.md")
    required = ["## [3.0.0]", "### Breaking changes", "P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"]
    ok = version == "3.0.0" and all(marker in changelog for marker in required)
    return Check("version/changelog cut", ok, f"VERSION={version}; v3 phase map={'present' if ok else 'incomplete'}")


def threat_model_check() -> Check:
    body = text("docs/threat_model.md")
    markers = [
        "IP/CIDR declaration used as a preflight bypass",
        "Undeclared SNI, Host, or non-standard port injection",
        "Literal-IP TLS verification ambiguity",
        "Tester triage prominence",
        "tests/test_v3_manual_triage.py",
    ]
    missing = [marker for marker in markers if marker not in body]
    return Check("v3 threat-model coverage", not missing, "V3-A/V3-B threats documented" if not missing else "missing: " + ", ".join(missing))


def run() -> tuple[bool, list[Check]]:
    checks = [
        version_changelog_check(),
        contract_check(),
        migration_check(),
        preflight_check(),
        all_findings_check(),
        sse_check(),
        export_redaction_check(),
        forbidden_patterns(),
        ui_docs_check(),
        threat_model_check(),
        contains("tests/test_v3_target_classes.py", "undeclared", "CIDR", "ip_url"),
        contains("tests/test_v3_manual_triage.py", "not-actionable", "every", "deterministic"),
        contains("tests/test_v3_release_polish.py", "Last-Event-ID", "all-findings"),
    ]
    return all(check.ok for check in checks), checks


def write_report(ok: bool, checks: list[Check]) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Windeep v3 release audit",
        "",
        f"Overall: **{'PASS' if ok else 'FAIL'}**",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for check in checks:
        lines.append(f"| {check.name} | **{'PASS' if check.ok else 'FAIL'}** | {check.detail.replace('|', '\\|')} |")
    lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ok, checks = run()
    write_report(ok, checks)
    for check in checks:
        print(f"[{'PASS' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
    print(f"V3 release audit: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
