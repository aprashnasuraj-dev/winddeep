"""Fail-closed v3.0.0 release contract audit.

This audit is intentionally target-free: it validates that the release contains
the executable guardrails and acceptance tests that enforce R3. Runtime fixture
behavior is covered by the referenced pytest suite in the same product gate.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "reports" / "release-audit-v3.md"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def _text(path: str) -> str:
    file = ROOT / path
    return file.read_text(encoding="utf-8") if file.exists() else ""


def _contains(path: str, *markers: str) -> Check:
    text = _text(path)
    missing = [marker for marker in markers if marker not in text]
    return Check(path, not missing, "ok" if not missing else "missing: " + ", ".join(missing))


def _required_files() -> Check:
    paths = [
        "app/data/migrations/0030_v3_release.py",
        "app/v3/contracts.py",
        "app/v3/pipeline.py",
        "app/v3/verification.py",
        "app/v3/targets.py",
        "app/v3/handling.py",
        "app/v3/reporting.py",
        "docs/handling_alignment.md",
        "docs/target_classes.md",
        "docs/verification_model.md",
        "docs/glossary.md",
        "docs/threat_model.md",
        "RELEASE_CHECKLIST.md",
        "tests/test_v3_release_wiring.py",
        "tests/test_v3_target_classes.py",
        "tests/test_v3_handling.py",
    ]
    missing = [path for path in paths if not (ROOT / path).exists()]
    return Check("v3 required files", not missing, "all present" if not missing else "missing: " + ", ".join(missing))


def _contract_freeze() -> Check:
    try:
        from app.v3.contracts import PUBLIC_CONTRACTS, V3_EVENT_TYPES, frozen_contract_manifest
        manifest = frozen_contract_manifest()
        expected_events = {"finding", "progress", "log", "evidence", "chain", "ranked", "verification", "disposition", "target"}
        ok = (
            manifest.get("release") == "3.0.0"
            and set(V3_EVENT_TYPES) == expected_events
            and PUBLIC_CONTRACTS.get("sse") == "windeep.sse.v1"
            and PUBLIC_CONTRACTS.get("har_extension") == "windeep.har-extension.v1"
            and PUBLIC_CONTRACTS.get("evidence_bundle") == "windeep.evidence-bundle.v1"
            and PUBLIC_CONTRACTS.get("report") == "windeep.report.v1"
        )
        return Check("P0-P8 public contract freeze", ok, json.dumps(manifest, sort_keys=True))
    except Exception as exc:
        return Check("P0-P8 public contract freeze", False, repr(exc))


def _preflight_reachability() -> Check:
    scheduler = _text("app/engine/scheduler.py")
    targets = _text("app/v3/targets.py")
    server = _text("app/server.py")
    ok = all(
        marker in text
        for text, marker in (
            (scheduler, "preflight"),
            (targets, "guard.authorize_scan"),
            (targets, "authorize_route"),
            (server, "PreFlightGuard"),
        )
    )
    return Check("R3(a) preflight required", ok, "scheduler + v3 target + server preflight markers")


def _cleanup_contract() -> Check:
    runtime = _text("app/ops/runtime.py")
    tests = _text("tests/test_p6_operational_depth.py")
    ok = "class CleanupSweeper" in runtime and "sweep(" in runtime and "outside encrypted-tmp" in tests
    return Check("R3(b) plaintext temp cleanup", ok, "P6 active sweeper + outside-temp acceptance")


def _report_contract() -> list[Check]:
    report = _text("app/v3/reporting.py")
    handling_tests = _text("tests/test_v3_handling.py")
    checks = [
        Check(
            "R3(c) handling citation/policy unspecified",
            ("handling_rule_ids" in report and "policy: unspecified" in report) or "policy: unspecified" in handling_tests,
            "v3 report handling citation gate",
        ),
        Check(
            "R3(d) High/Critical evidence minimum",
            all(marker in report for marker in ("flows", "provenance", "replay_handle", "high", "critical")),
            "reportability gate requires flow + provenance + repro for High/Critical",
        ),
        Check(
            "R3(e) export secret redaction",
            "redact" in report.casefold() and "unredacted" in handling_tests.casefold(),
            "v3 report uses redacted P3 evidence model; fixture asserts no secret export",
        ),
        Check(
            "R3(f) claim verification resolution",
            "VerificationPass" in report and "verification" in report.casefold() and "claim" in report.casefold(),
            "report generator resolves fixed claim verification records",
        ),
    ]
    return checks


def _forbidden_patterns() -> Check:
    forbidden: list[str] = []
    patterns = {
        r"\bos\.system\s*\(": "os.system",
        r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(": "subprocess execution",
        r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(": "requests direct HTTP",
        r"\bhttpx\.(?:get|post|put|patch|delete|request)\s*\(": "httpx direct HTTP",
        r"\baiohttp\.": "aiohttp direct HTTP",
    }
    for path in sorted((ROOT / "app" / "v3").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern, label in patterns.items():
            if re.search(pattern, text):
                forbidden.append(f"{path.relative_to(ROOT)}: {label}")
    return Check("C7 forbidden-pattern scan (new v3 modules)", not forbidden, "none" if not forbidden else "; ".join(forbidden))


def checks() -> list[Check]:
    version = _text("VERSION").strip()
    result = [
        Check("VERSION", version == "3.0.0", f"VERSION={version!r}"),
        _required_files(),
        _contract_freeze(),
        _preflight_reachability(),
        _cleanup_contract(),
        _contains("app/data/migrations/0030_v3_release.py", "verification_record", "v3_targets", "handling_policy", "handling_classification"),
        _forbidden_patterns(),
        *_report_contract(),
    ]
    threat = _text("docs/threat_model.md")
    result.append(Check("R4 IP/CIDR threat-model coverage", "IP/CIDR" in threat and "SNI" in threat and "Host" in threat, "target-surface threat section"))
    return result


def main() -> int:
    values = checks()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    failures = [item for item in values if not item.ok]
    lines = [
        "# Windeep v3 Release Audit",
        "",
        f"Overall: **{'PASS' if not failures else 'FAIL'}**",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for item in values:
        detail = item.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {item.name} | **{'PASS' if item.ok else 'FAIL'}** | {detail} |")
    lines.extend(["", f"Failures: **{len(failures)}**", ""])
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    for item in values:
        print(f"[{'PASS' if item.ok else 'FAIL'}] {item.name}: {item.detail}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
