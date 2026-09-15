"""Fail-closed release audits for Windeep's Windows tag pipeline.

These checks are release engineering controls only. They do not scan external
systems. Phase D uses Flask's local test client to verify authorization,
scope, CSRF and rate/crypto bootstrap behavior without contacting a target.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"
STATUS_FILE = REPORTS / "phase_status.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PLACEHOLDER_RE = re.compile(r"\b(TODO|FIXME|TBD|PLACEHOLDER)\b", re.IGNORECASE)
REQUIRED_API_MARKERS = (
    "/api/targets",
    "/api/scans",
    "/api/findings",
    "/api/reports",
    "/api/tools",
    "/api/settings",
    "/api/stream/",
    "/api/test-packs",
)


@dataclass
class Check:
    name: str
    status: str
    detail: str


def _record(phase: str, ok: bool) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    state: dict[str, bool] = {}
    if STATUS_FILE.exists():
        try:
            state = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
    state[phase] = ok
    STATUS_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _markdown(title: str, checks: list[Check], path: Path) -> bool:
    REPORTS.mkdir(parents=True, exist_ok=True)
    failures = [c for c in checks if c.status == "FAIL"]
    lines = [
        f"# {title}",
        "",
        f"Overall: **{'PASS' if not failures else 'FAIL'}**",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for check in checks:
        detail = check.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {check.name} | **{check.status}** | {detail} |")
    lines += ["", f"Failures: **{len(failures)}**", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return not failures


def _safe_relative_path(value: str) -> bool:
    if not value or Path(value).is_absolute() or PureWindowsPath(value).is_absolute():
        return False
    win = PureWindowsPath(value)
    posix = PurePosixPath(value.replace("\\", "/"))
    return ".." not in win.parts and ".." not in posix.parts


def _load_registry() -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[Check]]:
    checks: list[Check] = []
    root_path = ROOT / "tools_config.json"
    if not root_path.exists():
        return {}, {}, [Check("tools_config.json", "FAIL", "missing root tool registry")]
    try:
        root = json.loads(root_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, {}, [Check("tools_config.json", "FAIL", f"invalid JSON: {exc}")]

    includes = root.get("includes", [])
    if not isinstance(includes, list) or not includes:
        return root, {}, [Check("registry includes", "FAIL", "root registry has no category includes")]

    tools: dict[str, dict[str, Any]] = {}
    for rel in includes:
        if not isinstance(rel, str) or not _safe_relative_path(rel):
            checks.append(Check(f"registry include {rel!r}", "FAIL", "unsafe or invalid include path"))
            continue
        path = ROOT / rel
        if not path.exists():
            checks.append(Check(f"registry include {rel}", "FAIL", "declared include is missing"))
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            definitions = payload.get("tools", {})
            if not isinstance(definitions, dict):
                raise TypeError("tools must be an object")
            overlap = sorted(set(tools) & set(definitions))
            if overlap:
                checks.append(Check(f"registry include {rel}", "FAIL", f"duplicate names: {', '.join(overlap)}"))
            else:
                tools.update(definitions)
                checks.append(Check(f"registry include {rel}", "PASS", f"{len(definitions)} tool definitions"))
        except Exception as exc:
            checks.append(Check(f"registry include {rel}", "FAIL", f"invalid registry: {exc}"))

    declared = root.get("tool_count")
    actual = len(tools)
    checks.append(Check("declared tool count", "PASS" if declared == actual else "FAIL", f"declared={declared}, actual={actual}"))
    return root, tools, checks


def _python_inventory() -> tuple[list[Path], list[str], list[str], list[str]]:
    files = [ROOT / "launcher.py", *sorted((ROOT / "app").rglob("*.py")), *sorted((ROOT / "scripts").rglob("*.py"))]
    compile_errors: list[str] = []
    stubs: list[str] = []
    placeholders: list[str] = []
    for path in files:
        rel = path.relative_to(ROOT)
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            compile_errors.append(f"{rel}: {exc.msg}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(rel))
        except Exception as exc:
            compile_errors.append(f"{rel}: AST parse failed: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            if len(body) == 1 and isinstance(body[0], ast.Pass):
                stubs.append(f"{rel}:{node.lineno} {node.name}() is pass-only")
            if len(body) == 1 and isinstance(body[0], ast.Raise):
                called = body[0].exc
                if isinstance(called, ast.Call) and isinstance(called.func, ast.Name) and called.func.id == "NotImplementedError":
                    stubs.append(f"{rel}:{node.lineno} {node.name}() raises NotImplementedError")

        for line_no, line in enumerate(text.splitlines(), start=1):
            if PLACEHOLDER_RE.search(line) and not line.lstrip().startswith(("# noqa", "PLACEHOLDER_RE")):
                placeholders.append(f"{rel}:{line_no}: {line.strip()[:120]}")
    return files, compile_errors, stubs, placeholders


def phase_a() -> bool:
    checks: list[Check] = []
    files, compile_errors, stubs, placeholders = _python_inventory()
    checks.append(Check("Python syntax", "PASS" if not compile_errors else "FAIL", f"{len(files)} files compiled" if not compile_errors else "; ".join(compile_errors[:15])))
    checks.append(Check("implementation stubs", "PASS" if not stubs else "FAIL", "no pass-only/NotImplementedError production functions" if not stubs else "; ".join(stubs[:20])))
    checks.append(Check("TODO/FIXME inventory", "WARN" if placeholders else "PASS", f"{len(placeholders)} markers: " + "; ".join(placeholders[:12]) if placeholders else "no placeholder markers in Python sources"))

    _, tools, registry_checks = _load_registry()
    checks.extend(registry_checks)
    required_fields = {"binary", "category", "args", "timeout", "retries", "rate_limit", "requires_scope"}
    bad: list[str] = []
    unsafe_scope: list[str] = []
    bad_limits: list[str] = []
    for name, definition in tools.items():
        missing = sorted(required_fields - set(definition))
        if missing:
            bad.append(f"{name}: missing {','.join(missing)}")
        if definition.get("requires_scope") is not True:
            unsafe_scope.append(name)
        try:
            timeout = float(definition.get("timeout", 0))
            retries = int(definition.get("retries", -1))
            rate = float(definition.get("rate_limit", -1))
            if timeout <= 0 or retries < 0 or rate <= 0:
                bad_limits.append(name)
        except (TypeError, ValueError):
            bad_limits.append(name)
    checks.append(Check("wrapper metadata completeness", "PASS" if not bad else "FAIL", f"{len(tools)} wrappers structurally complete" if not bad else "; ".join(bad[:25])))
    checks.append(Check("wrapper scope requirement", "PASS" if not unsafe_scope else "FAIL", "all external wrappers require explicit scope" if not unsafe_scope else f"scope not mandatory: {', '.join(unsafe_scope[:25])}"))
    checks.append(Check("wrapper bounded execution", "PASS" if not bad_limits else "FAIL", "all wrappers define positive timeout/rate and non-negative retries" if not bad_limits else "invalid bounds: " + ", ".join(bad_limits[:25])))

    normalized: dict[str, list[str]] = {}
    for name, definition in tools.items():
        binary = str(definition.get("binary", name)).lower().replace("-", "").replace("_", "")
        normalized.setdefault(binary, []).append(name)
    aliases = [names for names in normalized.values() if len(names) > 1]
    checks.append(Check("duplicate/dead alias detection", "WARN" if aliases else "PASS", "possible duplicate binary aliases: " + "; ".join(", ".join(a) for a in aliases[:10]) if aliases else "no duplicate normalized binary names"))

    ui = ROOT / "app" / "static" / "index.html"
    checks.append(Check("desktop dashboard UI", "PASS" if ui.exists() and ui.stat().st_size > 1000 else "FAIL", f"app/static/index.html present ({ui.stat().st_size} bytes)" if ui.exists() else "full dashboard asset is absent; current server exposes bootstrap HTML only"))

    server_path = ROOT / "app" / "server.py"
    server_text = server_path.read_text(encoding="utf-8") if server_path.exists() else ""
    missing_routes = [route for route in REQUIRED_API_MARKERS if route not in server_text]
    checks.append(Check("operational API wiring", "PASS" if not missing_routes else "FAIL", "required dashboard APIs are wired" if not missing_routes else "missing route markers: " + ", ".join(missing_routes)))

    test_pack_candidates = [ROOT / "app" / "modules" / "test_packs.py", ROOT / "app" / "test_packs.py"]
    test_pack_path = next((p for p in test_pack_candidates if p.exists()), None)
    checks.append(Check("160-test pack implementation", "PASS" if test_pack_path else "FAIL", str(test_pack_path.relative_to(ROOT)) if test_pack_path else "no test-pack implementation found"))

    required_release_files = [
        ROOT / "Windeep.spec",
        ROOT / "installer" / "BugBountyInstaller.iss",
        ROOT / "installer" / "setup_tools.ps1",
        ROOT / "installer" / "install_python.ps1",
        ROOT / "installer" / "tools-manifest.json",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        ROOT / "scripts" / "audit" / "windows_install_audit.ps1",
        ROOT / ".github" / "workflows" / "release.yml",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required_release_files if not p.exists()]
    checks.append(Check("release file set", "PASS" if not missing else "FAIL", "all required release inputs present" if not missing else "missing: " + ", ".join(missing)))

    spec_text = (ROOT / "Windeep.spec").read_text(encoding="utf-8") if (ROOT / "Windeep.spec").exists() else ""
    checks.append(Check("PyInstaller onedir layout", "PASS" if "COLLECT(" in spec_text else "FAIL", "COLLECT onedir build configured" if "COLLECT(" in spec_text else "Windeep.spec does not create dist/Windeep/"))

    iss_text = (ROOT / "installer" / "BugBountyInstaller.iss").read_text(encoding="utf-8") if (ROOT / "installer" / "BugBountyInstaller.iss").exists() else ""
    recursive_package = "dist\\Windeep\\*" in iss_text and "recursesubdirs" in iss_text
    checks.append(Check("installer packages complete app tree", "PASS" if recursive_package else "FAIL", "dist/Windeep is installed recursively" if recursive_package else "installer does not recursively include dist/Windeep"))

    workflow_path = ROOT / ".github" / "workflows" / "release.yml"
    workflow = workflow_path.read_text(encoding="utf-8") if workflow_path.exists() else ""
    required_workflow_markers = [
        "tags:", "'v*'", "fetch-depth: 0", "python-version: '3.11'",
        "--cov-fail-under=85", "installer/setup_tools.ps1", "installer/install_python.ps1",
        "pyinstaller --clean --noconfirm Windeep.spec", "installer\\BugBountyInstaller.iss",
        "Compress-Archive", "git archive --format=zip", "SHA256SUMS.txt",
        "RELEASE-NOTES.md", "softprops/action-gh-release@", "SBOM.json", "actions/attest@",
    ]
    workflow_missing = [m for m in required_workflow_markers if m not in workflow]
    checks.append(Check("G1-G21 workflow contract", "PASS" if not workflow_missing else "FAIL", "tag release workflow contains required build/verify/publish stages" if not workflow_missing else "missing workflow markers: " + ", ".join(workflow_missing)))

    ok = _markdown("Phase A — Static Release Audit", checks, REPORTS / "static_audit.md")
    _record("A", ok)
    return ok


def _manifest() -> tuple[list[dict[str, Any]], list[Check]]:
    path = ROOT / "installer" / "tools-manifest.json"
    if not path.exists():
        return [], [Check("tool manifest", "FAIL", "installer/tools-manifest.json missing")]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload.get("tools", [])
        if not isinstance(entries, list):
            raise TypeError("tools must be an array")
        return entries, []
    except Exception as exc:
        return [], [Check("tool manifest", "FAIL", f"invalid JSON/schema: {exc}")]


def phase_b() -> bool:
    checks: list[Check] = []
    _, tools, registry_checks = _load_registry()
    checks.extend(check for check in registry_checks if check.status == "FAIL")
    manifest, manifest_checks = _manifest()
    checks.extend(manifest_checks)
    checks.append(Check("portable tool manifest non-empty", "PASS" if manifest else "FAIL", f"{len(manifest)} package entries" if manifest else "manifest contains no downloadable tools"))

    provided: set[str] = set()
    duplicate_provides: set[str] = set()
    invalid: list[str] = []
    probe_failures: list[str] = []
    legacy_blockers: list[str] = []
    known_release_blockers = {
        "aquatone": "upstream archived; must be explicitly supported legacy or replaced",
        "jsparser": "legacy Python 2.7 runtime contract",
        "sublist3r": "legacy compatibility must be pinned and proven on clean Windows",
        "waffw00f": "duplicate/typo candidate for wafw00f",
    }

    for entry in manifest:
        name = str(entry.get("name", "")).strip()
        version = str(entry.get("version", "")).strip()
        destination = str(entry.get("destination", "")).strip()
        url = str(entry.get("url", "")).strip()
        digest = str(entry.get("sha256", "")).strip()
        package_type = str(entry.get("package_type", "file")).strip().lower()
        probe = entry.get("probe")
        aliases = entry.get("provides", [name])
        license_id = str(entry.get("license", "")).strip()

        if (
            not name or not version or not destination or not _safe_relative_path(destination)
            or not url.startswith("https://") or not SHA256_RE.match(digest)
            or package_type not in {"file", "zip"} or not license_id
        ):
            invalid.append(name or "<unnamed>")
        if package_type == "zip":
            archive_path = str(entry.get("archive_path", "")).strip()
            if not archive_path or not _safe_relative_path(archive_path):
                invalid.append(f"{name or '<unnamed>'} (invalid archive_path)")
        if not isinstance(aliases, list) or not aliases or not all(isinstance(v, str) and v for v in aliases):
            invalid.append(f"{name or '<unnamed>'} (invalid provides)")
            aliases = []
        for alias in aliases:
            if alias in provided:
                duplicate_provides.add(alias)
            provided.add(alias)
        if not isinstance(probe, list) or not probe or not all(isinstance(v, str) and v for v in probe):
            invalid.append(f"{name or '<unnamed>'} (missing safe probe)")
            continue

        for alias in aliases:
            if alias in known_release_blockers and not bool(entry.get("legacy_reviewed", False)):
                legacy_blockers.append(f"{alias}: {known_release_blockers[alias]}")

        binary = ROOT / "tools" / destination
        if binary.exists():
            try:
                completed = subprocess.run([str(binary), *probe], capture_output=True, text=True, timeout=15, shell=False)
                expected = entry.get("expected_exit_codes", [0])
                if completed.returncode not in expected:
                    probe_failures.append(f"{name}: exit {completed.returncode}")
            except Exception as exc:
                probe_failures.append(f"{name}: {exc}")

    checks.append(Check("tool manifest integrity", "PASS" if not invalid else "FAIL", "versions, HTTPS URLs, hashes, licenses, paths, provides and safe probes are defined" if not invalid else "invalid entries: " + ", ".join(invalid[:30])))
    checks.append(Check("unique manifest provides", "PASS" if not duplicate_provides else "FAIL", "each wrapper is supplied exactly once" if not duplicate_provides else "duplicate mappings: " + ", ".join(sorted(duplicate_provides))))
    missing = sorted(set(tools) - provided)
    extra = sorted(provided - set(tools))
    checks.append(Check("registry → installer coverage", "PASS" if not missing else "FAIL", "every registered wrapper is supplied by the installer" if not missing else f"unpackaged wrappers ({len(missing)}): {', '.join(missing[:50])}"))
    checks.append(Check("manifest orphan detection", "WARN" if extra else "PASS", "manifest-only names: " + ", ".join(extra[:40]) if extra else "no orphan manifest mappings"))
    checks.append(Check("legacy/deprecated release review", "PASS" if not legacy_blockers else "FAIL", "no unreviewed known legacy/deprecated wrapper blockers" if not legacy_blockers else "; ".join(legacy_blockers)))
    checks.append(Check("safe liveness probes", "PASS" if not probe_failures else "FAIL", "available cached binaries passed their non-invasive probe; uncached binaries are verified after G11" if not probe_failures else "; ".join(probe_failures[:25])))

    ok = _markdown("Phase B — Tool Liveness and Packaging Audit", checks, REPORTS / "tool_liveness.md")
    _record("B", ok)
    return ok


def phase_e() -> bool:
    checks: list[Check] = []
    checks.append(Check("Python version", "PASS" if sys.version_info[:2] == (3, 11) else "FAIL", sys.version.split()[0]))
    pip_check = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True)
    checks.append(Check("pip check", "PASS" if pip_check.returncode == 0 else "FAIL", (pip_check.stdout or pip_check.stderr).strip()[:1500] or "dependency graph consistent"))
    audit_cmd = [sys.executable, "-m", "pip_audit", "-r", str(ROOT / "requirements.txt"), "--progress-spinner", "off", "--format", "json"]
    audit = subprocess.run(audit_cmd, capture_output=True, text=True)
    detail = "no known vulnerabilities reported" if audit.returncode == 0 else (audit.stdout or audit.stderr).strip()[:2000]
    checks.append(Check("pip-audit", "PASS" if audit.returncode == 0 else "FAIL", detail))
    ok = _markdown("Phase E — Dependency Audit", checks, REPORTS / "dependency_audit.md")
    _record("E", ok)
    return ok


def phase_d() -> bool:
    checks: list[Check] = []
    with tempfile.TemporaryDirectory(prefix="windeep-e2e-") as tmp:
        old = os.environ.get("WINDEEP_STATE_DIR")
        os.environ["WINDEEP_STATE_DIR"] = tmp
        try:
            from app.server import create_app

            app = create_app()
            app.testing = True
            client = app.test_client()

            health = client.get("/api/health")
            health_body = health.get_json() or {}
            checks.append(Check("local health", "PASS" if health.status_code == 200 and health_body.get("status") == "ok" and health_body.get("localhost_only") is True else "FAIL", f"HTTP {health.status_code}: {health_body}"))

            remote = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "203.0.113.10"})
            checks.append(Check("remote dashboard blocked", "PASS" if remote.status_code == 403 else "FAIL", f"HTTP {remote.status_code}"))

            handshake = client.post("/api/handshake")
            handshake_body = handshake.get_json() or {}
            csrf = handshake_body.get("csrf_token", "")
            checks.append(Check("auth handshake", "PASS" if handshake.status_code == 200 and csrf else "FAIL", f"HTTP {handshake.status_code}"))

            missing_csrf = client.post("/api/consent", json={"target": "example.test"})
            checks.append(Check("CSRF fail-closed", "PASS" if missing_csrf.status_code == 401 else "FAIL", f"HTTP {missing_csrf.status_code}"))

            headers = {"X-CSRF-Token": csrf}
            consent = client.post(
                "/api/consent",
                json={
                    "target": "example.test",
                    "scope": ["example.test"],
                    "out_of_scope": ["blocked.example.test"],
                    "authorized_by": "release-audit",
                    "purpose": "local CI guardrail verification",
                    "ttl_seconds": 300,
                },
                headers=headers,
            )
            consent_body = consent.get_json() or {}
            consent_id = consent_body.get("id", "")
            checks.append(Check("signed consent", "PASS" if consent.status_code == 201 and consent_id else "FAIL", f"HTTP {consent.status_code}"))

            preflight = client.post(
                "/api/preflight/check",
                json={
                    "target": "example.test",
                    "scope": ["example.test"],
                    "out_of_scope": ["blocked.example.test"],
                    "consent_id": consent_id,
                    "global_rps": 1.0,
                    "global_burst": 1.0,
                },
                headers=headers,
            )
            preflight_body = preflight.get_json() or {}
            checks.append(Check("authorized preflight", "PASS" if preflight.status_code == 200 and preflight_body.get("authorized") is True else "FAIL", f"HTTP {preflight.status_code}: {preflight_body}"))

            denied = client.post(
                "/api/preflight/check",
                json={
                    "target": "blocked.example.test",
                    "scope": ["example.test"],
                    "out_of_scope": ["blocked.example.test"],
                    "consent_id": consent_id,
                },
                headers=headers,
            )
            checks.append(Check("out-of-scope denied", "PASS" if denied.status_code == 403 else "FAIL", f"HTTP {denied.status_code}"))

            tampered_scope = client.post(
                "/api/preflight/check",
                json={
                    "target": "other.example.test",
                    "scope": ["other.example.test"],
                    "out_of_scope": [],
                    "consent_id": consent_id,
                },
                headers=headers,
            )
            checks.append(Check("consent scope binding", "PASS" if tampered_scope.status_code == 403 else "FAIL", f"HTTP {tampered_scope.status_code}"))
        except Exception as exc:
            checks.append(Check("E2E execution", "FAIL", repr(exc)))
        finally:
            if old is None:
                os.environ.pop("WINDEEP_STATE_DIR", None)
            else:
                os.environ["WINDEEP_STATE_DIR"] = old

    ok = _markdown("Phase D — Local End-to-End Guardrail Audit", checks, REPORTS / "e2e_audit.md")
    _record("D", ok)
    return ok


def _coverage_rate() -> tuple[float | None, str]:
    path = REPORTS / "coverage.xml"
    if not path.exists():
        return None, "reports/coverage.xml missing; run G7 before Phase F"
    try:
        root = ET.parse(path).getroot()
        raw = root.attrib.get("line-rate")
        if raw is None:
            return None, "coverage.xml has no line-rate attribute"
        value = float(raw)
        return value, f"line-rate={value:.4f} ({value * 100:.2f}%)"
    except Exception as exc:
        return None, f"coverage.xml parse failed: {exc}"


def phase_f() -> bool:
    REPORTS.mkdir(parents=True, exist_ok=True)
    try:
        states = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except Exception:
        states = {}

    required = ["A", "B", "E", "D"]
    blockers = [f"Phase {phase} did not PASS" for phase in required if states.get(phase) is not True]

    coverage, coverage_detail = _coverage_rate()
    coverage_ok = coverage is not None and coverage >= 0.85
    if not coverage_ok:
        blockers.append(f"coverage gate failed: {coverage_detail}")

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() if (ROOT / "VERSION").exists() else "unknown"
    ref_name = os.getenv("GITHUB_REF_NAME", "").strip()
    tag_ok = not ref_name or ref_name == f"v{version}"
    if not tag_ok:
        blockers.append(f"tag {ref_name!r} does not match VERSION v{version}")

    decision = "GO" if not blockers else "NO-GO"
    payload = {
        "decision": decision,
        "version": version,
        "tag": ref_name or None,
        "checks": {phase: bool(states.get(phase)) for phase in required},
        "coverage": {"ok": coverage_ok, "line_rate": coverage, "detail": coverage_detail, "minimum": 0.85},
        "tag_matches_version": tag_ok,
        "blockers": blockers,
    }
    (REPORTS / "release_gate.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _record("F", decision == "GO")
    return decision == "GO"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=["A", "B", "D", "E", "F"])
    args = parser.parse_args()
    fn = {"A": phase_a, "B": phase_b, "D": phase_d, "E": phase_e, "F": phase_f}[args.phase]
    return 0 if fn() else 1


if __name__ == "__main__":
    raise SystemExit(main())
