"""Fail-closed release audits for Windeep's Windows v0.1.0 pipeline.

These checks never scan an external target. Phase D uses Flask's local test
client only. The release contract deliberately separates the complete 137-tool
catalog from the small set of binaries certified for execution in this Windows
release.
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
EXPECTED_TOOL_COUNT = 137
EXPECTED_ACTIVE_TOOL_COUNT = 137
EXPECTED_CERTIFIED_TOOL_COUNT = 6
EXPECTED_CATALOG_FILES = 8
EXPECTED_TEST_COUNT = 160
ALLOWED_RELEASE_SUPPORT = {
    "bundled",
    "runtime",
    "internal",
    "external-service",
    "unsupported",
    "deprecated",
    "legacy",
}
BLOCKED_RELEASE_SUPPORT = {"external-service", "unsupported", "deprecated", "legacy"}
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


@dataclass(slots=True)
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
    state[phase] = bool(ok)
    STATUS_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _markdown(title: str, checks: list[Check], path: Path) -> bool:
    REPORTS.mkdir(parents=True, exist_ok=True)
    failures = [item for item in checks if item.status == "FAIL"]
    lines = [
        f"# {title}",
        "",
        f"Overall: **{'PASS' if not failures else 'FAIL'}**",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for item in checks:
        detail = item.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {item.name} | **{item.status}** | {detail} |")
    lines += ["", f"Failures: **{len(failures)}**", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return not failures


def _safe_relative_path(value: str) -> bool:
    if not value or Path(value).is_absolute() or PureWindowsPath(value).is_absolute():
        return False
    win = PureWindowsPath(value)
    posix = PurePosixPath(value.replace("\\", "/"))
    return ".." not in win.parts and ".." not in posix.parts


def _root_registry() -> tuple[dict[str, Any], str | None]:
    path = ROOT / "tools_config.json"
    if not path.exists():
        return {}, "tools_config.json is missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("root registry must be an object")
        return payload, None
    except Exception as exc:
        return {}, f"invalid tools_config.json: {exc}"


def _load_include_set(root: dict[str, Any], key: str) -> tuple[dict[str, dict[str, Any]], list[Check]]:
    checks: list[Check] = []
    includes = root.get(key, [])
    if not isinstance(includes, list) or not includes or not all(isinstance(item, str) for item in includes):
        return {}, [Check(f"{key}", "FAIL", f"{key} must be a non-empty list of paths")]
    tools: dict[str, dict[str, Any]] = {}
    for rel in includes:
        if not _safe_relative_path(rel):
            checks.append(Check(f"{key} {rel!r}", "FAIL", "unsafe include path"))
            continue
        path = (ROOT / rel).resolve()
        if not path.is_relative_to(ROOT):
            checks.append(Check(f"{key} {rel}", "FAIL", "include escapes repository"))
            continue
        if not path.exists():
            checks.append(Check(f"{key} {rel}", "FAIL", "declared include is missing"))
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            definitions = payload.get("tools", {})
            if not isinstance(definitions, dict):
                raise TypeError("tools must be an object")
            malformed = [name for name, value in definitions.items() if not isinstance(name, str) or not isinstance(value, dict)]
            if malformed:
                raise TypeError("every tool definition must be an object")
            overlap = sorted(set(tools).intersection(definitions))
            if overlap:
                checks.append(Check(f"{key} {rel}", "FAIL", "duplicate names: " + ", ".join(overlap[:20])))
                continue
            tools.update({str(name): dict(value) for name, value in definitions.items()})
            checks.append(Check(f"{key} {rel}", "PASS", f"{len(definitions)} tool definitions"))
        except Exception as exc:
            checks.append(Check(f"{key} {rel}", "FAIL", f"invalid registry: {exc}"))
    return tools, checks


def _catalog_and_active() -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[Check]]:
    root, error = _root_registry()
    if error:
        return {}, {}, {}, [Check("tools_config.json", "FAIL", error)]
    catalog, catalog_checks = _load_include_set(root, "catalog_includes")
    active, active_checks = _load_include_set(root, "includes")
    checks = [*catalog_checks, *active_checks]
    catalog_files = root.get("catalog_includes", [])
    checks.append(Check(
        "catalog category count",
        "PASS" if isinstance(catalog_files, list) and len(catalog_files) == EXPECTED_CATALOG_FILES else "FAIL",
        f"declared={len(catalog_files) if isinstance(catalog_files, list) else 'invalid'}, required={EXPECTED_CATALOG_FILES}",
    ))
    declared = root.get("tool_count")
    checks.append(Check(
        "catalog tool count",
        "PASS" if declared == len(catalog) == EXPECTED_TOOL_COUNT else "FAIL",
        f"declared={declared}, actual={len(catalog)}, required={EXPECTED_TOOL_COUNT}",
    ))
    active_declared = root.get("active_tool_count")
    checks.append(Check(
        "active runtime tool count",
        "PASS" if active_declared == len(active) == EXPECTED_ACTIVE_TOOL_COUNT else "FAIL",
        f"declared={active_declared}, actual={len(active)}, required={EXPECTED_ACTIVE_TOOL_COUNT}",
    ))
    return root, catalog, active, checks


def _effective_tools() -> tuple[dict[str, dict[str, Any]], str | None]:
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from app.tools.release_metadata import effective_definitions
        return effective_definitions(ROOT / "tools_config.json"), None
    except Exception as exc:
        return {}, repr(exc)


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
    checks.append(Check("Python syntax", "PASS" if not compile_errors else "FAIL", f"{len(files)} files compiled" if not compile_errors else "; ".join(compile_errors[:20])))
    checks.append(Check("implementation stubs", "PASS" if not stubs else "FAIL", "no pass-only/NotImplementedError production functions" if not stubs else "; ".join(stubs[:20])))
    checks.append(Check("TODO/FIXME inventory", "WARN" if placeholders else "PASS", f"{len(placeholders)} marker(s)" if placeholders else "no placeholder markers in Python sources"))

    _, catalog, active, registry_checks = _catalog_and_active()
    checks.extend(registry_checks)
    required_fields = {"binary", "category", "args", "timeout", "retries", "rate_limit", "requires_scope"}
    malformed: list[str] = []
    unsafe_scope: list[str] = []
    invalid_bounds: list[str] = []
    for name, definition in catalog.items():
        missing = sorted(required_fields.difference(definition))
        if missing:
            malformed.append(f"{name}: missing {','.join(missing)}")
        if definition.get("requires_scope") is not True:
            unsafe_scope.append(name)
        try:
            if float(definition.get("timeout", 0)) <= 0 or int(definition.get("retries", -1)) < 0 or float(definition.get("rate_limit", 0)) <= 0:
                invalid_bounds.append(name)
        except (TypeError, ValueError):
            invalid_bounds.append(name)
    checks.append(Check("137 catalog definitions structurally complete", "PASS" if not malformed else "FAIL", f"{len(catalog)} definitions complete" if not malformed else "; ".join(malformed[:30])))
    checks.append(Check("catalog scope requirement", "PASS" if not unsafe_scope else "FAIL", "all catalog wrappers require explicit scope" if not unsafe_scope else "scope not mandatory: " + ", ".join(unsafe_scope[:30])))
    checks.append(Check("catalog bounded execution", "PASS" if not invalid_bounds else "FAIL", "all catalog definitions have positive timeout/rate and non-negative retries" if not invalid_bounds else "invalid: " + ", ".join(invalid_bounds[:30])))

    effective, policy_error = _effective_tools()
    checks.append(Check("release policy load", "PASS" if not policy_error and len(effective) == EXPECTED_TOOL_COUNT else "FAIL", policy_error or f"{len(effective)} catalog integrations classified"))
    invalid_support = sorted(name for name, value in effective.items() if value.get("release_support") not in ALLOWED_RELEASE_SUPPORT)
    checks.append(Check("release classification values", "PASS" if not invalid_support else "FAIL", "every catalog integration has an allowed disposition" if not invalid_support else ", ".join(invalid_support[:40])))
    unreasoned = sorted(name for name, value in effective.items() if value.get("release_support") in BLOCKED_RELEASE_SUPPORT and not str(value.get("unsupported_reason") or "").strip())
    checks.append(Check("blocked/external integration reasons", "PASS" if not unreasoned else "FAIL", "every blocked or external integration has an explicit reason" if not unreasoned else ", ".join(unreasoned[:40])))
    bundled = {name for name, value in effective.items() if value.get("release_support") == "bundled"}
    unlicensed = sorted(name for name in bundled if not effective[name].get("license") or not effective[name].get("homepage"))
    checks.append(Check("bundled license metadata", "PASS" if not unlicensed else "FAIL", f"{len(bundled)} bundled integrations have license/homepage metadata" if not unlicensed else ", ".join(unlicensed)))
    checks.append(Check("operational runtime exposes complete catalog", "PASS" if set(active) == set(catalog) and len(active) == EXPECTED_ACTIVE_TOOL_COUNT else "FAIL", f"active={len(active)}, catalog={len(catalog)}, required={EXPECTED_ACTIVE_TOOL_COUNT}"))
    checks.append(Check("Windows-certified bundled subset", "PASS" if len(bundled) == EXPECTED_CERTIFIED_TOOL_COUNT else "FAIL", f"bundled={sorted(bundled)}, required_count={EXPECTED_CERTIFIED_TOOL_COUNT}"))

    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from app.modules.test_packs import TOTAL_TESTS
        checks.append(Check("160 production test packs", "PASS" if TOTAL_TESTS == EXPECTED_TEST_COUNT else "FAIL", f"registered={TOTAL_TESTS}, required={EXPECTED_TEST_COUNT}"))
    except Exception as exc:
        checks.append(Check("160 production test packs", "FAIL", repr(exc)))

    ui = ROOT / "app" / "static" / "index.html"
    checks.append(Check("desktop dashboard UI", "PASS" if ui.exists() and ui.stat().st_size > 1000 else "FAIL", f"app/static/index.html present ({ui.stat().st_size} bytes)" if ui.exists() else "full dashboard asset is absent"))
    server_path = ROOT / "app" / "server.py"
    server_text = server_path.read_text(encoding="utf-8") if server_path.exists() else ""
    missing_routes = [route for route in REQUIRED_API_MARKERS if route not in server_text]
    checks.append(Check("operational API wiring", "PASS" if not missing_routes else "FAIL", "required dashboard APIs are wired" if not missing_routes else "missing route markers: " + ", ".join(missing_routes)))

    required_release_files = [
        ROOT / "Windeep.spec",
        ROOT / "installer" / "BugBountyInstaller.iss",
        ROOT / "installer" / "setup_tools.ps1",
        ROOT / "installer" / "install_python.ps1",
        ROOT / "installer" / "tools-manifest.json",
        ROOT / "app" / "tools" / "release-policy.json",
        ROOT / "app" / "tools" / "release_metadata.py",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        ROOT / "scripts" / "audit" / "windows_install_audit.ps1",
        ROOT / ".github" / "workflows" / "release.yml",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required_release_files if not path.exists()]
    checks.append(Check("release file set", "PASS" if not missing else "FAIL", "all required release inputs present" if not missing else "missing: " + ", ".join(missing)))

    spec_text = (ROOT / "Windeep.spec").read_text(encoding="utf-8") if (ROOT / "Windeep.spec").exists() else ""
    spec_ok = "COLLECT(" in spec_text and "release-policy.json" in spec_text
    checks.append(Check("PyInstaller release evidence layout", "PASS" if spec_ok else "FAIL", "onedir build includes release policy evidence" if spec_ok else "Windeep.spec must package app/tools/release-policy.json"))
    iss_text = (ROOT / "installer" / "BugBountyInstaller.iss").read_text(encoding="utf-8") if (ROOT / "installer" / "BugBountyInstaller.iss").exists() else ""
    recursive_package = "dist\\Windeep\\*" in iss_text and "recursesubdirs" in iss_text
    checks.append(Check("installer packages complete app tree", "PASS" if recursive_package else "FAIL", "dist/Windeep is installed recursively" if recursive_package else "installer does not recursively include dist/Windeep"))

    workflow_path = ROOT / ".github" / "workflows" / "release.yml"
    workflow = workflow_path.read_text(encoding="utf-8") if workflow_path.exists() else ""
    required_workflow_markers = [
        "tags:", "'v*'", "fetch-depth: 0", "python-version: '3.11'", "--cov-fail-under=85",
        "installer/setup_tools.ps1", "--require-installed", "installer/install_python.ps1",
        "pyinstaller --clean --noconfirm Windeep.spec", "installer\\BugBountyInstaller.iss",
        "Compress-Archive", "git archive --format=zip", "SHA256SUMS.txt", "RELEASE-NOTES.md",
        "softprops/action-gh-release@", "SBOM.json", "actions/attest@",
    ]
    workflow_missing = [marker for marker in required_workflow_markers if marker not in workflow]
    checks.append(Check("tag release workflow contract", "PASS" if not workflow_missing else "FAIL", "release workflow contains required verify/build/publish stages" if not workflow_missing else "missing: " + ", ".join(workflow_missing)))

    ok = _markdown("Phase A — Static Release Audit", checks, REPORTS / "static_audit.md")
    _record("A", ok)
    return ok


def _manifest() -> tuple[list[dict[str, Any]], list[Check]]:
    path = ROOT / "installer" / "tools-manifest.json"
    if not path.exists():
        return [], [Check("tool manifest", "FAIL", "installer/tools-manifest.json missing")]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("platform") != "windows-amd64":
            raise ValueError("platform must be windows-amd64")
        entries = payload.get("tools", [])
        if not isinstance(entries, list):
            raise TypeError("tools must be an array")
        return [dict(item) for item in entries if isinstance(item, dict)], []
    except Exception as exc:
        return [], [Check("tool manifest", "FAIL", f"invalid JSON/schema: {exc}")]


def phase_b(*, require_installed: bool = False) -> bool:
    checks: list[Check] = []
    _, catalog, active, registry_checks = _catalog_and_active()
    checks.extend(check for check in registry_checks if check.status == "FAIL")
    effective, policy_error = _effective_tools()
    if policy_error:
        checks.append(Check("release policy", "FAIL", policy_error))
    checks.append(Check("catalog accounting", "PASS" if len(effective) == EXPECTED_TOOL_COUNT and set(effective) == set(catalog) else "FAIL", f"classified={len(effective)}, catalog={len(catalog)}, required={EXPECTED_TOOL_COUNT}"))
    dispositions = {status: sum(1 for value in effective.values() if value.get("release_support") == status) for status in ALLOWED_RELEASE_SUPPORT}
    unknown_disposition = sorted(name for name, value in effective.items() if value.get("release_support") not in ALLOWED_RELEASE_SUPPORT)
    checks.append(Check("no silent catalog disappearance", "PASS" if not unknown_disposition else "FAIL", json.dumps(dispositions, sort_keys=True) if not unknown_disposition else "unclassified: " + ", ".join(unknown_disposition[:40])))

    manifest, manifest_checks = _manifest()
    checks.extend(manifest_checks)
    checks.append(Check("portable tool manifest non-empty", "PASS" if manifest else "FAIL", f"{len(manifest)} package entries" if manifest else "manifest contains no bundled tools"))
    bundled = {name for name, value in effective.items() if value.get("release_support") == "bundled"}
    checks.append(Check("operational runtime catalog", "PASS" if set(active) == set(catalog) and len(active) == EXPECTED_ACTIVE_TOOL_COUNT else "FAIL", f"active={len(active)}, catalog={len(catalog)}"))
    checks.append(Check("Windows-certified manifest subset count", "PASS" if len(bundled) == EXPECTED_CERTIFIED_TOOL_COUNT else "FAIL", f"bundled={sorted(bundled)}, required_count={EXPECTED_CERTIFIED_TOOL_COUNT}"))

    provided: set[str] = set()
    duplicate_provides: set[str] = set()
    invalid: list[str] = []
    probe_failures: list[str] = []
    absent: list[str] = []
    entry_names: set[str] = set()
    for entry in manifest:
        name = str(entry.get("name", "")).strip()
        if not name or name in entry_names:
            invalid.append(name or "<unnamed/duplicate>")
        entry_names.add(name)
        version = str(entry.get("version", "")).strip()
        destination = str(entry.get("destination", "")).strip()
        url = str(entry.get("url", "")).strip()
        digest = str(entry.get("sha256", "")).strip()
        package_type = str(entry.get("package_type", "file")).strip().lower()
        license_id = str(entry.get("license", "")).strip()
        homepage = str(entry.get("homepage", "")).strip()
        review = str(entry.get("redistribution_review", "")).strip()
        aliases = entry.get("provides", [name])
        probe = entry.get("probe")
        expected = entry.get("expected_exit_codes", [0])
        if (
            not name or not version or not destination or not _safe_relative_path(destination)
            or not url.startswith("https://") or not SHA256_RE.match(digest)
            or package_type not in {"file", "zip"} or not license_id or not homepage or not review
        ):
            invalid.append(name or "<unnamed>")
        if package_type == "zip":
            archive_path = str(entry.get("archive_path", "")).strip()
            if not archive_path or not _safe_relative_path(archive_path):
                invalid.append(f"{name} invalid archive_path")
        if not isinstance(aliases, list) or not aliases or not all(isinstance(value, str) and value for value in aliases):
            invalid.append(f"{name} invalid provides")
            aliases = []
        for alias in aliases:
            if alias in provided:
                duplicate_provides.add(alias)
            provided.add(alias)
        if not isinstance(probe, list) or not probe or not all(isinstance(value, str) and value for value in probe):
            invalid.append(f"{name} missing safe probe")
            continue
        if not isinstance(expected, list) or not expected or not all(isinstance(value, int) for value in expected):
            invalid.append(f"{name} invalid expected_exit_codes")
            continue
        binary = ROOT / "tools" / destination
        if not binary.exists():
            if require_installed:
                absent.append(name)
            continue
        try:
            completed = subprocess.run([str(binary), *probe], capture_output=True, text=True, timeout=20, shell=False)
            if completed.returncode not in expected:
                probe_failures.append(f"{name}: exit {completed.returncode}")
        except Exception as exc:
            probe_failures.append(f"{name}: {exc}")

    checks.append(Check("tool manifest integrity", "PASS" if not invalid else "FAIL", "versions, HTTPS URLs, hashes, licenses, redistribution reviews, deterministic paths, mappings and safe probes are defined" if not invalid else "; ".join(invalid[:40])))
    checks.append(Check("unique manifest provides", "PASS" if not duplicate_provides else "FAIL", "every bundled alias is supplied exactly once" if not duplicate_provides else ", ".join(sorted(duplicate_provides))))
    missing = sorted(bundled.difference(provided))
    extra = sorted(provided.difference(bundled))
    checks.append(Check("bundled registry → installer coverage", "PASS" if not missing else "FAIL", "every bundled integration has a pinned production payload" if not missing else "missing: " + ", ".join(missing)))
    checks.append(Check("manifest excludes blocked/external integrations", "PASS" if not extra else "FAIL", "manifest contains only release-bundled integrations" if not extra else "not classified bundled: " + ", ".join(extra)))
    checks.append(Check("installed bundled binaries", "PASS" if not absent else "FAIL", "all required binaries are present" if require_installed and not absent else ("deferred until post-staging gate" if not require_installed else "missing: " + ", ".join(absent))))
    checks.append(Check("safe liveness probes", "PASS" if not probe_failures else "FAIL", "present binaries passed non-invasive liveness probes" if not probe_failures else "; ".join(probe_failures[:30])))

    ok = _markdown("Phase B — Tool Liveness and Packaging Audit", checks, REPORTS / "tool_liveness.md")
    _record("B", ok)
    return ok


def phase_e() -> bool:
    checks: list[Check] = []
    checks.append(Check("Python version", "PASS" if sys.version_info[:2] == (3, 11) else "FAIL", sys.version.split()[0]))
    pip_check = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True)
    checks.append(Check("pip check", "PASS" if pip_check.returncode == 0 else "FAIL", (pip_check.stdout or pip_check.stderr).strip()[:1500] or "dependency graph consistent"))
    audit = subprocess.run([sys.executable, "-m", "pip_audit", "-r", str(ROOT / "requirements.txt"), "--progress-spinner", "off", "--format", "json"], capture_output=True, text=True)
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
            if str(ROOT) not in sys.path:
                sys.path.insert(0, str(ROOT))
            from app.server import create_app

            app = create_app()
            app.testing = True
            client = app.test_client()
            health = client.get("/api/health")
            body = health.get_json() or {}
            health_ok = (
                health.status_code == 200
                and body.get("status") == "ok"
                and body.get("localhost_only") is True
                and body.get("integrations_total") == EXPECTED_ACTIVE_TOOL_COUNT
                and body.get("windows_certified_tools") == EXPECTED_CERTIFIED_TOOL_COUNT
                and body.get("test_count") == EXPECTED_TEST_COUNT
            )
            checks.append(Check("local health and release identity", "PASS" if health_ok else "FAIL", f"HTTP {health.status_code}: {body}"))

            remote = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "203.0.113.10"})
            checks.append(Check("remote dashboard blocked", "PASS" if remote.status_code == 403 else "FAIL", f"HTTP {remote.status_code}"))
            handshake = client.post("/api/handshake")
            hs = handshake.get_json() or {}
            csrf = hs.get("csrf_token", "")
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
                json={"target": "blocked.example.test", "scope": ["example.test"], "out_of_scope": ["blocked.example.test"], "consent_id": consent_id},
                headers=headers,
            )
            checks.append(Check("out-of-scope denied", "PASS" if denied.status_code == 403 else "FAIL", f"HTTP {denied.status_code}"))
            tampered = client.post(
                "/api/preflight/check",
                json={"target": "other.example.test", "scope": ["other.example.test"], "out_of_scope": [], "consent_id": consent_id},
                headers=headers,
            )
            checks.append(Check("consent scope binding", "PASS" if tampered.status_code == 403 else "FAIL", f"HTTP {tampered.status_code}"))
            integrations = client.get("/api/integrations", headers=headers)
            integration_body = integrations.get_json() or {}
            secure_ok = integration_body.get("database", {}).get("encrypted") is True and integration_body.get("flows", {}).get("encrypted") is True
            checks.append(Check("secure operational persistence", "PASS" if integrations.status_code == 200 and secure_ok else "FAIL", f"HTTP {integrations.status_code}: {integration_body}"))
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
        return None, "reports/coverage.xml missing; run tests before Phase F"
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
    parser.add_argument("--require-installed", action="store_true", help="Phase B: require every bundled Windows binary to exist and pass its safe probe")
    args = parser.parse_args()
    if args.phase == "B":
        ok = phase_b(require_installed=args.require_installed)
    else:
        ok = {"A": phase_a, "D": phase_d, "E": phase_e, "F": phase_f}[args.phase]()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
