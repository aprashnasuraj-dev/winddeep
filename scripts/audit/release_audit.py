"""Fail-closed Windeep release audits used by Windows QA and tag publishing.

No audit scans an external target. Phase D uses Flask's local test client and
exercises only localhost authentication, consent, scope, encrypted persistence,
API wiring, and evidence-only test packs.
"""
from __future__ import annotations

import argparse
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"
STATUS_FILE = REPORTS / "phase_status.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
EXPECTED_TOOL_COUNT = 137
EXPECTED_TEST_COUNT = 160
EXPECTED_UI_SECTIONS = {
    "targets", "scan-center", "recon", "web-scanner", "mobile-lab", "web3-audit",
    "secrets", "findings", "report-builder", "toolkit", "tools-status", "live-traffic",
    "brain-console", "chain-builder", "memory-vault", "settings",
}
ALLOWED_RELEASE_SUPPORT = {"bundled", "internal", "unsupported", "deprecated", "legacy"}


@dataclass(slots=True)
class Check:
    name: str
    status: str
    detail: str


def _record(phase: str, ok: bool) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    try:
        state = json.loads(STATUS_FILE.read_text(encoding="utf-8")) if STATUS_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        state = {}
    state[phase] = bool(ok)
    STATUS_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _markdown(title: str, checks: list[Check], path: Path) -> bool:
    REPORTS.mkdir(parents=True, exist_ok=True)
    failures = [item for item in checks if item.status == "FAIL"]
    lines = [
        f"# {title}", "", f"Overall: **{'PASS' if not failures else 'FAIL'}**", "",
        "| Check | Result | Detail |", "|---|---|---|",
    ]
    for item in checks:
        detail = item.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {item.name} | **{item.status}** | {detail} |")
    lines += ["", f"Failures: **{len(failures)}**", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return not failures


def _load_registry() -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[Check]]:
    checks: list[Check] = []
    root_path = ROOT / "tools_config.json"
    if not root_path.exists():
        return {}, {}, [Check("tools_config.json", "FAIL", "missing root registry")]
    try:
        root = json.loads(root_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, {}, [Check("tools_config.json", "FAIL", f"invalid JSON: {exc}")]
    tools: dict[str, dict[str, Any]] = {}
    includes = root.get("includes", [])
    if not isinstance(includes, list):
        return root, {}, [Check("registry includes", "FAIL", "includes must be an array")]
    for rel in includes:
        path = (ROOT / str(rel)).resolve()
        if not path.is_relative_to(ROOT):
            checks.append(Check(f"registry include {rel}", "FAIL", "include escapes repository"))
            continue
        if not path.exists():
            checks.append(Check(f"registry include {rel}", "FAIL", "declared include is missing"))
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            definitions = payload.get("tools", {})
            if not isinstance(definitions, dict):
                raise TypeError("tools must be an object")
            overlap = sorted(set(tools).intersection(definitions))
            if overlap:
                checks.append(Check(f"registry include {rel}", "FAIL", "duplicate names: " + ", ".join(overlap)))
                continue
            tools.update({str(name): dict(value) for name, value in definitions.items() if isinstance(value, dict)})
            checks.append(Check(f"registry include {rel}", "PASS", f"{len(definitions)} definitions"))
        except Exception as exc:
            checks.append(Check(f"registry include {rel}", "FAIL", f"invalid registry: {exc}"))
    declared = root.get("tool_count")
    checks.append(Check(
        "declared tool count",
        "PASS" if declared == len(tools) == EXPECTED_TOOL_COUNT else "FAIL",
        f"declared={declared}, actual={len(tools)}, required={EXPECTED_TOOL_COUNT}",
    ))
    return root, tools, checks


def _effective_tools() -> tuple[dict[str, dict[str, Any]], str | None]:
    try:
        sys.path.insert(0, str(ROOT))
        from app.tools.release_metadata import effective_definitions
        return effective_definitions(ROOT / "tools_config.json"), None
    except Exception as exc:
        return {}, str(exc)
    finally:
        try:
            sys.path.remove(str(ROOT))
        except ValueError:
            pass


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


def phase_a() -> bool:
    checks: list[Check] = []
    python_files = [ROOT / "launcher.py", *sorted((ROOT / "app").rglob("*.py")), *sorted((ROOT / "scripts").rglob("*.py"))]
    errors: list[str] = []
    for path in python_files:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc.msg}")
    checks.append(Check("Python syntax", "PASS" if not errors else "FAIL", f"{len(python_files)} files compiled" if not errors else "; ".join(errors[:20])))

    _, tools, registry_checks = _load_registry()
    checks.extend(registry_checks)
    required_fields = {"binary", "category", "args", "timeout", "retries", "rate_limit", "requires_scope"}
    bad = []
    unsafe = []
    for name, definition in tools.items():
        missing = sorted(required_fields.difference(definition))
        if missing:
            bad.append(f"{name}: {','.join(missing)}")
        if definition.get("requires_scope") is not True:
            unsafe.append(name)
    checks.append(Check("wrapper metadata completeness", "PASS" if not bad else "FAIL", f"{len(tools)} wrappers structurally complete" if not bad else "; ".join(bad[:30])))
    checks.append(Check("wrapper scope requirement", "PASS" if not unsafe else "FAIL", "all wrappers require explicit scope" if not unsafe else "unsafe: " + ", ".join(unsafe[:30])))

    effective, policy_error = _effective_tools()
    checks.append(Check("release policy load", "PASS" if not policy_error and len(effective) == EXPECTED_TOOL_COUNT else "FAIL", policy_error or f"{len(effective)} integrations classified"))
    invalid_support = sorted(name for name, value in effective.items() if value.get("release_support") not in ALLOWED_RELEASE_SUPPORT)
    checks.append(Check("release classification values", "PASS" if not invalid_support else "FAIL", "all classifications are recognized" if not invalid_support else ", ".join(invalid_support[:40])))
    unreasoned = sorted(name for name, value in effective.items() if value.get("release_support") in {"unsupported", "deprecated", "legacy"} and not str(value.get("unsupported_reason") or "").strip())
    checks.append(Check("blocked integration reasons", "PASS" if not unreasoned else "FAIL", "every blocked integration explains why" if not unreasoned else ", ".join(unreasoned[:40])))
    bundled_unlicensed = sorted(name for name, value in effective.items() if value.get("release_support") == "bundled" and (not value.get("license") or not value.get("homepage")))
    checks.append(Check("bundled license metadata", "PASS" if not bundled_unlicensed else "FAIL", "every bundled integration has license/homepage metadata" if not bundled_unlicensed else ", ".join(bundled_unlicensed)))
    legacy_expect = {
        "aquatone": ("deprecated", "gowitness"),
        "jsparser": ("deprecated", "linkfinder"),
        "waffw00f": ("deprecated", "wafw00f"),
        "sublist3r": ("legacy", "subfinder"),
    }
    legacy_bad = []
    for name, (status, replacement) in legacy_expect.items():
        value = effective.get(name, {})
        if value.get("release_support") != status or value.get("replacement") != replacement:
            legacy_bad.append(name)
    checks.append(Check("legacy/dead classification", "PASS" if not legacy_bad else "FAIL", "Aquatone, JSParser, waffw00f and Sublist3r are explicitly blocked/replaced" if not legacy_bad else "incorrect: " + ", ".join(legacy_bad)))

    try:
        sys.path.insert(0, str(ROOT))
        from app.modules.test_packs import all_tests
        test_count = len(all_tests())
        checks.append(Check("160 production test packs", "PASS" if test_count == EXPECTED_TEST_COUNT else "FAIL", f"registered={test_count}, required={EXPECTED_TEST_COUNT}"))
    except Exception as exc:
        checks.append(Check("160 production test packs", "FAIL", repr(exc)))
    finally:
        try:
            sys.path.remove(str(ROOT))
        except ValueError:
            pass

    html = ROOT / "app" / "static" / "index.html"
    css = ROOT / "app" / "static" / "styles.css"
    js = ROOT / "app" / "static" / "app.js"
    missing_assets = [str(path.relative_to(ROOT)) for path in (html, css, js) if not path.exists()]
    checks.append(Check("production dashboard assets", "PASS" if not missing_assets else "FAIL", "index.html + external CSS/JS present" if not missing_assets else "missing: " + ", ".join(missing_assets)))
    if html.exists():
        text = html.read_text(encoding="utf-8")
        present = {match for match in re.findall(r'<section\s+id="([^"]+)"', text)}
        missing_sections = sorted(EXPECTED_UI_SECTIONS.difference(present))
        checks.append(Check("dashboard integration sections", "PASS" if not missing_sections else "FAIL", f"{len(present)} section IDs present" if not missing_sections else "missing: " + ", ".join(missing_sections)))

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8") if (ROOT / "requirements.txt").exists() else ""
    capture_requirements = (ROOT / "requirements-capture.txt").read_text(encoding="utf-8") if (ROOT / "requirements-capture.txt").exists() else ""
    checks.append(Check("mitmproxy runtime isolation", "PASS" if "mitmproxy" not in requirements.casefold() and "mitmproxy==12.2.3" in capture_requirements else "FAIL", "main Python 3.11 excludes mitmproxy; capture pins 12.2.3 for Python 3.12"))
    standalone = (ROOT / "app" / "capture" / "standalone.py").read_text(encoding="utf-8") if (ROOT / "app" / "capture" / "standalone.py").exists() else ""
    checks.append(Check("secure standalone capture wiring", "PASS" if all(token in standalone for token in ("SecureDatabase", "SecureFlowDatabase", "WINDEEP_RESOLVE_ENDPOINT")) else "FAIL", "standalone capture uses encrypted database and explicit resolver"))

    required_release_files = [
        ROOT / "Windeep.spec", ROOT / "installer" / "BugBountyInstaller.iss",
        ROOT / "installer" / "setup_tools.ps1", ROOT / "installer" / "install_python.ps1",
        ROOT / "installer" / "install_capture_runtime.ps1", ROOT / "installer" / "tools-manifest.json",
        ROOT / "requirements.txt", ROOT / "requirements-dev.txt", ROOT / "requirements-capture.txt",
        ROOT / "app" / "tools" / "release-policy.json",
        ROOT / "scripts" / "audit" / "windows_install_audit.ps1",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required_release_files if not path.exists()]
    checks.append(Check("release file set", "PASS" if not missing else "FAIL", "all required release inputs present" if not missing else "missing: " + ", ".join(missing)))
    spec_text = (ROOT / "Windeep.spec").read_text(encoding="utf-8") if (ROOT / "Windeep.spec").exists() else ""
    checks.append(Check("PyInstaller onedir/source contract", "PASS" if "COLLECT(" in spec_text and '(ROOT / "app", "app")' in spec_text else "FAIL", "onedir build ships exact app source for isolated capture process"))
    iss_text = (ROOT / "installer" / "BugBountyInstaller.iss").read_text(encoding="utf-8") if (ROOT / "installer" / "BugBountyInstaller.iss").exists() else ""
    checks.append(Check("installer packages complete app tree", "PASS" if "dist\\Windeep\\*" in iss_text and "recursesubdirs" in iss_text else "FAIL", "dist/Windeep installed recursively"))

    ok = _markdown("Phase A — Static Release Audit", checks, REPORTS / "static_audit.md")
    _record("A", ok)
    return ok


def phase_b(*, require_installed: bool = False) -> bool:
    checks: list[Check] = []
    effective, policy_error = _effective_tools()
    if policy_error:
        checks.append(Check("release policy", "FAIL", policy_error))
    manifest, manifest_checks = _manifest()
    checks.extend(manifest_checks)
    checks.append(Check("portable tool manifest non-empty", "PASS" if manifest else "FAIL", f"{len(manifest)} package entries" if manifest else "manifest contains no bundled tools"))

    bundled = {name for name, value in effective.items() if value.get("release_support") == "bundled"}
    provided: set[str] = set()
    invalid: list[str] = []
    probe_failures: list[str] = []
    absent: list[str] = []
    names: set[str] = set()
    for entry in manifest:
        name = str(entry.get("name", "")).strip()
        if name in names:
            invalid.append(f"duplicate {name}")
        names.add(name)
        destination = str(entry.get("destination", "")).strip()
        url = str(entry.get("url", "")).strip()
        digest = str(entry.get("sha256", "")).strip()
        version = str(entry.get("version", "")).strip()
        license_name = str(entry.get("license", "")).strip()
        review = str(entry.get("redistribution_review", "")).strip()
        probe = entry.get("probe")
        aliases = entry.get("provides", [name])
        if not name or not version or not destination or not url.startswith("https://") or not SHA256_RE.match(digest) or not license_name or not review:
            invalid.append(name or "<unnamed>")
        if entry.get("archive") == "zip" and not str(entry.get("archive_member", "")).strip():
            invalid.append(f"{name} missing archive_member")
        if not isinstance(aliases, list) or not aliases or not all(isinstance(value, str) and value for value in aliases):
            invalid.append(f"{name} invalid provides")
            aliases = []
        provided.update(aliases)
        if not isinstance(probe, list) or not probe or not all(isinstance(value, str) and value for value in probe):
            invalid.append(f"{name} missing safe probe")
            continue
        binary = ROOT / "tools" / destination
        if not binary.exists():
            if require_installed:
                absent.append(name)
            continue
        try:
            completed = subprocess.run([str(binary), *probe], capture_output=True, text=True, timeout=20, shell=False)
            expected = entry.get("expected_exit_codes", [0])
            if completed.returncode not in expected:
                probe_failures.append(f"{name}: exit {completed.returncode}")
        except Exception as exc:
            probe_failures.append(f"{name}: {exc}")
    checks.append(Check("tool manifest integrity", "PASS" if not invalid else "FAIL", "URLs, versions, hashes, licenses, reviews, mappings and probes are defined" if not invalid else "; ".join(invalid[:40])))
    missing = sorted(bundled.difference(provided))
    extra = sorted(provided.difference(bundled))
    checks.append(Check("bundled registry → installer coverage", "PASS" if not missing else "FAIL", "every bundled integration has a pinned installer artifact" if not missing else "missing: " + ", ".join(missing)))
    checks.append(Check("manifest blocked-tool exclusion", "PASS" if not extra else "FAIL", "manifest contains only release-bundled integrations" if not extra else "not classified bundled: " + ", ".join(extra)))
    checks.append(Check("installed bundled binaries", "PASS" if not absent else "FAIL", "all required binaries are present" if require_installed and not absent else ("deferred until G11" if not require_installed else "missing: " + ", ".join(absent))))
    checks.append(Check("safe liveness probes", "PASS" if not probe_failures else "FAIL", "present binaries passed non-invasive probes" if not probe_failures else "; ".join(probe_failures[:30])))
    ok = _markdown("Phase B — Tool Liveness and Packaging Audit", checks, REPORTS / "tool_liveness.md")
    _record("B", ok)
    return ok


def phase_e() -> bool:
    checks: list[Check] = []
    checks.append(Check("Python version", "PASS" if sys.version_info[:2] == (3, 11) else "FAIL", sys.version.split()[0]))
    pip_check = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True)
    checks.append(Check("pip check", "PASS" if pip_check.returncode == 0 else "FAIL", (pip_check.stdout or pip_check.stderr).strip()[:1600] or "dependency graph consistent"))
    audit = subprocess.run([sys.executable, "-m", "pip_audit", "-r", str(ROOT / "requirements.txt"), "--progress-spinner", "off", "--format", "json"], capture_output=True, text=True)
    checks.append(Check("pip-audit", "PASS" if audit.returncode == 0 else "FAIL", "no known vulnerabilities reported" if audit.returncode == 0 else (audit.stdout or audit.stderr).strip()[:2500]))
    capture = (ROOT / "requirements-capture.txt").read_text(encoding="utf-8").strip()
    checks.append(Check("capture dependency pin", "PASS" if capture.splitlines()[-1:] == ["mitmproxy==12.2.3"] else "FAIL", capture[-500:]))
    ok = _markdown("Phase E — Dependency Audit", checks, REPORTS / "dependency_audit.md")
    _record("E", ok)
    return ok


def phase_d() -> bool:
    checks: list[Check] = []
    with tempfile.TemporaryDirectory(prefix="windeep-e2e-") as tmp:
        old = os.environ.get("WINDEEP_STATE_DIR")
        os.environ["WINDEEP_STATE_DIR"] = tmp
        runtime = None
        try:
            sys.path.insert(0, str(ROOT))
            from app.server import create_app
            app = create_app()
            app.testing = True
            runtime = app.extensions["windeep.runtime"]
            client = app.test_client()
            health = client.get("/api/health")
            health_json = health.get_json() or {}
            checks.append(Check("local health", "PASS" if health.status_code == 200 and health_json.get("status") == "ok" and health_json.get("tool_count") == EXPECTED_TOOL_COUNT else "FAIL", f"HTTP {health.status_code}: {health_json}"))
            remote = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "203.0.113.10"})
            checks.append(Check("remote dashboard blocked", "PASS" if remote.status_code == 403 else "FAIL", f"HTTP {remote.status_code}"))
            hs = client.post("/api/handshake")
            csrf = (hs.get_json() or {}).get("csrf_token", "")
            checks.append(Check("auth handshake", "PASS" if hs.status_code == 200 and csrf else "FAIL", f"HTTP {hs.status_code}"))
            headers = {"X-CSRF-Token": csrf}
            create_target = client.post("/api/targets", json={"name":"CI","type":"web","target":"example.test","scope":["example.test"],"out_of_scope":["blocked.example.test"]}, headers=headers)
            target = create_target.get_json() or {}
            checks.append(Check("target API", "PASS" if create_target.status_code == 201 and target.get("id") else "FAIL", f"HTTP {create_target.status_code}: {target}"))
            consent = client.post("/api/consent", json={"target":"example.test","scope":["example.test"],"out_of_scope":["blocked.example.test"],"authorized_by":"release-audit","purpose":"local CI guardrail verification","ttl_seconds":300}, headers=headers)
            cid = (consent.get_json() or {}).get("id", "")
            checks.append(Check("signed consent", "PASS" if consent.status_code == 201 and cid else "FAIL", f"HTTP {consent.status_code}"))
            preflight = client.post("/api/preflight/check", json={"target":"example.test","scope":["example.test"],"out_of_scope":["blocked.example.test"],"consent_id":cid,"global_rps":1.0,"global_burst":1.0}, headers=headers)
            checks.append(Check("authorized preflight", "PASS" if preflight.status_code == 200 and (preflight.get_json() or {}).get("authorized") is True else "FAIL", f"HTTP {preflight.status_code}: {preflight.get_json()}"))
            denied = client.post("/api/preflight/check", json={"target":"blocked.example.test","scope":["example.test"],"out_of_scope":["blocked.example.test"],"consent_id":cid}, headers=headers)
            checks.append(Check("out-of-scope denied", "PASS" if denied.status_code == 403 else "FAIL", f"HTTP {denied.status_code}"))
            packs = client.get("/api/test-packs")
            pack_json = packs.get_json() or {}
            checks.append(Check("test-pack API", "PASS" if packs.status_code == 200 and pack_json.get("count") == EXPECTED_TEST_COUNT else "FAIL", f"HTTP {packs.status_code}: count={pack_json.get('count')}"))
            run = client.post("/api/test-packs/run", json={"target_id":target.get("id"),"consent_id":cid,"packs":["browser_fidelity"]}, headers=headers)
            run_json = run.get_json() or {}
            checks.append(Check("evidence test-pack execution", "PASS" if run.status_code == 200 and run_json.get("count") == 20 else "FAIL", f"HTTP {run.status_code}: count={run_json.get('count')}"))
            root = client.get("/")
            checks.append(Check("production dashboard served", "PASS" if root.status_code == 200 and b"brain-console" in root.data and b"live-traffic" in root.data else "FAIL", f"HTTP {root.status_code}"))
            settings = client.get("/api/settings")
            settings_json = settings.get_json() or {}
            checks.append(Check("guardrail settings contract", "PASS" if settings.status_code == 200 and settings_json.get("encryption_at_rest") is True and settings_json.get("signed_consent_required") is True else "FAIL", f"HTTP {settings.status_code}: {settings_json}"))
        except Exception as exc:
            checks.append(Check("E2E execution", "FAIL", repr(exc)))
        finally:
            if runtime is not None:
                try:
                    runtime.close()
                except Exception:
                    pass
            try:
                sys.path.remove(str(ROOT))
            except ValueError:
                pass
            if old is None:
                os.environ.pop("WINDEEP_STATE_DIR", None)
            else:
                os.environ["WINDEEP_STATE_DIR"] = old
    ok = _markdown("Phase D — Local End-to-End Guardrail Audit", checks, REPORTS / "e2e_audit.md")
    _record("D", ok)
    return ok


def phase_f() -> bool:
    REPORTS.mkdir(parents=True, exist_ok=True)
    try:
        states = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except Exception:
        states = {}
    required = ["A", "B", "E", "D"]
    blockers = [f"Phase {phase} did not PASS" for phase in required if states.get(phase) is not True]
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() if (ROOT / "VERSION").exists() else "unknown"
    decision = "GO" if not blockers else "NO-GO"
    payload = {"decision":decision,"version":version,"checks":{phase:bool(states.get(phase)) for phase in required},"blockers":blockers}
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
        ok = {"A":phase_a,"D":phase_d,"E":phase_e,"F":phase_f}[args.phase]()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
