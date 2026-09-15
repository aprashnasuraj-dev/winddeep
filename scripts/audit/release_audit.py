"""Windeep release audits used by the Windows tag-release gate.

The audits are intentionally fail-closed. They never scan an external target;
Phase D exercises only the local Flask test client and security guardrails.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"
STATUS_FILE = REPORTS / "phase_status.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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
    lines = [f"# {title}", "", f"Overall: **{'PASS' if not failures else 'FAIL'}**", "", "| Check | Result | Detail |", "|---|---|---|"]
    for c in checks:
        detail = c.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {c.name} | **{c.status}** | {detail} |")
    lines += ["", f"Failures: **{len(failures)}**", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return not failures


def _load_registry() -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[Check]]:
    checks: list[Check] = []
    root_path = ROOT / "tools_config.json"
    if not root_path.exists():
        return {}, {}, [Check("tools_config.json", "FAIL", "missing root tool registry")]
    try:
        root = json.loads(root_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, {}, [Check("tools_config.json", "FAIL", f"invalid JSON: {exc}")]
    tools: dict[str, dict[str, Any]] = {}
    for rel in root.get("includes", []):
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


def phase_a() -> bool:
    checks: list[Check] = []
    python_files = [ROOT / "launcher.py", *sorted((ROOT / "app").rglob("*.py")), *sorted((ROOT / "scripts").rglob("*.py"))]
    compile_errors: list[str] = []
    for path in python_files:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            compile_errors.append(f"{path.relative_to(ROOT)}: {exc.msg}")
    checks.append(Check("Python syntax", "PASS" if not compile_errors else "FAIL", f"{len(python_files)} files compiled" if not compile_errors else "; ".join(compile_errors[:10])))

    root_registry, tools, registry_checks = _load_registry()
    checks.extend(registry_checks)
    required_fields = {"binary", "category", "args", "timeout", "retries", "rate_limit", "requires_scope"}
    bad: list[str] = []
    unsafe_scope: list[str] = []
    for name, definition in tools.items():
        missing = sorted(required_fields - set(definition))
        if missing:
            bad.append(f"{name}: missing {','.join(missing)}")
        if definition.get("requires_scope") is not True:
            unsafe_scope.append(name)
    checks.append(Check("wrapper metadata completeness", "PASS" if not bad else "FAIL", f"{len(tools)} wrappers structurally complete" if not bad else "; ".join(bad[:20])))
    checks.append(Check("wrapper scope requirement", "PASS" if not unsafe_scope else "FAIL", "all external wrappers require explicit scope" if not unsafe_scope else f"scope not mandatory: {', '.join(unsafe_scope[:20])}"))

    normalized: dict[str, list[str]] = {}
    for name, definition in tools.items():
        binary = str(definition.get("binary", name)).lower().replace("-", "").replace("_", "")
        normalized.setdefault(binary, []).append(name)
    aliases = [names for names in normalized.values() if len(names) > 1]
    checks.append(Check("duplicate/dead alias detection", "WARN" if aliases else "PASS", "possible duplicate binary aliases: " + "; ".join(", ".join(a) for a in aliases[:10]) if aliases else "no duplicate normalized binary names"))

    ui = ROOT / "app" / "static" / "index.html"
    checks.append(Check("desktop dashboard UI", "PASS" if ui.exists() else "FAIL", "app/static/index.html present" if ui.exists() else "full dashboard asset is absent; current server exposes bootstrap HTML only"))

    required_release_files = [
        ROOT / "Windeep.spec",
        ROOT / "installer" / "BugBountyInstaller.iss",
        ROOT / "installer" / "setup_tools.ps1",
        ROOT / "installer" / "install_python.ps1",
        ROOT / "installer" / "tools-manifest.json",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        ROOT / "scripts" / "audit" / "windows_install_audit.ps1",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required_release_files if not p.exists()]
    checks.append(Check("release file set", "PASS" if not missing else "FAIL", "all required release inputs present" if not missing else "missing: " + ", ".join(missing)))

    spec_text = (ROOT / "Windeep.spec").read_text(encoding="utf-8") if (ROOT / "Windeep.spec").exists() else ""
    checks.append(Check("PyInstaller onedir layout", "PASS" if "COLLECT(" in spec_text else "FAIL", "COLLECT onedir build configured" if "COLLECT(" in spec_text else "Windeep.spec does not create dist/Windeep/"))

    iss_text = (ROOT / "installer" / "BugBountyInstaller.iss").read_text(encoding="utf-8") if (ROOT / "installer" / "BugBountyInstaller.iss").exists() else ""
    recursive_package = "dist\\Windeep\\*" in iss_text and "recursesubdirs" in iss_text
    checks.append(Check("installer packages complete app tree", "PASS" if recursive_package else "FAIL", "dist/Windeep is installed recursively" if recursive_package else "installer does not recursively include dist/Windeep"))

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
    checks.extend(c for c in registry_checks if c.status == "FAIL")
    manifest, manifest_checks = _manifest()
    checks.extend(manifest_checks)
    checks.append(Check("portable tool manifest non-empty", "PASS" if manifest else "FAIL", f"{len(manifest)} package entries" if manifest else "manifest contains no downloadable tools"))

    provided: set[str] = set()
    invalid: list[str] = []
    probe_failures: list[str] = []
    for entry in manifest:
        name = str(entry.get("name", "")).strip()
        destinations = str(entry.get("destination", "")).strip()
        url = str(entry.get("url", "")).strip()
        digest = str(entry.get("sha256", "")).strip()
        probe = entry.get("probe")
        aliases = entry.get("provides", [name])
        if not name or not destinations or not url.startswith("https://") or not SHA256_RE.match(digest):
            invalid.append(name or "<unnamed>")
        if not isinstance(aliases, list) or not all(isinstance(v, str) and v for v in aliases):
            invalid.append(name or "<unnamed>")
            aliases = []
        provided.update(aliases)
        if not isinstance(probe, list) or not probe or not all(isinstance(v, str) for v in probe):
            invalid.append(f"{name or '<unnamed>'} (missing safe probe)")
            continue
        binary = ROOT / "tools" / destinations
        if binary.exists():
            try:
                completed = subprocess.run([str(binary), *probe], capture_output=True, text=True, timeout=15, shell=False)
                expected = entry.get("expected_exit_codes", [0])
                if completed.returncode not in expected:
                    probe_failures.append(f"{name}: exit {completed.returncode}")
            except Exception as exc:
                probe_failures.append(f"{name}: {exc}")
    checks.append(Check("tool manifest integrity", "PASS" if not invalid else "FAIL", "URLs, hashes, provides and safe probes are defined" if not invalid else "invalid entries: " + ", ".join(invalid[:30])))
    missing = sorted(set(tools) - provided)
    extra = sorted(provided - set(tools))
    checks.append(Check("registry → installer coverage", "PASS" if not missing else "FAIL", "every registered wrapper is supplied by the installer" if not missing else f"unpackaged wrappers ({len(missing)}): {', '.join(missing[:40])}"))
    checks.append(Check("manifest orphan detection", "WARN" if extra else "PASS", "manifest-only names: " + ", ".join(extra[:40]) if extra else "no orphan manifest mappings"))
    checks.append(Check("safe liveness probes", "PASS" if not probe_failures else "FAIL", "available cached binaries passed their non-invasive probe; uncached binaries are verified after G11" if not probe_failures else "; ".join(probe_failures[:20])))
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
            checks.append(Check("local health", "PASS" if health.status_code == 200 and health.get_json().get("status") == "ok" else "FAIL", f"HTTP {health.status_code}: {health.get_json()}"))
            remote = client.get("/api/health", environ_overrides={"REMOTE_ADDR": "203.0.113.10"})
            checks.append(Check("remote dashboard blocked", "PASS" if remote.status_code == 403 else "FAIL", f"HTTP {remote.status_code}"))
            hs = client.post("/api/handshake")
            hs_body = hs.get_json() or {}
            csrf = hs_body.get("csrf_token", "")
            checks.append(Check("auth handshake", "PASS" if hs.status_code == 200 and csrf else "FAIL", f"HTTP {hs.status_code}"))
            headers = {"X-CSRF-Token": csrf}
            consent = client.post("/api/consent", json={"target": "example.test", "scope": ["example.test"], "out_of_scope": ["blocked.example.test"], "authorized_by": "release-audit", "purpose": "local CI guardrail verification", "ttl_seconds": 300}, headers=headers)
            consent_body = consent.get_json() or {}
            cid = consent_body.get("id", "")
            checks.append(Check("signed consent", "PASS" if consent.status_code == 201 and cid else "FAIL", f"HTTP {consent.status_code}"))
            preflight = client.post("/api/preflight/check", json={"target": "example.test", "scope": ["example.test"], "out_of_scope": ["blocked.example.test"], "consent_id": cid, "global_rps": 1.0, "global_burst": 1.0}, headers=headers)
            checks.append(Check("authorized preflight", "PASS" if preflight.status_code == 200 and (preflight.get_json() or {}).get("authorized") is True else "FAIL", f"HTTP {preflight.status_code}: {preflight.get_json()}"))
            denied = client.post("/api/preflight/check", json={"target": "blocked.example.test", "scope": ["example.test"], "out_of_scope": ["blocked.example.test"], "consent_id": cid}, headers=headers)
            checks.append(Check("out-of-scope denied", "PASS" if denied.status_code == 403 else "FAIL", f"HTTP {denied.status_code}"))
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
    payload = {"decision": decision, "version": version, "checks": {phase: bool(states.get(phase)) for phase in required}, "blockers": blockers}
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
