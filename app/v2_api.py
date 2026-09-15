"""Windeep v2 product API.

This module adds a coherent product layer over the 137-entry integration
catalog without weakening the existing authorization boundary.  It focuses on
runtime readiness, target compatibility, cancellable scans, evidence-first
reports, and actionable local intelligence.  The v1 API remains intact for
release compatibility while the v2 UI migrates to these endpoints.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from flask import Flask, Response, jsonify, request

from app.engine.tool_wrapper import ToolCancelledError, ToolExecutionError
from app.engine.scan_runtime import RegisteredScanRuntime
from app.engine.v3_scan_pipeline import V3ScanPipeline
from app.tools import builtin_integrations


_CATEGORY_TARGET_TYPES: dict[str, tuple[str, ...]] = {
    "recon_passive": ("domain", "url", "host", "web"),
    "recon_active": ("domain", "url", "host", "web"),
    "web_vulns": ("url", "domain", "host", "web"),
    "mobile": ("apk", "ipa", "package", "mobile"),
    "web3": ("contract", "repo", "file", "web3"),
    "secrets": ("repo", "file", "url", "web"),
    "network": ("host", "domain", "url", "web"),
    "utilities": ("domain", "url", "host", "repo", "file", "apk", "ipa", "contract", "web", "mobile", "web3"),
}

_TARGET_ALIASES = {
    "website": "url",
    "web": "web",
    "domain": "domain",
    "url": "url",
    "host": "host",
    "ip": "host",
    "cidr": "host",
    "repository": "repo",
    "repo": "repo",
    "source": "repo",
    "file": "file",
    "apk": "apk",
    "ipa": "ipa",
    "package": "package",
    "mobile": "mobile",
    "contract": "contract",
    "web3": "web3",
}

_SETTINGS_ENV = {
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "etherscan_api_key": "ETHERSCAN_API_KEY",
    "corellium_base_url": "CORELLIUM_BASE_URL",
    "corellium_api_token": "CORELLIUM_API_TOKEN",
    "mobsf_url": "MOBSF_URL",
    "mobsf_api_key": "MOBSF_API_KEY",
}

_SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _target_type(value: str) -> str:
    return _TARGET_ALIASES.get(str(value or "").strip().lower(), str(value or "web").strip().lower() or "web")


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:80] or "windeep-report"


def _proof_markdown(target: Mapping[str, Any], findings: list[dict[str, Any]], title: str) -> str:
    lines = [
        f"# {title}",
        "",
        f"Target: `{target.get('target', '')}`",
        f"Target type: `{target.get('type', '')}`",
        f"Generated: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
        "",
        "> Windeep encrypts stored evidence at rest. This exported report is intentionally plaintext so an authorized tester can submit reproducible proof.",
        "",
        "## Executive summary",
        "",
        f"Findings: **{len(findings)}**",
        "",
    ]
    counts = {name: 0 for name in _SEVERITY_WEIGHT}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    lines.append("Severity: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    lines.extend(["", "## Findings with raw proof", ""])

    if not findings:
        lines.extend(["No findings were recorded for this target.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity") or "info").upper()
        endpoint = str(finding.get("endpoint") or target.get("target") or "")
        lines.extend(
            [
                f"### {index}. [{severity}] {finding.get('title', 'Finding')}",
                "",
                f"- Finding ID: `{finding.get('id', '')}`",
                f"- Tool: `{finding.get('tool', '')}`",
                f"- Type: `{finding.get('vuln_type', '')}`",
                f"- Endpoint: `{endpoint}`",
                f"- Confidence: `{finding.get('confidence', 0.5)}`",
                f"- CVSS: `{finding.get('cvss_score') if finding.get('cvss_score') is not None else 'not scored'}`",
                "",
            ]
        )
        description = str(finding.get("description") or "").strip()
        if description:
            lines.extend(["#### Description", "", description, ""])

        steps = str(finding.get("steps") or "").strip()
        if not steps:
            steps = (
                f"1. Use `{finding.get('tool', 'the recorded tool')}` against the same authorized target `{endpoint}`.\n"
                "2. Keep the same target scope and authentication context used by the recorded scan.\n"
                "3. Compare the resulting output with the raw evidence below."
            )
        lines.extend(["#### Proof of concept / reproduction", "", steps, ""])

        evidence = finding.get("evidence") or {}
        lines.extend(["#### Raw evidence", "", "```json", json.dumps(evidence, indent=2, ensure_ascii=False, default=str), "```", ""])

        raw_request = str(finding.get("request") or "").strip()
        raw_response = str(finding.get("response") or "").strip()
        if raw_request:
            lines.extend(["#### Raw request", "", "```http", raw_request, "```", ""])
        if raw_response:
            lines.extend(["#### Raw response", "", "```http", raw_response, "```", ""])

        impact = str(finding.get("impact") or "").strip()
        remediation = str(finding.get("remediation") or "").strip()
        if impact:
            lines.extend(["#### Impact", "", impact, ""])
        if remediation:
            lines.extend(["#### Remediation", "", remediation, ""])
        lines.extend(["---", ""])
    return "\n".join(lines)


def register_v2_api(
    app: Flask,
    *,
    root: Path,
    state: Path,
    tools_dir: Path,
    crypto: Any,
    audit: Any,
    consent: Any,
    database: Any,
    wrapper_classes: Mapping[str, type[Any]],
    authenticated: Callable[[Callable[..., Any]], Callable[..., Any]],
    broadcast: Callable[[str, dict[str, Any], int | None], None],
    target_scope: Callable[[dict[str, Any]], Any],
    preflight_for: Callable[..., Any],
) -> None:
    """Register the v2 routes on an existing Windeep Flask application."""

    cancel_events: dict[int, threading.Event] = {}
    cancel_lock = threading.Lock()
    settings_path = state / "settings.enc"

    def read_settings() -> dict[str, Any]:
        if not settings_path.exists():
            return {}
        try:
            raw = crypto.decrypt_text(settings_path.read_text(encoding="utf-8"), aad=b"windeep:settings")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def runtime_environment() -> dict[str, str]:
        env = dict(os.environ)
        settings = read_settings()
        for key, env_name in _SETTINGS_ENV.items():
            value = settings.get(key)
            if isinstance(value, str) and value.strip() and value != "configured":
                env[env_name] = value.strip()
        proxy = settings.get("proxy")
        if isinstance(proxy, str) and proxy.strip():
            env.setdefault("HTTP_PROXY", proxy.strip())
            env.setdefault("HTTPS_PROXY", proxy.strip())
        return env

    def compatible_types(cls: type[Any]) -> tuple[str, ...]:
        explicit = tuple(str(item) for item in getattr(cls, "target_types", ()) if str(item))
        if explicit:
            return explicit
        return _CATEGORY_TARGET_TYPES.get(str(getattr(cls, "category", "utilities")), _CATEGORY_TARGET_TYPES["utilities"])

    def tool_descriptor(name: str, cls: type[Any], *, target_type: str | None = None) -> dict[str, Any]:
        env = runtime_environment()
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: True, environment=env)
        missing_env = list(wrapper.missing_environment())
        builtin = builtin_integrations.supports(name)
        binary_path = wrapper.resolve_binary()
        wsl_available = bool(os.name == "nt" and shutil.which("wsl.exe"))
        ready = not missing_env and (builtin or binary_path is not None)
        types = compatible_types(cls)
        normalized_type = _target_type(target_type or "") if target_type else None
        compatible = normalized_type is None or normalized_type in types or "web" in types and normalized_type in {"domain", "url", "host"}
        if missing_env:
            blocked_reason = "Missing configuration: " + ", ".join(missing_env)
        elif not builtin and binary_path is None:
            blocked_reason = f"Executable '{cls.binary}' not found in tools/ or PATH"
            if wsl_available:
                blocked_reason += "; WSL fallback will be attempted on manual execution"
        elif not compatible:
            blocked_reason = f"Not aligned to target type '{normalized_type}'"
        else:
            blocked_reason = ""
        release_support = str(getattr(cls, "release_support", "runtime"))
        try:
            options_schema = cls.input_schema.model_json_schema()
        except Exception:
            options_schema = {"type": "object", "properties": {}}
        return {
            "name": name,
            "category": str(getattr(cls, "category", "uncategorized")),
            "description": str(getattr(cls, "description", "")),
            "adapter": "builtin" if builtin else "process",
            "ready": ready,
            "installed": bool(builtin or binary_path is not None),
            "configured": not missing_env,
            "missing_env": missing_env,
            "binary": str(binary_path) if binary_path else str(getattr(cls, "binary", name)),
            "wsl_available": wsl_available,
            "target_types": list(types),
            "compatible": compatible,
            "scan_default": bool(getattr(cls, "scan_default", True)),
            "release_support": release_support,
            "windows_certified": release_support == "bundled",
            "timeout": float(getattr(cls, "timeout", 120.0)),
            "retries": int(getattr(cls, "retries", 0)),
            "rate_limit": float(getattr(cls, "rate_limit", 0.0)),
            "options_schema": options_schema,
            "blocked_reason": blocked_reason,
        }

    def all_descriptors(target_type: str | None = None) -> list[dict[str, Any]]:
        return [tool_descriptor(name, cls, target_type=target_type) for name, cls in sorted(wrapper_classes.items())]

    def build_plan(target_row: dict[str, Any], mode: str, modules: list[str], names: list[str]) -> dict[str, Any]:
        target_type = _target_type(str(target_row.get("type") or "web"))
        descriptors = all_descriptors(target_type)
        by_name = {item["name"]: item for item in descriptors}
        selected: list[str] = []
        skipped: list[dict[str, str]] = []
        mode = mode.strip().lower() or "smart"
        requested_names = {str(item) for item in names if str(item)}
        requested_modules = {str(item) for item in modules if str(item)}

        for item in descriptors:
            name = item["name"]
            category = item["category"]
            choose = False
            require_ready = True
            if mode == "smart":
                choose = bool(item["scan_default"] and category != "utilities")
            elif mode == "full":
                choose = category != "utilities"
            elif mode in {"module", "category"}:
                choose = category in requested_modules
            elif mode in {"selected", "single"}:
                choose = name in requested_names
                require_ready = False
            elif mode == "catalog":
                choose = category != "utilities"
                require_ready = False
            else:
                raise ValueError(f"unknown scan mode: {mode}")
            if not choose:
                continue
            if not item["compatible"]:
                skipped.append({"tool": name, "reason": item["blocked_reason"] or "target type mismatch"})
                continue
            if require_ready and not item["ready"]:
                skipped.append({"tool": name, "reason": item["blocked_reason"] or "not ready"})
                continue
            selected.append(name)

        unknown = sorted(requested_names.difference(by_name))
        skipped.extend({"tool": name, "reason": "unknown integration"} for name in unknown)
        return {
            "target_id": int(target_row["id"]),
            "target": target_row["target"],
            "target_type": target_type,
            "mode": mode,
            "selected": selected,
            "selected_count": len(selected),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "catalog_count": len(descriptors),
            "ready_compatible_count": sum(1 for item in descriptors if item["ready"] and item["compatible"]),
        }

    scan_runtime = RegisteredScanRuntime()
    pipeline = V3ScanPipeline(
        database=database,
        wrapper_classes=wrapper_classes,
        tools_dir=tools_dir,
        target_scope=target_scope,
        preflight_for=preflight_for,
        runtime_environment=runtime_environment,
        broadcast=broadcast,
    )

    def worker(
        scan_id: int,
        target_row: dict[str, Any],
        plan: dict[str, Any],
        consent_id: str,
        tool_options: Mapping[str, Any],
        cancel_event: threading.Event,
    ) -> None:
        try:
            pipeline.run_sync(
                scan_id=scan_id,
                target_row=target_row,
                selected=list(plan["selected"]),
                consent_id=consent_id,
                tool_options=tool_options,
                cancel_event=cancel_event,
                mode=str(plan["mode"]),
                skipped=list(plan["skipped"]),
            )
        except asyncio.CancelledError:
            database.update_scan(scan_id, status="cancelled", finished_at=time.time())
            broadcast("progress", {"status": "cancelled", "reason": "operator cancellation"}, scan_id)
        except Exception as exc:
            database.add_scan_log(scan_id, str(exc), "error", "v3-orchestrator")
            database.update_scan(
                scan_id,
                status="failed",
                finished_at=time.time(),
                results_summary={"errors": [{"tool": "v3-orchestrator", "error": str(exc)}]},
            )
            broadcast("progress", {"status": "failed", "error": str(exc)}, scan_id)
        finally:
            with cancel_lock:
                cancel_events.pop(scan_id, None)

    @app.get("/api/v2/tools")
    @authenticated
    def v2_tools() -> Response:
        target_type = request.args.get("target_type")
        rows = all_descriptors(target_type)
        return jsonify({
            "total": len(rows),
            "ready": sum(1 for row in rows if row["ready"]),
            "configured": sum(1 for row in rows if row["configured"]),
            "windows_certified": sum(1 for row in rows if row["windows_certified"]),
            "tools": rows,
        })

    @app.get("/api/v2/scan-plan")
    @authenticated
    def v2_scan_plan() -> tuple[Response, int] | Response:
        try:
            target_id = int(request.args["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            mode = str(request.args.get("mode") or "smart")
            modules = [item for item in str(request.args.get("modules") or "").split(",") if item]
            names = [item for item in str(request.args.get("tools") or "").split(",") if item]
            return jsonify(build_plan(target_row, mode, modules, names))
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/scans")
    @authenticated
    def v2_scans_create() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            consent_id = str(data["consent_id"])
            preflight_for(target_row, consent_id, rps=float(data.get("global_rps", 5.0)))
            mode = str(data.get("mode") or "smart")
            modules = [str(item) for item in data.get("modules", [])]
            names = [str(item) for item in data.get("tools", [])]
            plan = build_plan(target_row, mode, modules, names)
            if not plan["selected"]:
                return jsonify({"error": "no runnable integrations in scan plan", "plan": plan}), 400
            tool_options = data.get("tool_options") or {}
            if not isinstance(tool_options, dict):
                raise ValueError("tool_options must be an object")
            scan_id = database.create_scan(target_id, f"v2:{mode}", plan["selected"])
            event = threading.Event()
            with cancel_lock:
                cancel_events[scan_id] = event
            scan_runtime.start(
                scan_id,
                worker,
                args=(scan_id, target_row, plan, consent_id, tool_options, event),
            )
            audit.append("v2.scan.started", {"scan_id": scan_id, "target_id": target_id, "mode": mode, "tools": len(plan["selected"])})
            return jsonify({"scan_id": scan_id, "status": "queued", "plan": plan}), 202
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/scans/<int:scan_id>/stop")
    @authenticated
    def v2_scans_stop(scan_id: int) -> tuple[Response, int]:
        with cancel_lock:
            event = cancel_events.get(scan_id)
        if event is None:
            with database._connect() as conn:
                row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return jsonify({"error": "scan not found"}), 404
            return jsonify({"scan_id": scan_id, "stop_requested": False, "status": row["status"], "message": "scan is not actively running"}), 409
        event.set()
        database.update_scan(scan_id, status="cancelling")
        audit.append("v2.scan.stop_requested", {"scan_id": scan_id})
        broadcast("progress", {"status": "cancelling", "message": "Stop requested; active process is being terminated."}, scan_id)
        return jsonify({"scan_id": scan_id, "stop_requested": True, "status": "cancelling"}), 202

    @app.post("/api/v2/reports/generate")
    @authenticated
    def v2_reports_generate() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            findings = database.list_findings(target_id=target_id, limit=5000)
            title = str(data.get("title") or f"Windeep proof report - {target_row['name']}")
            markdown = _proof_markdown(target_row, findings, title)
            encrypted = crypto.encrypt_text(markdown, aad=b"windeep:report.content")
            ids = [int(item["id"]) for item in findings]
            with database._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO reports(target_id, title, template, content, format, finding_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (target_id, title, "v2-proof", encrypted, "markdown", json.dumps(ids), time.time()),
                )
                report_id = int(cursor.lastrowid)
            audit.append("v2.report.generated", {"report_id": report_id, "target_id": target_id, "findings": len(ids)})
            return jsonify({"id": report_id, "title": title, "finding_ids": ids, "content": markdown, "format": "markdown", "encrypted_at_rest": True, "plaintext_export": True}), 201
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/reports/<int:report_id>/download")
    @authenticated
    def v2_reports_download(report_id: int) -> tuple[Response, int] | Response:
        with database._connect() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return jsonify({"error": "report not found"}), 404
        item = dict(row)
        title = str(item.get("title") or f"windeep-report-{report_id}")
        fmt = str(request.args.get("format") or "markdown").lower()
        ids_raw = item.get("finding_ids") or "[]"
        try:
            finding_ids = [int(value) for value in json.loads(str(ids_raw))]
        except Exception:
            finding_ids = []
        if fmt == "json":
            payload = {
                "report_id": report_id,
                "title": title,
                "target_id": item.get("target_id"),
                "generated_at": item.get("created_at"),
                "findings": [finding for fid in finding_ids if (finding := database.get_finding(fid)) is not None],
            }
            body = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
            response = Response(body, mimetype="application/json")
            response.headers["Content-Disposition"] = f'attachment; filename="{_safe_filename(title)}.json"'
            return response
        markdown = crypto.decrypt_text(str(item["content"]), aad=b"windeep:report.content")
        response = Response(markdown, mimetype="text/markdown")
        response.headers["Content-Disposition"] = f'attachment; filename="{_safe_filename(title)}.md"'
        return response

    @app.get("/api/v2/intelligence")
    @authenticated
    def v2_intelligence() -> tuple[Response, int] | Response:
        try:
            target_id = int(request.args["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            findings = database.list_findings(target_id=target_id, limit=5000)
            ranked = sorted(
                findings,
                key=lambda item: (_SEVERITY_WEIGHT.get(str(item.get("severity") or "info").lower(), 0), float(item.get("confidence") or 0.0)),
                reverse=True,
            )
            descriptors = all_descriptors(str(target_row.get("type") or "web"))
            with database._connect() as conn:
                rows = conn.execute("SELECT DISTINCT tool_name FROM tool_runs WHERE target_id = ?", (target_id,)).fetchall()
            already_run = {str(row["tool_name"]) for row in rows}
            recommendations = [
                {"tool": item["name"], "category": item["category"], "reason": "ready, target-compatible, and not yet run"}
                for item in descriptors
                if item["ready"] and item["compatible"] and item["scan_default"] and item["name"] not in already_run and item["category"] != "utilities"
            ][:20]
            readiness_gaps = [
                {"tool": item["name"], "category": item["category"], "reason": item["blocked_reason"]}
                for item in descriptors
                if item["compatible"] and not item["ready"]
            ][:50]
            return jsonify({
                "target_id": target_id,
                "finding_count": len(findings),
                "top_findings": [
                    {"id": item["id"], "title": item["title"], "severity": item["severity"], "confidence": item.get("confidence"), "tool": item.get("tool")}
                    for item in ranked[:12]
                ],
                "recommendations": recommendations,
                "readiness_gaps": readiness_gaps,
                "already_run_tools": sorted(already_run),
                "summary": {severity: sum(1 for item in findings if str(item.get("severity") or "info").lower() == severity) for severity in _SEVERITY_WEIGHT},
            })
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/settings")
    @authenticated
    def v2_settings_get() -> Response:
        data = read_settings()
        result: dict[str, Any] = {
            "global_rps": float(data.get("global_rps", 5.0)),
            "scan_speed": str(data.get("scan_speed") or "medium"),
            "proxy": str(data.get("proxy") or ""),
        }
        for key in _SETTINGS_ENV:
            result[key] = "configured" if data.get(key) else ""
        return jsonify(result)

    @app.put("/api/v2/settings")
    @authenticated
    def v2_settings_put() -> Response:
        incoming = request.get_json(silent=True) or {}
        current = read_settings()
        allowed = {"global_rps", "scan_speed", "proxy", *_SETTINGS_ENV.keys()}
        for key in allowed:
            if key not in incoming:
                continue
            value = incoming[key]
            if key in _SETTINGS_ENV and value in {"", None, "configured"}:
                continue
            if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                current[key] = value
        settings_path.write_text(
            crypto.encrypt_text(json.dumps(current, separators=(",", ":"), sort_keys=True), aad=b"windeep:settings"),
            encoding="utf-8",
        )
        audit.append("v2.settings.updated", {"keys": sorted(key for key in incoming if key in allowed)})
        return jsonify({"saved": True, "encrypted_at_rest": True})

    @app.get("/api/v2/status")
    @authenticated
    def v2_status() -> Response:
        descriptors = all_descriptors()
        with database._connect() as conn:
            running = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE status IN ('queued','running','cancelling')").fetchone()["count"]
            finding_count = conn.execute("SELECT COUNT(*) AS count FROM findings").fetchone()["count"]
        return jsonify({
            "catalog": len(descriptors),
            "ready": sum(1 for item in descriptors if item["ready"]),
            "configured": sum(1 for item in descriptors if item["configured"]),
            "running_scans": int(running),
            "findings": int(finding_count),
            "raw_proof_exports": True,
            "cancellable_processes": True,
            "target_aware_planning": True,
        })
