"""Windeep v2 product API with a guardrail-first DAG scan runtime."""
from __future__ import annotations

import asyncio
import io
import json
import os
import re
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Mapping

from flask import Flask, Response, jsonify, request, stream_with_context

from app.migrations import MigrationManager
from app.v2_pipeline import AssetObservationStore, ScanEventLog, SchedulerRuntimeRegistry, canonical_bytes, run_p0_scan


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
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "openai_api_key": "OPENAI_API_KEY",
}

# Non-secret brain settings stored as plain values (returned verbatim, not masked).
_SETTINGS_PLAIN = ("brain_llm_provider", "brain_llm_model")

_SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_TERMINAL_SCAN_STATUSES = {"completed", "completed_with_errors", "cancelled", "failed"}


def _target_type(value: str) -> str:
    return _TARGET_ALIASES.get(str(value or "").strip().lower(), str(value or "web").strip().lower() or "web")


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:80] or "windeep-report"


def _proof_markdown(target: Mapping[str, Any], findings: list[dict[str, Any]], title: str) -> str:
    """Legacy v2 proof renderer retained until the P3 evidence renderer lands."""
    lines = [
        f"# {title}",
        "",
        f"Target: `{target.get('target', '')}`",
        f"Target type: `{target.get('type', '')}`",
        f"Generated: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
        "",
        "> Windeep encrypts stored evidence at rest. This export requires the same live preflight authorization as a scan.",
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


def _poc_markdown(target: Mapping[str, Any], finding: Mapping[str, Any]) -> str:
    """Render one readable proof-of-concept file for a single finding."""
    severity = str(finding.get("severity") or "info").upper()
    endpoint = str(finding.get("endpoint") or target.get("target") or "")
    steps = str(finding.get("steps") or "").strip() or (
        f"1. Use `{finding.get('tool', 'the recorded tool')}` against the authorized target `{endpoint}`.\n"
        "2. Keep the same scope and authentication context used by the recorded scan.\n"
        "3. Compare the output with the raw evidence below."
    )
    lines = [
        f"# [{severity}] {finding.get('title', 'Finding')}",
        "",
        f"- Finding ID: `{finding.get('id', '')}`",
        f"- Tool: `{finding.get('tool', '')}`",
        f"- Type: `{finding.get('vuln_type', '')}`",
        f"- Endpoint: `{endpoint}`",
        f"- Confidence: `{finding.get('confidence', 0.5)}`",
        f"- CVSS: `{finding.get('cvss_score') if finding.get('cvss_score') is not None else 'not scored'}`",
        "",
        "## Description",
        "",
        str(finding.get("description") or "No description recorded."),
        "",
        "## Proof of concept / reproduction",
        "",
        steps,
        "",
        "## Raw evidence",
        "",
        "```json",
        json.dumps(finding.get("evidence") or {}, indent=2, ensure_ascii=False, default=str),
        "```",
        "",
    ]
    raw_request = str(finding.get("request") or "").strip()
    raw_response = str(finding.get("response") or "").strip()
    if raw_request:
        lines.extend(["## Raw request", "", "```http", raw_request, "```", ""])
    if raw_response:
        lines.extend(["## Raw response", "", "```http", raw_response, "```", ""])
    impact = str(finding.get("impact") or "").strip()
    remediation = str(finding.get("remediation") or "").strip()
    if impact:
        lines.extend(["## Impact", "", impact, ""])
    if remediation:
        lines.extend(["## Remediation", "", remediation, ""])
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
    """Register v2 routes and the P0 scheduler-owned scan runtime."""
    del consent  # authorization remains encapsulated by preflight_for

    MigrationManager(database.path, root / "app" / "data" / "migrations").apply()
    runtime = SchedulerRuntimeRegistry()
    event_log = ScanEventLog(database, crypto)
    asset_observations = AssetObservationStore(database)
    event_log.ensure_schema()
    asset_observations.ensure_schema()
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

    def tool_descriptor(name: str, cls: type[Any], *, target_type: str | None = None, active_probe: bool = False) -> dict[str, Any]:
        env = runtime_environment()
        wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: True, environment=env)
        missing_env = list(wrapper.missing_environment())
        runtime_state = wrapper.runtime_status(active_probe=active_probe)
        runtime_tier = str(runtime_state.get("tier") or "unavailable")
        backend = runtime_state.get("backend")
        binary_path = wrapper.resolve_binary()
        runtime_verified = bool(runtime_state.get("verified", True))
        runtime_deferred = bool(runtime_state.get("deferred", False))
        ready = not missing_env and runtime_tier != "unavailable" and runtime_verified
        types = compatible_types(cls)
        normalized_type = _target_type(target_type or "") if target_type else None
        compatible = normalized_type is None or normalized_type in types or ("web" in types and normalized_type in {"domain", "url", "host"})
        if missing_env:
            blocked_reason = "Missing configuration: " + ", ".join(missing_env)
        elif runtime_deferred:
            blocked_reason = "External runtime route detected; readiness check is deferred until scan planning or an explicit probe"
        elif runtime_tier == "unavailable":
            blocked_reason = "No execution backend is currently runnable; use winddeep doctor --heal or enable Docker/WSL/remote worker"
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
            "adapter": str(backend or getattr(cls, "runtime_strategy", "auto")),
            "ready": ready,
            "installed": bool(binary_path is not None),
            "resolved": runtime_tier != "unavailable",
            "runtime_verified": runtime_verified,
            "runtime_deferred": runtime_deferred,
            "configured": not missing_env,
            "missing_env": missing_env,
            "binary": str(binary_path) if binary_path else str(getattr(cls, "binary", name)),
            "runtime_tier": runtime_tier,
            "backend": backend,
            "runtime_strategy": str(runtime_state.get("runtime_strategy") or getattr(cls, "runtime_strategy", "auto")),
            "execution_chain": list(runtime_state.get("chain") or []),
            "execution_name": str(getattr(cls, "execution_name", name)),
            "alias_to": str(getattr(cls, "alias_to", "") or "") or None,
            "requires_host": str(getattr(cls, "requires_host", "") or "") or None,
            "has_provision_recipe": bool(getattr(cls, "provision", None)),
            "container_image": str(getattr(cls, "container_image", "") or "") or None,
            "builtin_fallback": str(getattr(cls, "builtin_fallback", "") or "") or None,
            "target_types": list(types),
            "compatible": compatible,
            "scan_default": bool(getattr(cls, "scan_default", True)),
            "result_role": str(getattr(cls, "result_role", "finding")),
            "release_support": release_support,
            "windows_certified": release_support == "bundled",
            "timeout": float(getattr(cls, "timeout", 120.0)),
            "retries": int(getattr(cls, "retries", 0)),
            "rate_limit": float(getattr(cls, "rate_limit", 0.0)),
            "options_schema": options_schema,
            "blocked_reason": blocked_reason,
        }

    def all_descriptors(target_type: str | None = None, *, active_probe: bool = False) -> list[dict[str, Any]]:
        return [tool_descriptor(name, cls, target_type=target_type, active_probe=active_probe) for name, cls in sorted(wrapper_classes.items())]

    def build_plan(target_row: dict[str, Any], mode: str, modules: list[str], names: list[str]) -> dict[str, Any]:
        normalized_target_type = _target_type(str(target_row.get("type") or "web"))
        # Discover the whole catalog passively. Active WSL/container probes can
        # be slow, so run them only for candidates this plan could actually use.
        descriptors = all_descriptors(normalized_target_type)
        by_name = {item["name"]: item for item in descriptors}
        selected: list[str] = []
        skipped: list[dict[str, str]] = []
        normalized_mode = mode.strip().lower() or "smart"
        requested_names = {str(item) for item in names if str(item)}
        requested_modules = {str(item) for item in modules if str(item)}
        for index, item in enumerate(descriptors):
            name = item["name"]
            category = item["category"]
            choose = False
            if normalized_mode == "smart":
                choose = bool(item["scan_default"] and category != "utilities")
            elif normalized_mode == "full":
                choose = category != "utilities"
            elif normalized_mode in {"module", "category"}:
                choose = category in requested_modules
            elif normalized_mode in {"selected", "single"}:
                choose = name in requested_names
            elif normalized_mode == "catalog":
                choose = category != "utilities"
            else:
                raise ValueError(f"unknown scan mode: {normalized_mode}")
            if not choose:
                continue
            if item["result_role"] == "diagnostic" and normalized_mode not in {"selected", "single"}:
                skipped.append({"tool": name, "reason": "diagnostic-only command; select explicitly to inspect its output"})
                continue
            if not item["compatible"]:
                skipped.append({"tool": name, "reason": item["blocked_reason"] or "target type mismatch"})
                continue
            if not item["configured"]:
                skipped.append({"tool": name, "reason": item["blocked_reason"] or "not configured"})
                continue
            # Revalidate every selected candidate before scheduling. Passive
            # availability of other catalog entries never authorizes execution.
            item = tool_descriptor(name, wrapper_classes[name], target_type=normalized_target_type, active_probe=True)
            descriptors[index] = item
            if not item["ready"]:
                skipped.append({"tool": name, "reason": item["blocked_reason"] or "not ready"})
                continue
            selected.append(name)
        unknown = sorted(requested_names.difference(by_name))
        skipped.extend({"tool": name, "reason": "unknown integration"} for name in unknown)
        return {
            "target_id": int(target_row["id"]),
            "target": target_row["target"],
            "target_type": normalized_target_type,
            "mode": normalized_mode,
            "selected": selected,
            "selected_count": len(selected),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "catalog_count": len(descriptors),
            "ready_compatible_count": sum(1 for item in descriptors if item["ready"] and item["compatible"]),
            "ready_compatible_count_is_lower_bound": any(
                item["compatible"] and item["runtime_deferred"] for item in descriptors
            ),
        }

    def save_scan_authorization(scan_id: int, target_id: int, consent_id: str) -> None:
        encrypted = crypto.encrypt_text(consent_id, aad=f"windeep:scan_auth:{scan_id}".encode("utf-8"))
        with database._connect() as conn:
            conn.execute(
                "INSERT INTO scan_authorizations(scan_id, target_id, consent_ref, created_at) VALUES (?, ?, ?, ?)",
                (scan_id, target_id, encrypted, time.time()),
            )

    def load_scan_authorization(scan_id: int) -> tuple[dict[str, Any], str]:
        with database._connect() as conn:
            row = conn.execute("SELECT target_id, consent_ref FROM scan_authorizations WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            raise PermissionError("scan authorization record is unavailable")
        target_row = database.get_target(int(row["target_id"]))
        if target_row is None:
            raise PermissionError("authorized target is unavailable")
        consent_id = crypto.decrypt_text(str(row["consent_ref"]), aad=f"windeep:scan_auth:{scan_id}".encode("utf-8"))
        return target_row, consent_id

    def latest_target_authorization(target_id: int) -> tuple[dict[str, Any], str]:
        with database._connect() as conn:
            row = conn.execute("SELECT scan_id FROM scan_authorizations WHERE target_id = ? ORDER BY scan_id DESC LIMIT 1", (target_id,)).fetchone()
        if row is None:
            raise PermissionError("no authorized scan exists for this target")
        return load_scan_authorization(int(row["scan_id"]))

    def require_target_access(target_id: int) -> dict[str, Any]:
        target_row, consent_id = latest_target_authorization(target_id)
        preflight_for(target_row, consent_id)
        return target_row

    @app.get("/api/v2/tools")
    @authenticated
    def v2_tools() -> Response:
        target_type = request.args.get("target_type")
        rows = all_descriptors(target_type)
        tiers: dict[str, int] = {}
        for row in rows:
            tier = str(row["runtime_tier"])
            tiers[tier] = tiers.get(tier, 0) + 1
        return jsonify({
            "total": len(rows),
            "ready": sum(1 for row in rows if row["ready"]),
            "configured": sum(1 for row in rows if row["configured"]),
            "resolved": sum(1 for row in rows if row["resolved"]),
            "unavailable": sum(1 for row in rows if row["runtime_tier"] == "unavailable"),
            "tiers": tiers,
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
            global_rps = float(data.get("global_rps", 5.0))
            preflight_for(target_row, consent_id, rps=global_rps)
            mode = str(data.get("mode") or "smart")
            modules = [str(item) for item in data.get("modules", [])]
            names = [str(item) for item in data.get("tools", [])]
            plan = build_plan(target_row, mode, modules, names)
            if not plan["selected"]:
                return jsonify({"error": "no runnable integrations in scan plan", "plan": plan}), 400
            tool_options = data.get("tool_options") or {}
            if not isinstance(tool_options, dict):
                raise ValueError("tool_options must be an object")
            scan_id = database.create_scan(target_id, f"v2:{plan['mode']}", plan["selected"])
            database.update_scan(scan_id, status="queued", progress=0.0)
            save_scan_authorization(scan_id, target_id, consent_id)
            environment = runtime_environment()

            async def run(cancel_event: Any) -> None:
                await run_p0_scan(
                    scan_id=scan_id,
                    target_row=target_row,
                    selected=plan["selected"],
                    skipped=plan["skipped"],
                    mode=plan["mode"],
                    consent_id=consent_id,
                    tool_options=tool_options,
                    cancel_event=cancel_event,
                    database=database,
                    crypto=crypto,
                    audit=audit,
                    wrapper_classes=wrapper_classes,
                    tools_dir=tools_dir,
                    target_scope=target_scope,
                    preflight_for=lambda row, cid: preflight_for(row, cid, rps=global_rps),
                    broadcast=broadcast,
                    environment=environment,
                )

            runtime.start(scan_id, run)
            audit.append("v2.scan.started", {"scan_id": scan_id, "target_id": target_id, "mode": plan["mode"], "tools": len(plan["selected"])})
            return jsonify({"scan_id": scan_id, "status": "queued", "plan": plan, "events": f"/api/v2/scans/{scan_id}/events"}), 202
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v2/scans/<int:scan_id>/stop")
    @authenticated
    def v2_scans_stop(scan_id: int) -> tuple[Response, int]:
        try:
            target_row, consent_id = load_scan_authorization(scan_id)
            preflight_for(target_row, consent_id)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        if not runtime.stop(scan_id):
            with database._connect() as conn:
                row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return jsonify({"error": "scan not found"}), 404
            return jsonify({"scan_id": scan_id, "stop_requested": False, "status": row["status"], "message": "scan is not actively running"}), 409
        database.update_scan(scan_id, status="cancelling")
        audit.append("v2.scan.stop_requested", {"scan_id": scan_id})
        event = event_log.append(scan_id, "progress", {"status": "cancelling", "message": "Stop requested; active task is draining within its timeout."})
        broadcast("progress", dict(event["data"]), scan_id)
        return jsonify({"scan_id": scan_id, "stop_requested": True, "status": "cancelling"}), 202

    @app.get("/api/v2/scans/<int:scan_id>/events")
    @authenticated
    def v2_scan_events(scan_id: int) -> tuple[Response, int] | Response:
        try:
            target_row, consent_id = load_scan_authorization(scan_id)
            preflight_for(target_row, consent_id)
            raw_last = request.headers.get("Last-Event-ID", "0").strip() or "0"
            last_seq = int(raw_last)
            if last_seq < 0:
                raise ValueError("Last-Event-ID must be non-negative")
        except (PermissionError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 403

        @stream_with_context
        def stream():
            cursor = last_seq
            while True:
                events = event_log.list_after(scan_id, cursor)
                for event in events:
                    cursor = int(event["seq"])
                    body = canonical_bytes(event).decode("utf-8")
                    yield f"id: {cursor}\nevent: {event['type']}\ndata: {body}\n\n"
                with database._connect() as conn:
                    row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if row is None or (str(row["status"]) in _TERMINAL_SCAN_STATUSES and not events):
                    return
                time.sleep(0.10)

        response = Response(stream(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
        return response

    @app.get("/api/v2/scans/<int:scan_id>/observations")
    @authenticated
    def v2_scan_observations(scan_id: int) -> tuple[Response, int] | Response:
        try:
            target_row, consent_id = load_scan_authorization(scan_id)
            preflight_for(target_row, consent_id)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        with database._connect() as conn:
            row = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return jsonify({"error": "scan not found"}), 404
        items = asset_observations.list_scan(scan_id)
        by_tool: dict[str, int] = {}
        historical = 0
        for item in items:
            tool = str(item.get("tool") or "unknown")
            by_tool[tool] = by_tool.get(tool, 0) + 1
            if item.get("temporal_scope") == "historical":
                historical += 1
        return jsonify(
            {
                "scan_id": scan_id,
                "count": len(items),
                "historical": historical,
                "current_or_unspecified": len(items) - historical,
                "submission_candidates": 0,
                "by_tool": dict(sorted(by_tool.items())),
                "observations": items,
            }
        )

    @app.post("/api/v2/reports/generate")
    @authenticated
    def v2_reports_generate() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target_row = require_target_access(target_id)
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
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/v2/reports/<int:report_id>/download")
    @authenticated
    def v2_reports_download(report_id: int) -> tuple[Response, int] | Response:
        # Read authorization metadata first. The evidence-bearing report row is
        # not fetched until the target has passed live preflight.
        with database._connect() as conn:
            auth_row = conn.execute("SELECT target_id FROM reports WHERE id = ?", (report_id,)).fetchone()
        if auth_row is None:
            return jsonify({"error": "report not found"}), 404
        try:
            require_target_access(int(auth_row["target_id"]))
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        with database._connect() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return jsonify({"error": "report not found"}), 404
        item = dict(row)
        title = str(item.get("title") or f"windeep-report-{report_id}")
        fmt = str(request.args.get("format") or "markdown").lower()
        try:
            finding_ids = [int(value) for value in json.loads(str(item.get("finding_ids") or "[]"))]
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
            response = Response(json.dumps(payload, indent=2, ensure_ascii=False, default=str), mimetype="application/json")
            response.headers["Content-Disposition"] = f'attachment; filename="{_safe_filename(title)}.json"'
            return response
        markdown = crypto.decrypt_text(str(item["content"]), aad=b"windeep:report.content")
        response = Response(markdown, mimetype="text/markdown")
        response.headers["Content-Disposition"] = f'attachment; filename="{_safe_filename(title)}.md"'
        return response

    @app.get("/api/v2/reports/<int:report_id>/evidence")
    @authenticated
    def v2_reports_evidence(report_id: int) -> tuple[Response, int] | Response:
        """Export a readable, self-contained evidence / PoC bundle as a .zip.

        The bundle contains the human-readable report, machine-readable findings,
        and one Markdown PoC file per finding (steps, raw request/response, and
        captured evidence). Authorization is re-checked via live preflight before
        any evidence-bearing content is read.
        """
        with database._connect() as conn:
            auth_row = conn.execute("SELECT target_id FROM reports WHERE id = ?", (report_id,)).fetchone()
        if auth_row is None:
            return jsonify({"error": "report not found"}), 404
        # Match the report-download route: do not load proof unless the target's
        # most recent recorded scan authorization passes live preflight.
        try:
            target_row = require_target_access(int(auth_row["target_id"]))
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        with database._connect() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return jsonify({"error": "report not found"}), 404
        item = dict(row)
        title = str(item.get("title") or f"windeep-report-{report_id}")
        try:
            finding_ids = [int(value) for value in json.loads(str(item.get("finding_ids") or "[]"))]
        except Exception:
            finding_ids = []
        findings = [finding for fid in finding_ids if (finding := database.get_finding(fid)) is not None]
        try:
            report_markdown = crypto.decrypt_text(str(item["content"]), aad=b"windeep:report.content")
        except Exception:
            report_markdown = "# Report\n\n(Stored report content could not be decrypted.)\n"

        generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        readme = "\n".join([
            f"# Windeep evidence bundle — {title}",
            "",
            f"- Report ID: {report_id}",
            f"- Target: {target_row.get('target', '')}",
            f"- Findings: {len(findings)}",
            f"- Exported: {generated}",
            "",
            "## Authorization",
            "",
            "This bundle contains evidence from authorized security testing only. Handle,",
            "store, and share it in line with the target program's rules and your NDA.",
            "",
            "## Contents",
            "",
            "- `report.md` — full human-readable report (all findings).",
            "- `findings.json` — machine-readable findings for import/automation.",
            "- `poc/` — one Markdown proof-of-concept per finding (reproduction steps,",
            "  raw request/response, and captured evidence).",
            "",
        ])

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.md", readme)
            archive.writestr("report.md", report_markdown)
            archive.writestr("findings.json", json.dumps(findings, indent=2, ensure_ascii=False, default=str))
            for finding in findings:
                fid = finding.get("id")
                slug = _safe_filename(str(finding.get("title") or f"finding-{fid}"))[:60] or f"finding-{fid}"
                poc = _poc_markdown(target_row, finding)
                archive.writestr(f"poc/{fid}-{slug}.md", poc)

        buffer.seek(0)
        audit.append("v2.report.evidence_exported", {"report_id": report_id, "findings": len(findings)})
        response = Response(buffer.getvalue(), mimetype="application/zip")
        response.headers["Content-Disposition"] = f'attachment; filename="{_safe_filename(title)}-evidence.zip"'
        return response

    @app.get("/api/v2/audit")
    @authenticated
    def v2_audit() -> tuple[Response, int] | Response:
        """Human-like audit: evidence-grounded hypotheses, chains, and self-critique.

        Uses the configured brain LLM when an API key is present (Settings or
        environment); otherwise the deterministic rule-based reasoner is used, so
        this endpoint always returns useful output.
        """
        from app.brain.finding_ranker import FindingRanker
        from app.brain.hypothesis_engine import HypothesisEngine
        from app.brain.runtime_config import brain_reasoner_name, build_llm_client
        from app.brain.self_critic import SelfCritic
        from app.engine.event_bus import EventBus
        from app.engine.scan_context import ScanContext

        try:
            target_id = int(request.args["target_id"])
            # Reasons over findings that are already readable via /api/findings
            # (authenticated local session), so no separate scan authorization
            # is required to view the human-like audit.
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            findings = database.list_findings(target_id=target_id, limit=5000)
            settings = read_settings()
            context = ScanContext(
                target=str(target_row.get("target") or ""),
                scope=[str(x) for x in (target_row.get("scope") or [])] or [str(target_row.get("target") or "")],
                out_of_scope=[str(x) for x in (target_row.get("out_of_scope") or [])],
                target_id=target_id,
            )

            async def _run() -> dict[str, Any]:
                event_bus = EventBus()
                llm = build_llm_client(settings)
                engine = HypothesisEngine(llm, event_bus, database=None)
                hypotheses = await engine.generate(findings, context)
                hypothesis_rows = [item.model_dump() for item in hypotheses]
                critic = SelfCritic(llm, event_bus=event_bus)
                critique: list[dict[str, Any]] = []
                for finding in sorted(findings, key=lambda f: _SEVERITY_WEIGHT.get(str(f.get("severity") or "info").lower(), 0), reverse=True)[:8]:
                    result = await critic.evaluate(finding, context)
                    critique.append({
                        "finding_id": finding.get("id"),
                        "finding_title": finding.get("title"),
                        "verdict": result.decision,
                        "rationale": "; ".join(result.reasons) or ("Evidence supports this finding." if result.decision == "PASS" else ""),
                        "missing_evidence": result.missing_evidence,
                    })
                return {"hypotheses": hypothesis_rows, "critique": critique}

            result = asyncio.run(_run())
            # Derive simple attack chains from shared hypothesis chain hints.
            chains: list[dict[str, Any]] = []
            grouped: dict[str, list[str]] = {}
            for hyp in result["hypotheses"]:
                for hint in hyp.get("chain_hints") or []:
                    grouped.setdefault(str(hint), []).append(hyp.get("test_class") or hyp.get("id") or "step")
            for hint, steps in sorted(grouped.items()):
                if len(steps) >= 1:
                    chains.append({"title": f"Chain: {hint}", "narrative": " → ".join(dict.fromkeys(steps))})

            ranked = FindingRanker().rank(findings)
            audit.append("v2.audit.run", {"target_id": target_id, "findings": len(findings), "hypotheses": len(result["hypotheses"])})
            return jsonify({
                "target_id": target_id,
                "reasoner": brain_reasoner_name(settings),
                "finding_count": len(findings),
                "hypotheses": result["hypotheses"],
                "chains": chains,
                "critique": result["critique"],
                "ranked_top": [
                    {"finding_id": int(item.finding.get("id") or item.finding.get("finding_id") or 0), "score": round(item.score, 3)}
                    for item in ranked[:10]
                ],
            })
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # brain is best-effort; never 500 the workspace
            audit.append("v2.audit.error", {"error": str(exc)})
            return jsonify({"error": f"audit unavailable: {exc}", "reasoner": "rule-based", "hypotheses": [], "chains": [], "critique": []}), 200

    @app.get("/api/v2/intelligence")
    @authenticated
    def v2_intelligence() -> tuple[Response, int] | Response:
        try:
            target_id = int(request.args["target_id"])
            target_row = require_target_access(target_id)
            findings = database.list_findings(target_id=target_id, limit=5000)
            ranked = sorted(
                findings,
                key=lambda item: (_SEVERITY_WEIGHT.get(str(item.get("severity") or "info").lower(), 0), float(item.get("confidence") or 0.0), -int(item.get("id") or 0)),
                reverse=True,
            )
            descriptors = all_descriptors(str(target_row.get("type") or "web"))
            with database._connect() as conn:
                rows = conn.execute("SELECT DISTINCT tool_name FROM tool_runs WHERE target_id = ?", (target_id,)).fetchall()
            already_run = {str(row["tool_name"]) for row in rows}
            recommendations = [
                {"tool": item["name"], "category": item["category"], "reason": f"{item['runtime_tier']}, target-compatible, and not yet run"}
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
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
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
        for key in _SETTINGS_PLAIN:
            result[key] = str(data.get(key) or "")
        return jsonify(result)

    @app.put("/api/v2/settings")
    @authenticated
    def v2_settings_put() -> Response:
        incoming = request.get_json(silent=True) or {}
        current = read_settings()
        allowed = {"global_rps", "scan_speed", "proxy", *_SETTINGS_ENV.keys(), *_SETTINGS_PLAIN}
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
        tiers: dict[str, int] = {}
        for item in descriptors:
            tier = str(item["runtime_tier"])
            tiers[tier] = tiers.get(tier, 0) + 1
        with database._connect() as conn:
            running = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE status IN ('queued','running','cancelling')").fetchone()["count"]
            finding_count = conn.execute("SELECT COUNT(*) AS count FROM findings").fetchone()["count"]
        return jsonify({
            "catalog": len(descriptors),
            "registered": len(descriptors),
            "ready": sum(1 for item in descriptors if item["ready"]),
            "resolved": sum(1 for item in descriptors if item["resolved"]),
            "unavailable": sum(1 for item in descriptors if item["runtime_tier"] == "unavailable"),
            "configured": sum(1 for item in descriptors if item["configured"]),
            "tiers": tiers,
            "running_scans": int(running),
            "findings": int(finding_count),
            "raw_proof_exports": True,
            "cancellable_processes": True,
            "target_aware_planning": True,
            "dag_scheduler": True,
            "replayable_sse": True,
            "resolver_native_readiness": True,
        })
