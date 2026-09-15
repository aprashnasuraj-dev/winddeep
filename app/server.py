"""Local-only Windeep API and dashboard with fail-closed release guardrails."""
from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
import time
import webbrowser
from functools import wraps
from pathlib import Path
from threading import Timer
from typing import Any, Callable, TypeVar, cast

from flask import Flask, Response, jsonify, make_response, request, send_from_directory, stream_with_context

from app.engine.pipeline_store import PipelineStore
from app.engine.tool_wrapper import ToolExecutionError, ToolWrapperFactory
from app.modules.test_packs import PACK_COUNTS, TOTAL_TESTS, list_tests, run_selected
from app.tools.release_metadata import apply_release_metadata
from app.v2_api import register_v2_api
from app.security.audit import AuditLog
from app.security.auth import AuthenticationError, LocalAuthManager, SessionClaims, is_loopback_remote
from app.security.consent import ConsentAuthority, ConsentError
from app.security.crypto import CryptoManager
from app.security.preflight import PreFlightGuard
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer, ScopeViolation
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase

F = TypeVar("F", bound=Callable[..., Any])


def _state_dir() -> Path:
    return Path(os.getenv("WINDEEP_STATE_DIR", "state")).resolve()


def _resource_root() -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    return Path(bundled).resolve() if bundled else Path(__file__).resolve().parents[1]


def _request_token() -> str:
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return bearer[7:].strip()
    return request.cookies.get("windeep_session", "")


def _json_value(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def create_app() -> Flask:
    """Create the localhost-only Windeep application."""
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    root = _resource_root()
    static_dir = root / "app" / "static"
    registry_path = root / "tools_config.json"
    tools_dir = root / "tools"

    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024, JSON_SORT_KEYS=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

    crypto = CryptoManager(wrapped_key_path=state / "crypto" / "dek.bin")
    audit = AuditLog(state / "audit" / "audit.jsonl")
    auth = LocalAuthManager(protector=crypto.protector)
    consent = ConsentAuthority(state / "consent", protector=crypto.protector)
    database = SecureDatabase(state / "windeep.db", crypto=crypto)
    pipeline_store = PipelineStore(database)
    flow_database = SecureFlowDatabase(database)
    factory = ToolWrapperFactory(registry_path)
    wrapper_classes = factory.load()
    effective_tools = apply_release_metadata(wrapper_classes, registry_path)
    scan_cancel: set[int] = set()
    sse_lock = threading.Lock()
    sse_global: set[queue.Queue[str]] = set()
    sse_scans: dict[int, set[queue.Queue[str]]] = {}

    app.extensions["windeep.crypto"] = crypto
    app.extensions["windeep.audit"] = audit
    app.extensions["windeep.auth"] = auth
    app.extensions["windeep.consent"] = consent
    app.extensions["windeep.database"] = database
    app.extensions["windeep.pipeline_store"] = pipeline_store
    app.extensions["windeep.flow_database"] = flow_database
    app.extensions["windeep.tool_factory"] = factory

    def authenticated(view: F) -> F:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            token = _request_token()
            if not token:
                return jsonify({"error": "authentication required"}), 401
            try:
                claims = auth.validate(token)
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    auth.validate_csrf(claims, request.headers.get("X-CSRF-Token", ""))
            except AuthenticationError as exc:
                audit.append("dashboard.auth_failed", {"path": request.path, "reason": str(exc)})
                return jsonify({"error": str(exc)}), 401
            request.environ["windeep.session_claims"] = claims
            return view(*args, **kwargs)
        return cast(F, wrapper)

    def _sse_safe(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        safe = dict(data)
        if event_type == "finding" and isinstance(safe.get("finding"), dict):
            finding = dict(safe["finding"])
            for key in ("evidence", "request", "response", "description", "steps", "impact", "remediation"):
                finding.pop(key, None)
            safe["finding"] = finding
        for key in list(safe):
            lowered = key.casefold()
            if any(marker in lowered for marker in ("authorization", "cookie", "password", "secret", "token", "api_key")):
                safe[key] = "<redacted>"
        return safe

    def _wire_replay_event(row: dict[str, Any]) -> str:
        payload = _sse_safe(str(row["event_type"]), dict(row["payload"]))
        envelope = {
            "type": str(row["event_type"]),
            "scan_id": int(row["scan_id"]),
            "schema_version": str(row["schema_version"]),
            "seq": int(row["seq"]),
            **payload,
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True, default=str)

    def _sse_frame(payload: str) -> str:
        decoded = _json_value(payload, {})
        event_type = str(decoded.get("type") or "message")
        seq = decoded.get("seq")
        event_id = f"id: {int(seq)}\n" if isinstance(seq, int) else ""
        return f"{event_id}event: {event_type}\ndata: {payload}\n\n"

    def broadcast(event_type: str, data: dict[str, Any], scan_id: int | None = None) -> None:
        clean = dict(data)
        persisted_seq = clean.pop("_sse_seq", None)
        persisted_schema = clean.pop("_sse_schema", None)
        clean = _sse_safe(event_type, clean)
        if scan_id is not None:
            if persisted_seq is None:
                event = pipeline_store.append_scan_event(
                    scan_id, event_type, clean, schema_version=str(persisted_schema or "windeep.sse.v1")
                )
                seq = int(event["seq"])
                schema_version = str(event["schema_version"])
            else:
                seq = int(persisted_seq)
                schema_version = str(persisted_schema or "windeep.sse.v1")
            envelope = {
                "type": event_type,
                "scan_id": scan_id,
                "schema_version": schema_version,
                "seq": seq,
                **clean,
            }
        else:
            envelope = {"type": event_type, "scan_id": None, **clean}
        payload = json.dumps(envelope, separators=(",", ":"), sort_keys=True, default=str)
        with sse_lock:
            recipients = set(sse_global)
            if scan_id is not None:
                recipients.update(sse_scans.get(scan_id, set()))
        for channel in recipients:
            try:
                channel.put_nowait(payload)
            except queue.Full:
                try:
                    channel.get_nowait()
                    channel.put_nowait(payload)
                except (queue.Empty, queue.Full):
                    pass

    def subscribe(scan_id: int | None = None, *, after_seq: int = 0):
        channel: queue.Queue[str] = queue.Queue(maxsize=256)
        with sse_lock:
            if scan_id is None:
                sse_global.add(channel)
            else:
                sse_scans.setdefault(scan_id, set()).add(channel)
        last_seq = max(0, int(after_seq))
        try:
            if scan_id is not None:
                for event in pipeline_store.list_scan_events(scan_id, after_seq=last_seq):
                    payload = _wire_replay_event(event)
                    last_seq = int(event["seq"])
                    yield _sse_frame(payload)
            while True:
                try:
                    payload = channel.get(timeout=25.0)
                    decoded = _json_value(payload, {})
                    seq = decoded.get("seq")
                    if scan_id is not None and isinstance(seq, int):
                        if seq <= last_seq:
                            continue
                        if seq > last_seq + 1:
                            for event in pipeline_store.list_scan_events(scan_id, after_seq=last_seq):
                                event_seq = int(event["seq"])
                                if event_seq > seq:
                                    break
                                last_seq = event_seq
                                yield _sse_frame(_wire_replay_event(event))
                            continue
                        last_seq = seq
                    yield _sse_frame(payload)
                except queue.Empty:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            with sse_lock:
                sse_global.discard(channel)
                if scan_id is not None:
                    channels = sse_scans.get(scan_id)
                    if channels is not None:
                        channels.discard(channel)
                        if not channels:
                            sse_scans.pop(scan_id, None)

    def target_scope(target_row: dict[str, Any]) -> ScopeEnforcer:
        allow = list(target_row.get("scope") or []) or [str(target_row["target"])]
        return ScopeEnforcer(target=str(target_row["target"]), allow=allow, deny=list(target_row.get("out_of_scope") or []))

    def preflight_for(target_row: dict[str, Any], consent_id: str, *, rps: float = 5.0) -> PreFlightGuard:
        scope = target_scope(target_row)
        bounded = max(0.1, min(float(rps), 20.0))
        governor = RateGovernor(global_policy=RatePolicy(rate_per_second=bounded, burst=max(1.0, bounded)))
        guard = PreFlightGuard(scope=scope, rate_governor=governor, consent=consent, crypto=crypto, audit=audit)
        guard.authorize_scan(target=str(target_row["target"]), consent_id=consent_id)
        return guard

    def scan_row(scan_id: int) -> dict[str, Any] | None:
        with database._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["modules"] = _json_value(item.get("modules"), [])
        item["results_summary"] = _json_value(item.get("results_summary"), {})
        return item

    def scan_rows(target_id: int | None = None) -> list[dict[str, Any]]:
        with database._connect() as conn:
            rows = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 500").fetchall() if target_id is None else conn.execute("SELECT id FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 500", (target_id,)).fetchall()
        return [item for row in rows if (item := scan_row(int(row["id"]))) is not None]

    def tool_metadata() -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for name, cls in sorted(wrapper_classes.items()):
            wrapper = cls(tools_dir=tools_dir, scope_validator=lambda _value: False)
            result.append({"name": name, "category": cls.category, "description": cls.description, "adapter": getattr(cls, "adapter_kind", "process"), "installed": wrapper.validate_installed(), "configured": not bool(wrapper.missing_environment()), "required_env": sorted(set((*cls.required_env, *wrapper.missing_environment()))), "timeout": cls.timeout, "retries": cls.retries, "rate_limit": cls.rate_limit, "requires_scope": cls.requires_scope, "release_support": getattr(cls, "release_support", "unsupported"), "windows_certified": getattr(cls, "release_support", "") == "bundled"})
        return result

    def select_tools(scan_type: str, modules: list[str]) -> list[str]:
        if scan_type == "full":
            return sorted(wrapper_classes)
        requested = set(modules)
        return sorted(name for name, cls in wrapper_classes.items() if name in requested or cls.category in requested)

    async def execute_one_tool(tool_name: str, target_row: dict[str, Any], *, scan_id: int | None = None) -> list[dict[str, Any]]:
        if tool_name not in wrapper_classes:
            raise KeyError(f"unknown tool integration: {tool_name}")
        scope = target_scope(target_row)
        cls = wrapper_classes[tool_name]
        wrapper = cls(tools_dir=tools_dir, scope_validator=scope.is_allowed)
        run_id = database.create_tool_run(tool_name=tool_name, status="running", scan_id=scan_id, target_id=int(target_row["id"]), command=[tool_name, "<scope-bound target>"])
        try:
            findings = await wrapper.run(str(target_row["target"]))
            output: list[dict[str, Any]] = []
            for finding in findings:
                payload = finding.model_dump()
                finding_id, created = database.create_finding(target_id=int(target_row["id"]), scan_id=scan_id, title=str(payload["title"]), severity=str(payload.get("severity") or "info"), vuln_type=str(payload.get("vuln_type") or "tool_output"), tool=tool_name, endpoint=payload.get("endpoint"), description=str(payload.get("description") or ""), evidence=dict(payload.get("evidence") or {}), confidence=float(payload.get("confidence") or 0.5))
                payload["id"] = finding_id
                payload["created"] = created
                output.append(payload)
                if created:
                    broadcast("finding", {"finding": payload}, scan_id)
            database.finish_tool_run(run_id, status="completed", exit_code=0, stdout_tail=f"{len(output)} normalized result(s)")
            return output
        except Exception as exc:
            database.finish_tool_run(run_id, status="failed", error=str(exc))
            raise

    def scan_worker(scan_id: int, target_row: dict[str, Any], tool_names: list[str], consent_id: str) -> None:
        errors: list[dict[str, str]] = []
        total_findings = 0
        database.update_scan(scan_id, status="running", started_at=time.time(), progress=0.0)
        broadcast("log", {"level": "info", "module": "orchestrator", "message": f"Authorized scan starting with {len(tool_names)} tool(s)."}, scan_id)
        try:
            preflight_for(target_row, consent_id)
            if not tool_names:
                raise ValueError("no tool integrations matched the requested scan selection")
            for index, tool_name in enumerate(tool_names, start=1):
                if scan_id in scan_cancel:
                    database.update_scan(scan_id, status="cancelled", finished_at=time.time())
                    broadcast("progress", {"progress": round(((index - 1) / len(tool_names)) * 100, 2), "status": "cancelled"}, scan_id)
                    return
                broadcast("log", {"level": "info", "module": tool_name, "message": f"Starting {tool_name}"}, scan_id)
                try:
                    findings = asyncio.run(execute_one_tool(tool_name, target_row, scan_id=scan_id))
                    total_findings += len(findings)
                except Exception as exc:
                    errors.append({"tool": tool_name, "error": str(exc)})
                    database.add_scan_log(scan_id, str(exc), "error", tool_name)
                    broadcast("log", {"level": "error", "module": tool_name, "message": str(exc)}, scan_id)
                progress = round((index / len(tool_names)) * 100.0, 2)
                database.update_scan(scan_id, progress=progress)
                broadcast("progress", {"progress": progress, "status": "running"}, scan_id)
            summary = {"tools": len(tool_names), "findings": total_findings, "errors": errors}
            database.update_scan(scan_id, status="completed", progress=100.0, finished_at=time.time(), results_summary=summary)
            broadcast("progress", {"progress": 100.0, "status": "completed", "summary": summary}, scan_id)
        except Exception as exc:
            database.add_scan_log(scan_id, str(exc), "error", "orchestrator")
            database.update_scan(scan_id, status="failed", finished_at=time.time(), results_summary={"errors": [{"tool": "orchestrator", "error": str(exc)}]})
            broadcast("progress", {"status": "failed", "error": str(exc)}, scan_id)
        finally:
            scan_cancel.discard(scan_id)

    @app.before_request
    def require_loopback() -> Response | tuple[Response, int] | None:
        if not is_loopback_remote(request.remote_addr):
            audit.append("dashboard.remote_blocked", {"remote_addr": request.remote_addr, "path": request.path})
            return jsonify({"error": "Windeep dashboard is local-only"}), 403
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health() -> tuple[Response, int]:
        crypto_health, audit_health, auth_health = crypto.healthcheck(), audit.healthcheck(), auth.healthcheck()
        ok = bool(crypto_health["ok"] and audit_health["ok"] and auth_health["ok"])
        version = (root / "VERSION").read_text(encoding="utf-8").strip() if (root / "VERSION").exists() else "dev"
        return jsonify({"status": "ok" if ok else "blocked", "service": "windeep", "version": version, "localhost_only": True, "integrations_total": len(wrapper_classes), "windows_certified_tools": sum(1 for cls in wrapper_classes.values() if getattr(cls, "release_support", "") == "bundled"), "test_count": TOTAL_TESTS, "controls": {"crypto": crypto_health, "audit": audit_health, "dashboard_auth": auth_health, "encrypted_database": {"ok": True}}}), 200 if ok else 503

    @app.post("/api/handshake")
    def handshake() -> Response:
        token, csrf, claims = auth.issue()
        audit.append("dashboard.handshake", {"sid": claims.sid, "expires_at": claims.expires_at})
        response = make_response(jsonify({"csrf_token": csrf, "expires_at": claims.expires_at, "session": "established"}))
        response.set_cookie("windeep_session", token, httponly=True, samesite="Strict", secure=False, max_age=int(claims.expires_at - claims.issued_at), path="/")
        return response

    @app.get("/api/session")
    @authenticated
    def session_status() -> tuple[Response, int]:
        claims = cast(SessionClaims, request.environ["windeep.session_claims"])
        return jsonify({"authenticated": True, "issued_at": claims.issued_at, "expires_at": claims.expires_at}), 200

    @app.post("/api/consent")
    @authenticated
    def create_consent() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target = str(data["target"])
            scope = ScopeEnforcer(target=target, allow=[str(v) for v in data.get("scope", [])], deny=[str(v) for v in data.get("out_of_scope", [])])
            record = consent.issue(scope, authorized_by=str(data["authorized_by"]), purpose=str(data["purpose"]), ttl_seconds=int(data.get("ttl_seconds", 8 * 60 * 60)))
            audit.append("consent.issued", {"consent_id": record.id, "authorized_by": record.authorized_by, "expires_at": record.expires_at, "scope_sha256": record.scope_sha256})
            return jsonify({"id": record.id, "authorized_by": record.authorized_by, "purpose": record.purpose, "issued_at": record.issued_at, "expires_at": record.expires_at, "scope_sha256": record.scope_sha256, "public_key": consent.public_key_b64()}), 201
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/preflight/check")
    @authenticated
    def preflight_check() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target = str(data["target"])
            scope = ScopeEnforcer(target=target, allow=[str(v) for v in data.get("scope", [])], deny=[str(v) for v in data.get("out_of_scope", [])])
            governor = RateGovernor(global_policy=RatePolicy(rate_per_second=float(data.get("global_rps", 10.0)), burst=float(data.get("global_burst", 10.0))))
            guard = PreFlightGuard(scope=scope, rate_governor=governor, consent=consent, crypto=crypto, audit=audit)
            record = guard.authorize_scan(target=target, consent_id=str(data["consent_id"]))
            return jsonify({"authorized": True, "consent_id": record.id, "health": guard.healthcheck()}), 200
        except (KeyError, TypeError, ValueError, ScopeViolation, ConsentError, PermissionError) as exc:
            return jsonify({"authorized": False, "error": str(exc)}), 403

    @app.get("/api/targets")
    @authenticated
    def targets_list() -> Response:
        return jsonify(database.list_targets())

    @app.post("/api/targets")
    @authenticated
    def targets_create() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = database.create_target(str(data["name"]).strip(), str(data.get("type") or "web"), str(data["target"]).strip(), scope=[str(v) for v in data.get("scope", [])], out_of_scope=[str(v) for v in data.get("out_of_scope", [])], notes=str(data.get("notes") or ""), tags=[str(v) for v in data.get("tags", [])])
            audit.append("target.created", {"target_id": target_id})
            return jsonify(database.get_target(target_id)), 201
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/targets/<int:target_id>")
    @authenticated
    def targets_get(target_id: int) -> tuple[Response, int] | Response:
        row = database.get_target(target_id)
        return jsonify(row) if row else (jsonify({"error": "target not found"}), 404)

    @app.put("/api/targets/<int:target_id>")
    @authenticated
    def targets_update(target_id: int) -> tuple[Response, int] | Response:
        if database.get_target(target_id) is None:
            return jsonify({"error": "target not found"}), 404
        data = request.get_json(silent=True) or {}
        changes: dict[str, Any] = {key: str(value) for key, value in data.items() if key in {"name", "type", "target", "notes"}}
        for key in {"scope", "out_of_scope", "tags"}.intersection(data):
            changes[key] = json.dumps([str(v) for v in data[key]], separators=(",", ":"))
        if changes:
            changes["updated_at"] = time.time()
            columns = ", ".join(f"{key} = ?" for key in changes)
            with database._connect() as conn:
                conn.execute(f"UPDATE targets SET {columns} WHERE id = ?", (*changes.values(), target_id))
        audit.append("target.updated", {"target_id": target_id, "fields": sorted(changes)})
        return jsonify(database.get_target(target_id))

    @app.delete("/api/targets/<int:target_id>")
    @authenticated
    def targets_delete(target_id: int) -> tuple[Response, int]:
        with database._connect() as conn:
            deleted = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,)).rowcount
        audit.append("target.deleted", {"target_id": target_id, "deleted": bool(deleted)})
        return jsonify({"deleted": bool(deleted)}), 200 if deleted else 404

    @app.get("/api/scans")
    @authenticated
    def scans_list() -> Response:
        raw = request.args.get("target_id")
        return jsonify(scan_rows(int(raw)) if raw else scan_rows())

    @app.post("/api/scans")
    @authenticated
    def scans_create() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            consent_id = str(data["consent_id"])
            preflight_for(target_row, consent_id, rps=float(data.get("global_rps", 5.0)))
            scan_type = str(data.get("scan_type") or "full")
            modules = [str(v) for v in data.get("modules", [])]
            tool_names = select_tools(scan_type, modules)
            scan_id = database.create_scan(target_id, scan_type, modules or tool_names)
            threading.Thread(target=scan_worker, args=(scan_id, target_row, tool_names, consent_id), daemon=True, name=f"windeep-scan-{scan_id}").start()
            return jsonify(scan_row(scan_id)), 202
        except (KeyError, TypeError, ValueError, ScopeViolation, ConsentError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 403

    @app.get("/api/scans/<int:scan_id>")
    @authenticated
    def scans_get(scan_id: int) -> tuple[Response, int] | Response:
        row = scan_row(scan_id)
        return jsonify(row) if row else (jsonify({"error": "scan not found"}), 404)

    @app.get("/api/scans/<int:scan_id>/logs")
    @authenticated
    def scans_logs(scan_id: int) -> Response:
        limit = max(1, min(int(request.args.get("limit", 500)), 5000))
        with database._connect() as conn:
            rows = conn.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()
        return jsonify([dict(row) for row in rows])

    @app.post("/api/scans/<int:scan_id>/cancel")
    @authenticated
    def scans_cancel(scan_id: int) -> tuple[Response, int]:
        if scan_row(scan_id) is None:
            return jsonify({"error": "scan not found"}), 404
        scan_cancel.add(scan_id)
        audit.append("scan.cancel_requested", {"scan_id": scan_id})
        return jsonify({"scan_id": scan_id, "cancel_requested": True}), 202

    @app.get("/api/findings")
    @authenticated
    def findings_list() -> Response:
        raw_target = request.args.get("target_id")
        return jsonify(database.list_findings(target_id=int(raw_target) if raw_target else None, severity=request.args.get("severity"), status=request.args.get("status"), vuln_type=request.args.get("vuln_type"), limit=max(1, min(int(request.args.get("limit", 500)), 5000))))

    @app.get("/api/findings/summary")
    @authenticated
    def findings_summary() -> Response:
        raw = request.args.get("target_id")
        with database._connect() as conn:
            rows = conn.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE target_id = ? GROUP BY severity", (int(raw),)).fetchall() if raw else conn.execute("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity").fetchall()
        summary = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
        summary.update({str(row["severity"]): int(row["count"]) for row in rows})
        return jsonify(summary)

    @app.get("/api/findings/<int:finding_id>")
    @authenticated
    def findings_get(finding_id: int) -> tuple[Response, int] | Response:
        row = database.get_finding(finding_id)
        return jsonify(row) if row else (jsonify({"error": "finding not found"}), 404)

    @app.post("/api/findings")
    @authenticated
    def findings_create() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            finding_id, created = database.create_finding(target_id=int(data["target_id"]), scan_id=int(data["scan_id"]) if data.get("scan_id") is not None else None, title=str(data["title"]), severity=str(data.get("severity") or "info"), vuln_type=str(data.get("vuln_type") or "manual"), tool=str(data.get("tool") or "manual"), endpoint=data.get("endpoint"), description=str(data.get("description") or ""), evidence=dict(data.get("evidence") or {}), request=str(data.get("request") or ""), response=str(data.get("response") or ""), steps=str(data.get("steps") or ""), impact=str(data.get("impact") or ""), remediation=str(data.get("remediation") or ""), confidence=float(data.get("confidence", 0.5)))
            return jsonify({"finding": database.get_finding(finding_id), "created": created}), 201 if created else 200
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.put("/api/findings/<int:finding_id>")
    @authenticated
    def findings_update(finding_id: int) -> tuple[Response, int] | Response:
        if database.get_finding(finding_id) is None:
            return jsonify({"error": "finding not found"}), 404
        data = request.get_json(silent=True) or {}
        changes = {key: value for key, value in data.items() if key in {"status", "duplicate_of", "confidence", "severity"}}
        if changes:
            changes["updated_at"] = time.time()
            columns = ", ".join(f"{key} = ?" for key in changes)
            with database._connect() as conn:
                conn.execute(f"UPDATE findings SET {columns} WHERE id = ?", (*changes.values(), finding_id))
        return jsonify(database.get_finding(finding_id))

    @app.delete("/api/findings/<int:finding_id>")
    @authenticated
    def findings_delete(finding_id: int) -> tuple[Response, int]:
        with database._connect() as conn:
            deleted = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,)).rowcount
        return jsonify({"deleted": bool(deleted)}), 200 if deleted else 404

    def decode_report(item: dict[str, Any]) -> dict[str, Any]:
        item["content"] = crypto.decrypt_text(str(item["content"]), aad=b"windeep:report.content")
        item["finding_ids"] = _json_value(item.get("finding_ids"), [])
        return item

    @app.get("/api/reports")
    @authenticated
    def reports_list() -> Response:
        raw = request.args.get("target_id")
        with database._connect() as conn:
            rows = conn.execute("SELECT * FROM reports WHERE target_id = ? ORDER BY id DESC", (int(raw),)).fetchall() if raw else conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 200").fetchall()
        return jsonify([decode_report(dict(row)) for row in rows])

    @app.post("/api/reports/generate")
    @authenticated
    def reports_generate() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target_row = database.get_target(target_id)
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            findings = database.list_findings(target_id=target_id, limit=5000)
            lines = [f"# Windeep Report — {target_row['name']}", "", f"Target: `{target_row['target']}`", "", "## Findings", ""]
            for finding in findings:
                lines.extend([f"### [{str(finding['severity']).upper()}] {finding['title']}", f"- Type: {finding['vuln_type']}", f"- Tool: {finding['tool']}", f"- Endpoint: {finding.get('endpoint') or ''}", f"- Confidence: {finding.get('confidence', 0.5)}", "", str(finding.get("description") or ""), ""])
            encrypted = crypto.encrypt_text("\n".join(lines), aad=b"windeep:report.content")
            finding_ids = [int(item["id"]) for item in findings]
            with database._connect() as conn:
                cursor = conn.execute("INSERT INTO reports(target_id, title, template, content, format, finding_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (target_id, str(data.get("title") or f"Windeep report - {target_row['name']}"), str(data.get("template") or "generic"), encrypted, "markdown", json.dumps(finding_ids), time.time()))
                row = conn.execute("SELECT * FROM reports WHERE id = ?", (int(cursor.lastrowid),)).fetchone()
            return jsonify(decode_report(dict(row))), 201
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/tools")
    @authenticated
    def tools_list() -> Response:
        return jsonify(tool_metadata())

    @app.post("/api/tools/run")
    @authenticated
    def tools_run() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_row = database.get_target(int(data["target_id"]))
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            preflight_for(target_row, str(data["consent_id"]), rps=float(data.get("global_rps", 5.0)))
            results = asyncio.run(execute_one_tool(str(data["tool"]), target_row))
            return jsonify({"results": results, "count": len(results)}), 200
        except (KeyError, TypeError, ValueError, ScopeViolation, ConsentError, PermissionError, ToolExecutionError, FileNotFoundError) as exc:
            return jsonify({"error": str(exc)}), 400

    settings_path = state / "settings.enc"

    @app.get("/api/settings")
    @authenticated
    def settings_get() -> Response:
        if not settings_path.exists():
            return jsonify({"scan_speed": "medium", "global_rps": 5.0, "proxy": "", "secrets_stored_encrypted": True})
        data = _json_value(crypto.decrypt_text(settings_path.read_text(encoding="utf-8"), aad=b"windeep:settings"), {})
        for key in list(data):
            if any(marker in key.lower() for marker in ("key", "token", "secret", "password")):
                data[key] = "configured" if data[key] else ""
        data["secrets_stored_encrypted"] = True
        return jsonify(data)

    @app.put("/api/settings")
    @authenticated
    def settings_put() -> Response:
        data = request.get_json(silent=True) or {}
        sanitized = {key: value for key, value in data.items() if isinstance(key, str) and len(key) <= 100 and isinstance(value, (str, int, float, bool, list, dict, type(None)))}
        settings_path.write_text(crypto.encrypt_text(json.dumps(sanitized, separators=(",", ":"), sort_keys=True), aad=b"windeep:settings"), encoding="utf-8")
        audit.append("settings.updated", {"keys": sorted(sanitized)})
        return jsonify({"saved": True, "secrets_stored_encrypted": True})

    @app.get("/api/test-packs")
    @authenticated
    def test_packs_list() -> Response:
        return jsonify({"total": TOTAL_TESTS, "counts": PACK_COUNTS, "tests": list_tests()})

    @app.post("/api/test-packs/run")
    @authenticated
    def test_packs_run() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_row = database.get_target(int(data["target_id"]))
            if target_row is None:
                return jsonify({"error": "target not found"}), 404
            preflight_for(target_row, str(data["consent_id"]), rps=float(data.get("global_rps", 5.0)))
            pack = str(data["pack"])
            names = [str(value) for value in data.get("tests", [])]
            results = asyncio.run(run_selected(pack, names, {"target": target_row["target"], "observations": data.get("observations") or {}}))
            return jsonify({"pack": pack, "results": results, "network_actions": 0}), 200
        except (KeyError, TypeError, ValueError, ScopeViolation, ConsentError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/test-packs/<pack>/status")
    @authenticated
    def test_packs_status(pack: str) -> tuple[Response, int]:
        if pack not in PACK_COUNTS:
            return jsonify({"error": "unknown test pack"}), 404
        return jsonify({"pack": pack, "count": PACK_COUNTS[pack], "runner": "assessment-only", "status": "ready"}), 200

    @app.get("/api/stream/global")
    @authenticated
    def stream_global() -> Response:
        return Response(stream_with_context(subscribe()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/stream/<int:scan_id>")
    @authenticated
    def stream_scan(scan_id: int) -> Response:
        raw_last = request.headers.get("Last-Event-ID", "0").strip() or "0"
        try:
            after_seq = max(0, int(raw_last))
        except ValueError:
            after_seq = 0
        return Response(stream_with_context(subscribe(scan_id, after_seq=after_seq)), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/integrations")
    @authenticated
    def integrations() -> Response:
        return jsonify({"database": {"encrypted": True, "implementation": type(database).__name__}, "flows": {"encrypted": True, "implementation": type(flow_database).__name__}, "tools": {"active": len(wrapper_classes), "catalog": len(effective_tools), "windows_certified": sum(1 for cls in wrapper_classes.values() if getattr(cls, "release_support", "") == "bundled"), "all_scope_bound": all(cls.requires_scope for cls in wrapper_classes.values())}, "test_packs": {"count": TOTAL_TESTS, "network_actions": 0}, "browser": {"module": "app.browser.automation", "runtime": "playwright"}, "capture": {"module": "app.capture", "persistence": type(flow_database).__name__}, "brain": {"module": "app.brain", "status": "available"}})

    register_v2_api(
        app,
        root=root,
        state=state,
        tools_dir=tools_dir,
        crypto=crypto,
        audit=audit,
        consent=consent,
        database=database,
        wrapper_classes=wrapper_classes,
        authenticated=authenticated,
        broadcast=broadcast,
        target_scope=target_scope,
        preflight_for=preflight_for,
    )

    @app.get("/")
    def index() -> Response:
        return send_from_directory(static_dir, "index.html")

    @app.get("/static/<path:filename>")
    def static_files(filename: str) -> Response:
        return send_from_directory(static_dir, filename)

    return app


def main() -> int:
    """Run Windeep bound strictly to IPv4 loopback."""
    port = int(os.getenv("WINDEEP_PORT", "7331"))
    if port < 1 or port > 65535:
        raise ValueError("WINDEEP_PORT must be between 1 and 65535")
    if os.getenv("WINDEEP_NO_BROWSER", "").strip().lower() not in {"1", "true", "yes"}:
        Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    create_app().run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
