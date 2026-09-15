"""Authenticated production API wiring for the Windeep desktop dashboard."""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import queue
import time
from collections.abc import Callable, Mapping
from typing import Any

from flask import Flask, Response, jsonify, request, stream_with_context

from app.brain.chain_builder import ChainBuilder
from app.brain.llm_client import LLMClient
from app.brain.memory import MemoryStore
from app.browser.automation import BrowserAutomationEngine
from app.capture.process import CaptureProcess, CaptureProcessError
from app.modules.test_packs import list_test_metadata
from app.runtime import RuntimeErrorSafe, WindeepRuntime
from app.security.consent import ConsentError
from app.security.scope import ScopeEnforcer, ScopeViolation
from app.submissions import SubmissionError


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, parsed))


def _public_blob(value: Any, *, limit: int = 65536) -> Any:
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, bytes):
        return value
    clipped = value[:limit]
    try:
        text = clipped.decode("utf-8")
        return {"encoding": "utf-8", "data": text, "truncated": len(value) > limit}
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "data": base64.b64encode(clipped).decode("ascii"),
            "truncated": len(value) > limit,
        }


def _json_safe(value: Any) -> Any:
    if isinstance(value, (bytes, memoryview)):
        return _public_blob(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def register_production_api(
    app: Flask,
    *,
    runtime: WindeepRuntime,
    capture: CaptureProcess,
    authenticated: Callable[[Callable[..., Any]], Callable[..., Any]],
) -> None:
    """Register every production dashboard route on an already secured Flask app."""

    def error_response(exc: BaseException) -> tuple[Response, int]:
        if isinstance(exc, (ScopeViolation, ConsentError, PermissionError)):
            return jsonify({"error": str(exc)}), 403
        if isinstance(exc, KeyError):
            return jsonify({"error": f"missing field: {exc.args[0]}"}), 400
        if isinstance(exc, (ValueError, TypeError, RuntimeErrorSafe, SubmissionError, CaptureProcessError)):
            return jsonify({"error": str(exc)}), 400
        runtime.audit.append("api.error", {"path": request.path, "type": type(exc).__name__, "error": str(exc)})
        return jsonify({"error": "internal operation failed; see local audit log"}), 500

    def capture_authorized() -> bool:
        token = request.headers.get("X-Windeep-Capture-Token", "")
        return bool(token) and hmac.compare_digest(token, runtime.capture_token)

    @app.get("/api/dashboard/summary")
    @authenticated
    def dashboard_summary() -> Response:
        return jsonify(runtime.summary())

    # ---- Targets ---------------------------------------------------------
    @app.get("/api/targets")
    @authenticated
    def targets_list() -> Response:
        return jsonify(runtime.database.list_targets())

    @app.post("/api/targets")
    @authenticated
    def targets_create() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target_value = str(data["target"]).strip()
            name = str(data.get("name") or target_value).strip()
            target_type = str(data.get("type") or "web").strip().lower()
            scope = [str(value) for value in data.get("scope") or []]
            out = [str(value) for value in data.get("out_of_scope") or []]
            ScopeEnforcer(target=target_value, allow=scope, deny=out)
            target_id = runtime.database.create_target(
                name,
                target_type,
                target_value,
                scope=scope,
                out_of_scope=out,
                notes=str(data.get("notes") or ""),
                tags=[str(value) for value in data.get("tags") or []],
            )
            runtime.audit.append("target.created", {"target_id": target_id, "target": target_value, "type": target_type})
            return jsonify(runtime.database.get_target(target_id)), 201
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/targets/<int:target_id>")
    @authenticated
    def targets_get(target_id: int) -> tuple[Response, int] | Response:
        item = runtime.database.get_target(target_id)
        return jsonify(item) if item is not None else (jsonify({"error": "target not found"}), 404)

    @app.put("/api/targets/<int:target_id>")
    @authenticated
    def targets_update(target_id: int) -> tuple[Response, int] | Response:
        if runtime.database.get_target(target_id) is None:
            return jsonify({"error": "target not found"}), 404
        data = request.get_json(silent=True) or {}
        allowed = {"name", "type", "target", "scope", "out_of_scope", "notes", "tags"}
        changes = {key: data[key] for key in allowed if key in data}
        if not changes:
            return jsonify(runtime.database.get_target(target_id))
        current = runtime.database.get_target(target_id) or {}
        candidate_target = str(changes.get("target", current.get("target", ""))).strip()
        candidate_scope = [str(v) for v in changes.get("scope", current.get("scope", []))]
        candidate_out = [str(v) for v in changes.get("out_of_scope", current.get("out_of_scope", []))]
        try:
            ScopeEnforcer(target=candidate_target, allow=candidate_scope, deny=candidate_out)
            db_changes: dict[str, Any] = dict(changes)
            for key in ("scope", "out_of_scope", "tags"):
                if key in db_changes:
                    db_changes[key] = json.dumps([str(v) for v in db_changes[key]], ensure_ascii=False, separators=(",", ":"))
            db_changes["updated_at"] = time.time()
            columns = ", ".join(f"{key} = ?" for key in db_changes)
            with runtime.database._connect() as conn:
                conn.execute(f"UPDATE targets SET {columns} WHERE id = ?", (*db_changes.values(), target_id))
            runtime.audit.append("target.updated", {"target_id": target_id, "fields": sorted(changes)})
            return jsonify(runtime.database.get_target(target_id))
        except Exception as exc:
            return error_response(exc)

    @app.delete("/api/targets/<int:target_id>")
    @authenticated
    def targets_delete(target_id: int) -> tuple[Response, int] | Response:
        with runtime.database._connect() as conn:
            cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        if cursor.rowcount != 1:
            return jsonify({"error": "target not found"}), 404
        runtime.audit.append("target.deleted", {"target_id": target_id})
        return jsonify({"deleted": True, "id": target_id})

    # ---- Tools and scans -------------------------------------------------
    @app.get("/api/tools")
    @authenticated
    def tools_list() -> Response:
        return jsonify(runtime.list_tools())

    @app.post("/api/tools/run")
    @authenticated
    def tool_run() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            scan_id = runtime.start_tool_scan(
                target_id=int(data["target_id"]),
                consent_id=str(data["consent_id"]),
                tool_names=[str(data["tool"])],
                scan_type="single",
                global_rps=float(data.get("global_rps", 3.0)),
            )
            return jsonify({"scan_id": scan_id, "status": "pending"}), 202
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/scans")
    @authenticated
    def scans_list() -> Response:
        target_id = request.args.get("target_id", type=int)
        return jsonify(runtime.list_scans(target_id=target_id, limit=_bounded_int(request.args.get("limit"), 200, 1, 1000)))

    @app.post("/api/scans")
    @authenticated
    def scans_start() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            tools = [str(value) for value in (data.get("tools") or data.get("modules") or [])]
            scan_id = runtime.start_tool_scan(
                target_id=int(data["target_id"]),
                consent_id=str(data["consent_id"]),
                tool_names=tools,
                scan_type=str(data.get("scan_type") or "module"),
                global_rps=float(data.get("global_rps", 5.0)),
            )
            return jsonify({"scan_id": scan_id, "status": "pending"}), 202
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/scans/<int:scan_id>")
    @authenticated
    def scans_get(scan_id: int) -> tuple[Response, int] | Response:
        item = runtime.get_scan(scan_id)
        return jsonify(item) if item is not None else (jsonify({"error": "scan not found"}), 404)

    @app.get("/api/scans/<int:scan_id>/logs")
    @authenticated
    def scans_logs(scan_id: int) -> Response:
        return jsonify(runtime.list_scan_logs(scan_id, limit=_bounded_int(request.args.get("limit"), 1000, 1, 5000)))

    @app.post("/api/scans/<int:scan_id>/cancel")
    @authenticated
    def scans_cancel(scan_id: int) -> tuple[Response, int]:
        cancelled = runtime.cancel_scan(scan_id)
        return jsonify({"scan_id": scan_id, "cancel_requested": cancelled}), 200 if cancelled else 409

    # ---- Findings --------------------------------------------------------
    @app.get("/api/findings")
    @authenticated
    def findings_list() -> Response:
        findings = runtime.database.list_findings(
            target_id=request.args.get("target_id", type=int),
            severity=request.args.get("severity") or None,
            status=request.args.get("status") or None,
            vuln_type=request.args.get("vuln_type") or None,
            limit=_bounded_int(request.args.get("limit"), 500, 1, 5000),
        )
        return jsonify(findings)

    @app.get("/api/findings/summary")
    @authenticated
    def findings_summary() -> Response:
        target_id = request.args.get("target_id", type=int)
        where = " WHERE target_id = ?" if target_id is not None else ""
        params: tuple[Any, ...] = (target_id,) if target_id is not None else ()
        with runtime.database._connect() as conn:
            rows = conn.execute(f"SELECT severity, COUNT(*) AS count FROM findings{where} GROUP BY severity", params).fetchall()
        return jsonify({str(row["severity"]): int(row["count"]) for row in rows})

    @app.get("/api/findings/<int:finding_id>")
    @authenticated
    def findings_get(finding_id: int) -> tuple[Response, int] | Response:
        item = runtime.database.get_finding(finding_id)
        return jsonify(item) if item is not None else (jsonify({"error": "finding not found"}), 404)

    @app.put("/api/findings/<int:finding_id>")
    @authenticated
    def findings_update(finding_id: int) -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        status = str(data.get("status") or "").strip()
        allowed_status = {"new", "triaged", "reported", "resolved", "duplicate", "bounty_received"}
        if status not in allowed_status:
            return jsonify({"error": "only the finding status is mutable through this endpoint"}), 400
        with runtime.database._connect() as conn:
            cursor = conn.execute("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?", (status, time.time(), finding_id))
        if cursor.rowcount != 1:
            return jsonify({"error": "finding not found"}), 404
        runtime.audit.append("finding.status_updated", {"finding_id": finding_id, "status": status})
        return jsonify(runtime.database.get_finding(finding_id))

    # ---- Live traffic ----------------------------------------------------
    @app.get("/api/flows")
    @authenticated
    def flows_list() -> tuple[Response, int] | Response:
        target_id = request.args.get("target_id", type=int)
        if target_id is None:
            return jsonify({"error": "target_id is required"}), 400
        query = str(request.args.get("q") or "")
        limit = _bounded_int(request.args.get("limit"), 250, 1, 1000)
        if query:
            rows = runtime.flows.search_flows(query, target_id=target_id, limit=limit)
        else:
            rows = runtime.flows.get_flows_by_target(target_id, limit=limit)
        return jsonify(_json_safe(rows))

    @app.get("/api/flows/<int:flow_id>")
    @authenticated
    def flows_get(flow_id: int) -> tuple[Response, int] | Response:
        item = runtime.flows.get_flow_by_id(flow_id)
        return jsonify(_json_safe(item)) if item is not None else (jsonify({"error": "flow not found"}), 404)

    @app.get("/api/flows/<int:flow_id>/export")
    @authenticated
    def flows_export(flow_id: int) -> tuple[Response, int] | Response:
        export_format = str(request.args.get("format") or "raw").lower()
        try:
            content = runtime.flows.export_flow(flow_id, export_format)  # type: ignore[arg-type]
            mimetype = "application/json" if export_format == "har" else "text/plain"
            return Response(content, mimetype=mimetype)
        except (KeyError, ValueError) as exc:
            return error_response(exc)

    # ---- Test packs ------------------------------------------------------
    @app.get("/api/test-packs")
    @authenticated
    def test_packs_list() -> Response:
        tests = list_test_metadata()
        counts: dict[str, int] = {}
        for item in tests:
            counts[item["pack"]] = counts.get(item["pack"], 0) + 1
        return jsonify({"count": len(tests), "packs": counts, "tests": tests})

    @app.post("/api/test-packs/run")
    @authenticated
    def test_packs_run() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            results = runtime.run_test_packs(
                target_id=int(data["target_id"]),
                consent_id=str(data["consent_id"]),
                packs=[str(v) for v in data.get("packs") or []] or None,
                test_ids=[str(v) for v in data.get("test_ids") or []] or None,
                authenticated=bool(data.get("authenticated", False)),
                account_count=int(data.get("account_count") or 0),
                mobile_artifact=bool(data.get("mobile_artifact", False)),
                signals=[str(v) for v in data.get("signals") or []],
            )
            return jsonify({"count": len(results), "results": results})
        except Exception as exc:
            return error_response(exc)

    # ---- Brain / chains / memory ----------------------------------------
    @app.get("/api/brain/hypotheses")
    @authenticated
    def brain_hypotheses_list() -> Response:
        return jsonify(runtime.database.list_hypotheses(
            target_id=request.args.get("target_id", type=int),
            min_confidence=float(request.args.get("min_confidence") or 0.0),
            limit=_bounded_int(request.args.get("limit"), 500, 1, 5000),
        ))

    @app.post("/api/brain/hypotheses")
    @authenticated
    def brain_hypotheses_generate() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            results = runtime.generate_brain_hypotheses(target_id=int(data["target_id"]), consent_id=str(data["consent_id"]))
            return jsonify({"count": len(results), "hypotheses": results})
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/chains")
    @authenticated
    def chains_list() -> Response:
        target_id = request.args.get("target_id", type=int)
        with runtime.database._connect() as conn:
            if target_id is None:
                rows = conn.execute("SELECT * FROM chains ORDER BY weight DESC, id DESC LIMIT 1000").fetchall()
            else:
                rows = conn.execute("SELECT * FROM chains WHERE target_id = ? ORDER BY weight DESC, id DESC LIMIT 1000", (target_id,)).fetchall()
        return jsonify([dict(row) for row in rows])

    @app.post("/api/chains/rebuild")
    @authenticated
    def chains_rebuild() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target = runtime.database.get_target(target_id)
            if target is None:
                return jsonify({"error": "target not found"}), 404
            runtime.guard_for_target(target, str(data["consent_id"]), global_rps=1.0, global_burst=1.0)
            findings = runtime.database.list_findings(target_id=target_id, limit=5000)
            builder = ChainBuilder(LLMClient([]), runtime.event_bus, database=runtime.database)
            future = asyncio.run_coroutine_threadsafe(builder.build(findings, target_id=target_id), runtime._loop)
            edges = future.result(timeout=120)
            return jsonify({"count": len(edges), "edges": [edge.model_dump() for edge in edges]})
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/memory")
    @authenticated
    def memory_search() -> tuple[Response, int] | Response:
        query_text = str(request.args.get("q") or "").strip()
        if not query_text:
            return jsonify({"items": [], "count": 0})
        store = MemoryStore(runtime.state_dir / "memory.lancedb", database=runtime.database)
        try:
            items = asyncio.run(store.find_similar(query_text, limit=_bounded_int(request.args.get("limit"), 10, 1, 100)))
            return jsonify({"count": len(items), "items": items})
        except Exception as exc:
            return error_response(exc)

    @app.post("/api/memory/findings/<int:finding_id>")
    @authenticated
    def memory_embed(finding_id: int) -> tuple[Response, int] | Response:
        finding = runtime.database.get_finding(finding_id)
        if finding is None:
            return jsonify({"error": "finding not found"}), 404
        store = MemoryStore(runtime.state_dir / "memory.lancedb", database=runtime.database)
        try:
            memory_id = asyncio.run(store.embed_finding(finding, target_id=int(finding["target_id"]), finding_id=finding_id))
            return jsonify({"memory_id": memory_id}), 201
        except Exception as exc:
            return error_response(exc)

    # ---- Browser fidelity ------------------------------------------------
    @app.post("/api/browser/marker-check")
    @authenticated
    def browser_marker_check() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data["target_id"])
            target = runtime.database.get_target(target_id)
            if target is None:
                return jsonify({"error": "target not found"}), 404
            guard = runtime.guard_for_target(target, str(data["consent_id"]), global_rps=float(data.get("global_rps", 2.0)), global_burst=2.0)
            url = str(data.get("url") or target["target"])
            guard.scope.assert_allowed(url)
            marker = str(data.get("marker") or f"WINDEEP-{int(time.time())}")[:128]
            parameter = str(data["parameter"]).strip()
            if not parameter:
                raise ValueError("parameter is required")
            if not capture.is_running():
                capture.start()

            async def run_check() -> dict[str, object]:
                engine = BrowserAutomationEngine(scope=guard.scope, rate_governor=guard.rate_governor, audit=runtime.audit, proxy_url=f"http://{capture.host}:{capture.port}", headless=True)
                try:
                    return await engine.reflected_marker_check(url, parameter=parameter, marker=marker)
                finally:
                    await engine.close()

            return jsonify(asyncio.run(run_check()))
        except Exception as exc:
            return error_response(exc)

    # ---- Reports ---------------------------------------------------------
    @app.get("/api/reports")
    @authenticated
    def reports_list() -> Response:
        return jsonify(runtime.list_reports(request.args.get("target_id", type=int)))

    @app.post("/api/reports/generate")
    @authenticated
    def reports_generate() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            report = runtime.generate_report(int(data["target_id"]), title=str(data.get("title") or "Windeep Audit Report"), template=str(data.get("template") or "generic"))
            return jsonify(report), 201
        except Exception as exc:
            return error_response(exc)

    # ---- Submission tracking -------------------------------------------
    @app.get("/api/submissions")
    @authenticated
    def submissions_list() -> Response:
        return jsonify(runtime.submissions.list(
            status=request.args.get("status") or None,
            target_id=request.args.get("target_id", type=int),
            platform=request.args.get("platform") or None,
            limit=_bounded_int(request.args.get("limit"), 500, 1, 5000),
        ))

    @app.post("/api/submissions")
    @authenticated
    def submissions_create() -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            submission_id = runtime.submissions.create(
                platform=str(data["platform"]),
                program_name=str(data["program_name"]),
                finding_id=int(data["finding_id"]) if data.get("finding_id") is not None else None,
                target_id=int(data["target_id"]) if data.get("target_id") is not None else None,
                external_id=str(data["external_id"]) if data.get("external_id") else None,
                external_url=str(data["external_url"]) if data.get("external_url") else None,
                notes=str(data.get("notes") or ""),
            )
            return jsonify(runtime.submissions.get(submission_id)), 201
        except Exception as exc:
            return error_response(exc)

    @app.post("/api/submissions/<int:submission_id>/transition")
    @authenticated
    def submissions_transition(submission_id: int) -> tuple[Response, int] | Response:
        data = request.get_json(silent=True) or {}
        try:
            item = runtime.submissions.transition(
                submission_id,
                str(data["status"]),
                external_id=str(data["external_id"]) if data.get("external_id") is not None else None,
                external_url=str(data["external_url"]) if data.get("external_url") is not None else None,
                notes=str(data["notes"]) if data.get("notes") is not None else None,
                bounty_amount=float(data["bounty_amount"]) if data.get("bounty_amount") is not None else None,
                bounty_currency=str(data["bounty_currency"]) if data.get("bounty_currency") is not None else None,
            )
            return jsonify(item)
        except Exception as exc:
            return error_response(exc)

    @app.get("/api/submissions/earnings")
    @authenticated
    def submissions_earnings() -> Response:
        summary = runtime.submissions.earnings()
        return jsonify({"by_currency": summary.by_currency, "paid_count": summary.paid_count})

    @app.get("/api/submissions/kanban")
    @authenticated
    def submissions_kanban() -> Response:
        return jsonify(runtime.submissions.kanban())

    # ---- Capture process -------------------------------------------------
    @app.get("/api/capture/status")
    @authenticated
    def capture_status() -> Response:
        return jsonify(capture.status())

    @app.post("/api/capture/start")
    @authenticated
    def capture_start() -> tuple[Response, int] | Response:
        try:
            capture.start()
            runtime.audit.append("capture.started", capture.status())
            return jsonify(capture.status())
        except Exception as exc:
            return error_response(exc)

    @app.post("/api/capture/stop")
    @authenticated
    def capture_stop() -> Response:
        capture.stop()
        runtime.audit.append("capture.stopped", {"port": capture.port})
        return jsonify(capture.status())

    @app.post("/api/capture/resolve")
    def capture_resolve() -> tuple[Response, int] | Response:
        if not capture_authorized():
            return jsonify({"error": "capture authentication failed"}), 401
        data = request.get_json(silent=True) or {}
        target_id, scan_id = runtime.resolve_capture_target(str(data.get("url") or ""))
        return jsonify({"target_id": target_id, "scan_id": scan_id})

    @app.post("/api/capture/events")
    def capture_events() -> tuple[Response, int] | Response:
        if not capture_authorized():
            return jsonify({"error": "capture authentication failed"}), 401
        data = request.get_json(silent=True) or {}
        try:
            runtime.ingest_capture_event(str(data["topic"]), data.get("payload") or {})
            return jsonify({"accepted": True})
        except Exception as exc:
            return error_response(exc)

    # ---- SSE -------------------------------------------------------------
    @app.get("/api/stream/global")
    @authenticated
    def global_stream() -> Response:
        subscriber = runtime.subscribe_events()

        @stream_with_context
        def generate():
            try:
                yield ": windeep-event-stream\n\n"
                while True:
                    try:
                        event = subscriber.get(timeout=25.0)
                        yield "data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n\n"
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            finally:
                runtime.unsubscribe_events(subscriber)

        return Response(generate(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/stream/<int:scan_id>")
    @authenticated
    def scan_stream(scan_id: int) -> Response:
        subscriber = runtime.subscribe_events()

        @stream_with_context
        def generate():
            try:
                yield ": windeep-scan-stream\n\n"
                while True:
                    try:
                        event = subscriber.get(timeout=25.0)
                        payload = event.get("payload") or {}
                        if str(payload.get("scan_id")) == str(scan_id):
                            yield "data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n\n"
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            finally:
                runtime.unsubscribe_events(subscriber)

        return Response(generate(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/settings")
    @authenticated
    def settings_get() -> Response:
        return jsonify({
            "localhost_only": True,
            "capture": capture.status(),
            "state_dir": str(runtime.state_dir),
            "tool_count": len(runtime.wrapper_classes),
            "test_count": len(list_test_metadata()),
            "max_scan_rps": 25,
            "encryption_at_rest": True,
            "signed_consent_required": True,
        })
