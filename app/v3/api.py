"""Guarded v3 API surface for tester triage and all-findings reporting."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, Response, jsonify, request

from app.v3.events import V3EventPublisher
from app.v3.release_migration import apply_v3_release_migration
from app.v3.reporting import V3ReportGenerator
from app.v3.triage import ManualTriage, TriageError
from app.v4.api import register_v4_api


def register_v3_api(
    app: Flask,
    *,
    crypto: Any,
    audit: Any,
    database: Any,
    authenticated: Callable[[Callable[..., Any]], Callable[..., Any]],
    preflight_for: Callable[..., Any],
    event_publisher: V3EventPublisher,
) -> None:
    """Register v3 compatibility and v4 routes when the full app runtime exists."""
    apply_v3_release_migration(database.path)
    triage = ManualTriage(database, audit)
    reports = V3ReportGenerator(database, crypto, triage=triage)

    def scan_access(scan_id: int) -> tuple[dict[str, Any], str]:
        with database._connect() as conn:
            row = conn.execute(
                "SELECT target_id, consent_ref FROM scan_authorizations WHERE scan_id = ?",
                (int(scan_id),),
            ).fetchone()
        if row is None:
            raise PermissionError("scan authorization record is unavailable")
        target = database.get_target(int(row["target_id"]))
        if target is None:
            raise PermissionError("authorized target is unavailable")
        consent_id = crypto.decrypt_text(
            str(row["consent_ref"]),
            aad=f"windeep:scan_auth:{int(scan_id)}".encode("utf-8"),
        )
        preflight_for(target, consent_id)
        return target, consent_id

    def finding_scan(finding_id: int) -> tuple[dict[str, Any], int]:
        finding = database.get_finding(int(finding_id))
        if finding is None:
            raise KeyError(f"finding not found: {finding_id}")
        scan_id = finding.get("scan_id")
        if scan_id is None:
            raise PermissionError("finding has no authorized scan context")
        return finding, int(scan_id)

    def verification_state(finding_id: int) -> str:
        with database._connect() as conn:
            record = conn.execute(
                "SELECT id FROM verification_record WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (int(finding_id),),
            ).fetchone()
            if record is None:
                return "not-recorded"
            rows = conn.execute(
                "SELECT state FROM verification_claim WHERE record_id = ? ORDER BY id ASC",
                (int(record["id"]),),
            ).fetchall()
        order = {"verified": 0, "partially_verified": 1, "needs-review": 2}
        states = [str(row["state"]) for row in rows]
        return max(states, key=lambda value: order.get(value, 3), default="not-recorded")

    @app.get("/api/v3/status")
    @authenticated
    def v3_status() -> Response:
        return jsonify(
            {
                "version": "3.0.0-compat",
                "sse_schema": "windeep.sse.v1",
                "all_findings_reporting": True,
                "manual_triage": True,
            }
        )

    @app.get("/api/v3/findings/<int:finding_id>/triage")
    @authenticated
    def v3_triage_get(finding_id: int) -> tuple[Response, int] | Response:
        try:
            _finding, scan_id = finding_scan(finding_id)
            scan_access(scan_id)
            return jsonify(triage.get(finding_id))
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404
        except PermissionError as exc:
            audit.append("v3.api.denied", {"finding_id": finding_id, "path": request.path, "reason": str(exc)})
            return jsonify({"error": str(exc)}), 403

    @app.put("/api/v3/findings/<int:finding_id>/triage")
    @authenticated
    def v3_triage_put(finding_id: int) -> tuple[Response, int] | Response:
        body = request.get_json(silent=True) or {}
        try:
            _finding, scan_id = finding_scan(finding_id)
            scan_access(scan_id)
            result = triage.set(
                finding_id,
                severity=body.get("severity"),
                status=body.get("status"),
                title=body.get("title"),
                notes=body.get("notes"),
            )
            event_publisher.finding_updated(scan_id, finding_id, result)
            return jsonify(result)
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404
        except TriageError as exc:
            return jsonify({"error": str(exc)}), 400
        except PermissionError as exc:
            audit.append("v3.api.denied", {"finding_id": finding_id, "path": request.path, "reason": str(exc)})
            return jsonify({"error": str(exc)}), 403

    @app.get("/api/v3/findings/<int:finding_id>/verification")
    @authenticated
    def v3_verification(finding_id: int) -> tuple[Response, int] | Response:
        try:
            _finding, scan_id = finding_scan(finding_id)
            scan_access(scan_id)
            return jsonify({"finding_id": finding_id, "state": verification_state(finding_id)})
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404
        except PermissionError as exc:
            audit.append("v3.api.denied", {"finding_id": finding_id, "path": request.path, "reason": str(exc)})
            return jsonify({"error": str(exc)}), 403

    @app.get("/api/v3/scans/<int:scan_id>/report")
    @authenticated
    def v3_scan_report(scan_id: int) -> tuple[Response, int] | Response:
        try:
            scan_access(scan_id)
            artifact = reports.render_scan(scan_id)
            requested = str(request.args.get("format") or "markdown").casefold()
            audit.append(
                "v3.report.rendered",
                {"scan_id": scan_id, "sha256": artifact.sha256, "findings": len(artifact.finding_ids), "format": requested},
            )
            if requested == "markdown":
                return Response(artifact.markdown, mimetype="text/markdown")
            if requested == "html":
                return Response(artifact.html, mimetype="text/html")
            if requested == "json":
                return jsonify(
                    {
                        "scan_id": scan_id,
                        "sha256": artifact.sha256,
                        "finding_ids": list(artifact.finding_ids),
                        "markdown": artifact.markdown,
                    }
                )
            return jsonify({"error": "format must be markdown, html, or json"}), 400
        except PermissionError as exc:
            audit.append("v3.api.denied", {"scan_id": scan_id, "path": request.path, "reason": str(exc)})
            return jsonify({"error": str(exc)}), 403

    # Standalone v3 compatibility tests construct a minimal Flask app without
    # the tool-factory extension. The production server installs the extension
    # before calling this function, so v4 remains additive there without making
    # v3 registration depend on v4 bootstrapping details.
    if "windeep.tool_factory" in app.extensions:
        register_v4_api(app, authenticated=authenticated, audit=audit)


__all__ = ["register_v3_api"]