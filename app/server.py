"""Local-only Flask API bootstrap with mandatory dashboard security controls."""

from __future__ import annotations

import os
import webbrowser
from functools import wraps
from pathlib import Path
from threading import Timer
from typing import Any, Callable, TypeVar, cast

from flask import Flask, Response, jsonify, make_response, request

from app.security.audit import AuditLog
from app.security.auth import AuthenticationError, LocalAuthManager, SessionClaims, is_loopback_remote
from app.security.consent import ConsentAuthority, ConsentError
from app.security.crypto import CryptoManager
from app.security.preflight import PreFlightGuard
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer, ScopeViolation

F = TypeVar("F", bound=Callable[..., Any])


def _state_dir() -> Path:
    return Path(os.getenv("WINDEEP_STATE_DIR", "state")).resolve()


def _request_token() -> str:
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return bearer[7:].strip()
    return request.cookies.get("windeep_session", "")


def create_app() -> Flask:
    """Create the Windeep Flask app with localhost, auth, CSRF, and CSP controls."""
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        JSON_SORT_KEYS=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )

    crypto = CryptoManager(wrapped_key_path=state / "crypto" / "dek.bin")
    audit = AuditLog(state / "audit" / "audit.jsonl")
    auth = LocalAuthManager(protector=crypto.protector)
    consent = ConsentAuthority(state / "consent", protector=crypto.protector)

    app.extensions["windeep.crypto"] = crypto
    app.extensions["windeep.audit"] = audit
    app.extensions["windeep.auth"] = auth
    app.extensions["windeep.consent"] = consent

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

    @app.before_request
    def require_loopback() -> Response | tuple[Response, int] | None:
        if not is_loopback_remote(request.remote_addr):
            audit.append("dashboard.remote_blocked", {"remote_addr": request.remote_addr, "path": request.path})
            return jsonify({"error": "Windeep dashboard is local-only"}), 403
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; object-src 'none'; connect-src 'self'; "
            "img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health() -> tuple[Response, int]:
        crypto_health = crypto.healthcheck()
        audit_health = audit.healthcheck()
        auth_health = auth.healthcheck()
        ok = bool(crypto_health["ok"] and audit_health["ok"] and auth_health["ok"])
        return jsonify(
            {
                "status": "ok" if ok else "blocked",
                "service": "windeep",
                "localhost_only": True,
                "controls": {
                    "crypto": crypto_health,
                    "audit": audit_health,
                    "dashboard_auth": auth_health,
                },
            }
        ), 200 if ok else 503

    @app.post("/api/handshake")
    def handshake() -> Response:
        token, csrf, claims = auth.issue()
        audit.append("dashboard.handshake", {"sid": claims.sid, "expires_at": claims.expires_at})
        response = make_response(jsonify({"csrf_token": csrf, "expires_at": claims.expires_at, "session": "established"}))
        response.set_cookie(
            "windeep_session",
            token,
            httponly=True,
            samesite="Strict",
            secure=False,
            max_age=int(claims.expires_at - claims.issued_at),
            path="/",
        )
        return response

    @app.post("/api/consent")
    @authenticated
    def create_consent() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target = str(data["target"])
            scope = ScopeEnforcer(
                target=target,
                allow=[str(v) for v in data.get("scope", [])],
                deny=[str(v) for v in data.get("out_of_scope", [])],
            )
            record = consent.issue(
                scope,
                authorized_by=str(data["authorized_by"]),
                purpose=str(data["purpose"]),
                ttl_seconds=int(data.get("ttl_seconds", 8 * 60 * 60)),
            )
            audit.append(
                "consent.issued",
                {
                    "consent_id": record.id,
                    "authorized_by": record.authorized_by,
                    "expires_at": record.expires_at,
                    "scope_sha256": record.scope_sha256,
                },
            )
            return jsonify(
                {
                    "id": record.id,
                    "authorized_by": record.authorized_by,
                    "purpose": record.purpose,
                    "issued_at": record.issued_at,
                    "expires_at": record.expires_at,
                    "scope_sha256": record.scope_sha256,
                    "public_key": consent.public_key_b64(),
                }
            ), 201
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/preflight/check")
    @authenticated
    def preflight_check() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            target = str(data["target"])
            scope = ScopeEnforcer(
                target=target,
                allow=[str(v) for v in data.get("scope", [])],
                deny=[str(v) for v in data.get("out_of_scope", [])],
            )
            governor = RateGovernor(
                global_policy=RatePolicy(
                    rate_per_second=float(data.get("global_rps", 10.0)),
                    burst=float(data.get("global_burst", 10.0)),
                )
            )
            guard = PreFlightGuard(scope=scope, rate_governor=governor, consent=consent, crypto=crypto, audit=audit)
            record = guard.authorize_scan(target=target, consent_id=str(data["consent_id"]))
            return jsonify({"authorized": True, "consent_id": record.id, "health": guard.healthcheck()}), 200
        except (KeyError, TypeError, ValueError, ScopeViolation, ConsentError, PermissionError) as exc:
            return jsonify({"authorized": False, "error": str(exc)}), 403

    @app.get("/api/session")
    @authenticated
    def session_status() -> tuple[Response, int]:
        claims = cast(SessionClaims, request.environ["windeep.session_claims"])
        return jsonify({"authenticated": True, "issued_at": claims.issued_at, "expires_at": claims.expires_at}), 200

    @app.get("/")
    def index() -> tuple[str, int, dict[str, str]]:
        body = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Windeep</title>"
            "<style>body{background:#0a0e17;color:#e5e7eb;font-family:system-ui;max-width:760px;margin:10vh auto;padding:24px}code{color:#67e8f9}</style>"
            "</head><body><h1>Windeep</h1><p>Secure local bootstrap is running.</p>"
            "<p>Start a local API session with <code>POST /api/handshake</code>.</p></body></html>"
        )
        return body, 200, {"Content-Type": "text/html; charset=utf-8"}

    return app


def main() -> int:
    """Run Windeep bound strictly to IPv4 loopback."""
    port = int(os.getenv("WINDEEP_PORT", "7331"))
    if port < 1 or port > 65535:
        raise ValueError("WINDEEP_PORT must be between 1 and 65535")
    Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    create_app().run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
