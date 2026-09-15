"""Local dashboard authentication and CSRF protection for Windeep."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from app.security.crypto import SecretProtector, default_secret_protector


class AuthenticationError(PermissionError):
    """Raised when a local dashboard session cannot be authenticated."""


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """Authenticated local-dashboard session claims."""

    sid: str
    issued_at: float
    expires_at: float


class LocalAuthManager:
    """Issue opaque DPAPI-protected session tokens with CSRF binding."""

    def __init__(self, *, protector: SecretProtector | None = None, ttl_seconds: int = 12 * 60 * 60) -> None:
        if ttl_seconds < 300:
            raise ValueError("ttl_seconds must be >= 300")
        self.protector = protector or default_secret_protector()
        self.ttl_seconds = ttl_seconds
        self._csrf_key = os.urandom(32)

    @staticmethod
    def _b64e(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _b64d(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))

    def issue(self) -> tuple[str, str, SessionClaims]:
        """Issue a protected session token plus its CSRF token."""
        now = time.time()
        claims = SessionClaims(sid=self._b64e(os.urandom(24)), issued_at=now, expires_at=now + self.ttl_seconds)
        payload = json.dumps({"sid": claims.sid, "iat": claims.issued_at, "exp": claims.expires_at}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = self._b64e(self.protector.protect(payload))
        return token, self.csrf_for(claims), claims

    def validate(self, token: str) -> SessionClaims:
        """Validate and decode a protected session token."""
        try:
            payload = self.protector.unprotect(self._b64d(token))
            data: dict[str, Any] = json.loads(payload.decode("utf-8"))
            claims = SessionClaims(sid=str(data["sid"]), issued_at=float(data["iat"]), expires_at=float(data["exp"]))
        except Exception as exc:
            raise AuthenticationError("invalid dashboard session") from exc
        now = time.time()
        if claims.issued_at > now + 300:
            raise AuthenticationError("dashboard session was issued in the future")
        if claims.expires_at <= now:
            raise AuthenticationError("dashboard session expired")
        return claims

    def csrf_for(self, claims: SessionClaims) -> str:
        """Derive the CSRF token bound to a session id and expiration."""
        message = f"{claims.sid}:{claims.expires_at:.6f}".encode("utf-8")
        return self._b64e(hmac.new(self._csrf_key, message, hashlib.sha256).digest())

    def validate_csrf(self, claims: SessionClaims, token: str) -> None:
        """Raise if the supplied CSRF token is missing or mismatched."""
        expected = self.csrf_for(claims)
        if not token or not hmac.compare_digest(expected, token):
            raise AuthenticationError("invalid CSRF token")

    def healthcheck(self) -> dict[str, object]:
        """Verify a complete issue/validate round-trip."""
        token, csrf, claims = self.issue()
        verified = self.validate(token)
        self.validate_csrf(verified, csrf)
        return {"ok": verified.sid == claims.sid, "provider": type(self.protector).__name__}


def is_loopback_remote(remote_addr: str | None) -> bool:
    """Return whether a Flask request remote address is loopback."""
    return remote_addr in {"127.0.0.1", "::1", "localhost"}
