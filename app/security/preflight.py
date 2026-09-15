"""Fail-closed pre-flight guardrail layer for every Windeep scan."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from app.security.audit import AuditLog
from app.security.consent import ConsentAuthority, ConsentRecord
from app.security.crypto import CryptoManager
from app.security.rate_governor import RateGovernor
from app.security.scope import ScopeEnforcer


class PreFlightError(PermissionError):
    """Raised when a scan cannot pass mandatory guardrails."""


@dataclass(slots=True)
class PreFlightGuard:
    """Require scope, rate governance, consent, crypto, and audit health."""

    scope: ScopeEnforcer
    rate_governor: RateGovernor
    consent: ConsentAuthority
    crypto: CryptoManager
    audit: AuditLog

    def healthcheck(self) -> dict[str, Any]:
        """Return component health and a fail-closed aggregate status."""
        components = {
            "scope": self.scope.healthcheck(),
            "rate_governor": self.rate_governor.healthcheck(),
            "consent": self.consent.healthcheck(),
            "crypto": self.crypto.healthcheck(),
            "audit": self.audit.healthcheck(),
        }
        ok = all(bool(item.get("ok")) for item in components.values())
        return {"ok": ok, "components": components}

    def require_healthy(self) -> None:
        """Block the application scan path if any critical control is unhealthy."""
        state = self.healthcheck()
        if not state["ok"]:
            raise PreFlightError(f"pre-flight guardrail health check failed: {state['components']}")

    def _record_denial(self, event: str, payload: dict[str, Any]) -> None:
        """Record a denial or fail closed when the audit sink cannot accept it."""
        try:
            self.audit.append(event, payload)
        except Exception as exc:
            raise PreFlightError(f"pre-flight denial could not be audited: {exc}") from exc

    def authorize_scan(self, *, target: str, consent_id: str) -> ConsentRecord:
        """Verify all controls and authorize a target against signed live consent."""
        try:
            self.require_healthy()
            self.scope.assert_allowed(target)
            record = self.consent.verify(consent_id, self.scope)
            self.audit.append(
                "scan.authorized",
                {"target": target, "consent_id": record.id, "authorized_by": record.authorized_by, "scope_sha256": record.scope_sha256},
            )
            return record
        except Exception as exc:
            self._record_denial(
                "scan.denied",
                {
                    "target": target,
                    "consent_id": consent_id,
                    "reason": type(exc).__name__,
                    "detail": str(exc),
                },
            )
            raise

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        """Acquire governed scan capacity while propagating cancellation."""
        try:
            await self.rate_governor.acquire(key, cost=cost)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._record_denial(
                "scan.rate_denied",
                {"rate_key": key, "cost": cost, "reason": type(exc).__name__, "detail": str(exc)},
            )
            raise
