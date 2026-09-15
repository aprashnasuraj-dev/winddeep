"""Fail-closed pre-flight guardrail layer for every Windeep scan and tool action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

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
            self._record_denial("scan.denied", target=target, consent_id=consent_id, reason=str(exc))
            raise

    def authorize_tool(self, *, target: str, consent_id: str, tool_name: str) -> ConsentRecord:
        """Re-check mandatory controls immediately before a tool invocation."""
        try:
            self.require_healthy()
            self.scope.assert_allowed(target)
            record = self.consent.verify(consent_id, self.scope)
            self.audit.append(
                "tool.authorized",
                {
                    "target": target,
                    "tool": tool_name,
                    "consent_id": record.id,
                    "authorized_by": record.authorized_by,
                    "scope_sha256": record.scope_sha256,
                },
            )
            return record
        except Exception as exc:
            self._record_denial(
                "tool.denied",
                target=target,
                tool=tool_name,
                consent_id=consent_id,
                reason=str(exc),
            )
            raise

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        """Acquire governed capacity while propagating cancellation."""
        try:
            await self.rate_governor.acquire(key, cost=cost)
        except Exception as exc:
            self._record_denial("rate.denied", key=key, cost=cost, reason=str(exc))
            raise

    async def acquire_tool_and_host_rate(self, tool_name: str, target: str, *, cost: float = 1.0) -> None:
        """Acquire one global token plus tool and host keyed capacity."""
        host_key = self._host_key(target)
        try:
            await self.rate_governor.acquire_many((tool_name, host_key), cost=cost)
        except Exception as exc:
            self._record_denial(
                "rate.denied",
                key=f"{tool_name},{host_key}",
                cost=cost,
                reason=str(exc),
            )
            raise

    async def acquire_host_rate(self, target: str, *, cost: float = 1.0) -> None:
        """Backward-compatible host-only acquisition for older scheduler fakes."""
        key = self._host_key(target)
        try:
            await self.rate_governor.acquire(key, cost=cost)
        except Exception as exc:
            self._record_denial("rate.denied", key=key, cost=cost, reason=str(exc))
            raise

    @staticmethod
    def _host_key(target: str) -> str:
        parsed = urlsplit(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).strip().casefold()
        if not host:
            raise PreFlightError("cannot derive host rate key from target")
        return f"host:{host}"

    def _record_denial(self, event: str, **payload: Any) -> None:
        """Best-effort denial event without ever turning a denial into authorization."""
        try:
            self.audit.append(event, payload)
        except Exception:
            # The audit sink is itself a mandatory health dependency. If it is
            # unavailable, execution remains denied; there is no bypass path.
            pass
