"""Scope enforcement for authorized Windeep security testing."""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


class ScopeViolation(PermissionError):
    """Raised when a candidate target is outside the configured authorization scope."""


def _hostname(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or candidate.split("/", 1)[0]).strip("[]").rstrip(".").lower()


def _normalized_url(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    port = parsed.port
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def _ip(value: str) -> ipaddress._BaseAddress | None:  # type: ignore[attr-defined]
    host = _hostname(value)
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass(slots=True)
class ScopeEnforcer:
    """Apply explicit allow/deny rules to domains, URLs, IPs, and CIDR blocks.

    Deny rules always win. When no allow rules are supplied, only the exact
    primary target is allowed. Wildcard host rules use ``*.example.com``
    semantics and do not implicitly include the apex domain.
    """

    target: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.target = self.target.strip()
        self.allow = [rule.strip() for rule in self.allow if rule.strip()]
        self.deny = [rule.strip() for rule in self.deny if rule.strip()]
        if not self.target:
            raise ValueError("target must not be empty")

    @classmethod
    def from_iterables(
        cls,
        target: str,
        allow: Iterable[str] | None = None,
        deny: Iterable[str] | None = None,
    ) -> "ScopeEnforcer":
        """Build a scope enforcer from arbitrary iterables."""
        return cls(target=target, allow=list(allow or ()), deny=list(deny or ()))

    def is_allowed(self, candidate: str) -> bool:
        """Return ``True`` only when a candidate is explicitly authorized."""
        if not candidate or not candidate.strip():
            return False
        if any(self._matches(candidate, rule) for rule in self.deny):
            return False
        rules = self.allow or [self.target]
        return any(self._matches(candidate, rule) for rule in rules)

    def assert_allowed(self, candidate: str) -> None:
        """Raise :class:`ScopeViolation` when a candidate is unauthorized."""
        if not self.is_allowed(candidate):
            raise ScopeViolation(f"candidate is outside authorized scope: {candidate}")

    def healthcheck(self) -> dict[str, object]:
        """Return a serializable health snapshot used by pre-flight checks."""
        return {
            "ok": bool(self.target),
            "target": self.target,
            "allow_rules": len(self.allow) or 1,
            "deny_rules": len(self.deny),
        }

    def fingerprint_material(self) -> str:
        """Return deterministic scope material suitable for authorization signing."""
        allows = sorted(self.allow or [self.target], key=str.casefold)
        denies = sorted(self.deny, key=str.casefold)
        return "\n".join([f"target={self.target}", *[f"allow={v}" for v in allows], *[f"deny={v}" for v in denies]])

    @staticmethod
    def _matches(candidate: str, rule: str) -> bool:
        rule = rule.strip()
        if not rule:
            return False
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            network = None
        if network is not None:
            candidate_ip = _ip(candidate)
            return candidate_ip is not None and candidate_ip in network
        try:
            rule_ip = ipaddress.ip_address(rule.strip("[]"))
        except ValueError:
            rule_ip = None
        if rule_ip is not None:
            candidate_ip = _ip(candidate)
            return candidate_ip == rule_ip
        if "://" in rule or "/" in rule:
            candidate_url = _normalized_url(candidate)
            rule_url = _normalized_url(rule)
            if any(char in rule_url for char in "*?["):
                return fnmatch.fnmatchcase(candidate_url.casefold(), rule_url.casefold())
            return candidate_url.casefold() == rule_url.casefold() or candidate_url.casefold().startswith(rule_url.casefold().rstrip("/") + "/")
        candidate_host = _hostname(candidate)
        rule_host = _hostname(rule)
        if not candidate_host or not rule_host:
            return False
        if rule.startswith("*."):
            suffix = rule[2:].rstrip(".").lower()
            return candidate_host.endswith("." + suffix) and candidate_host != suffix
        if any(char in rule_host for char in "*?["):
            return fnmatch.fnmatchcase(candidate_host, rule_host)
        return candidate_host == rule_host
