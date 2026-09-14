"""Shared scan context and conservative scope matching for Windeep."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


def _hostname(value: str) -> str:
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or "").rstrip(".").lower()


def _normalized_url(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = f"https://{value}"
    return value.rstrip("/")


@dataclass(slots=True)
class ScanContext:
    """Mutable state passed across an authorized scan pipeline."""

    target: str
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    tech_stack: set[str] = field(default_factory=set)
    session: Any | None = None
    auth_tokens: dict[str, str] = field(default_factory=dict)
    findings_so_far: list[Any] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    proxy_config: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_in_scope(self, candidate: str) -> bool:
        """Return whether a candidate is allowed by scope and not denied.

        Out-of-scope rules always win. With no explicit scope rules, Windeep
        defaults to the exact target host rather than assuming sibling hosts or
        subdomains are authorized.
        """
        if not candidate.strip():
            return False
        if any(self._matches_rule(candidate, rule) for rule in self.out_of_scope):
            return False
        rules = self.scope or [self.target]
        return any(self._matches_rule(candidate, rule) for rule in rules)

    def require_in_scope(self, candidate: str) -> None:
        """Raise PermissionError when a candidate is outside authorized scope."""
        if not self.is_in_scope(candidate):
            raise PermissionError(f"target is outside configured scope: {candidate}")

    def redacted_snapshot(self) -> dict[str, Any]:
        """Return serializable state with authentication material removed."""
        return {
            "target": self.target,
            "scope": list(self.scope),
            "out_of_scope": list(self.out_of_scope),
            "tech_stack": sorted(self.tech_stack),
            "auth_token_names": sorted(self.auth_tokens),
            "finding_count": len(self.findings_so_far),
            "hypothesis_count": len(self.hypotheses),
            "proxy_config": {
                key: value
                for key, value in self.proxy_config.items()
                if "password" not in key.lower()
            },
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def _matches_rule(candidate: str, rule: str) -> bool:
        candidate_host = _hostname(candidate)
        rule = rule.strip()
        if not rule:
            return False

        if "://" in rule or "/" in rule:
            candidate_url = _normalized_url(candidate)
            rule_url = _normalized_url(rule)
            if any(char in rule_url for char in "*?["):
                return fnmatch.fnmatchcase(candidate_url.lower(), rule_url.lower())
            return (
                candidate_url.lower() == rule_url.lower()
                or candidate_url.lower().startswith(rule_url.lower() + "/")
            )

        rule_host = _hostname(rule)
        if not candidate_host or not rule_host:
            return False
        if rule.startswith("*."):
            suffix = rule_host[2:] if rule_host.startswith("*.") else rule[2:].lower()
            return candidate_host.endswith("." + suffix) and candidate_host != suffix
        return fnmatch.fnmatchcase(candidate_host, rule_host)
