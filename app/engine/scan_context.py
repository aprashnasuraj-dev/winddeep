"""Shared scan context with authorization metadata for Windeep."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.security.scope import ScopeEnforcer


@dataclass(slots=True)
class ScanContext:
    """Mutable state passed across one explicitly authorized scan pipeline."""

    target: str
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    consent_id: str = ""
    target_id: int | None = None
    tech_stack: set[str] = field(default_factory=set)
    session: Any | None = None
    auth_tokens: dict[str, str] = field(default_factory=dict)
    findings_so_far: list[Any] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    proxy_config: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def scope_enforcer(self) -> ScopeEnforcer:
        """Build the canonical ScopeEnforcer for this scan context."""
        return ScopeEnforcer(target=self.target, allow=list(self.scope), deny=list(self.out_of_scope))

    def is_in_scope(self, candidate: str) -> bool:
        """Return whether a candidate is allowed by the canonical scope engine."""
        return self.scope_enforcer().is_allowed(candidate)

    def require_in_scope(self, candidate: str) -> None:
        """Raise when a candidate is outside authorized scope."""
        self.scope_enforcer().assert_allowed(candidate)

    def redacted_snapshot(self) -> dict[str, Any]:
        """Return serializable state with authentication material removed."""
        return {
            "target": self.target,
            "target_id": self.target_id,
            "scope": list(self.scope),
            "out_of_scope": list(self.out_of_scope),
            "consent_id": self.consent_id,
            "tech_stack": sorted(self.tech_stack),
            "auth_token_names": sorted(self.auth_tokens),
            "finding_count": len(self.findings_so_far),
            "hypothesis_count": len(self.hypotheses),
            "proxy_config": {
                key: value
                for key, value in self.proxy_config.items()
                if "password" not in key.lower() and "token" not in key.lower()
            },
            "metadata": dict(self.metadata),
        }
