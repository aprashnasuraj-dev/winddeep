"""Session and token lifecycle analysis for authorized Windeep testing."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class SessionToken:
    """One user-supplied session/token observation without retaining the raw secret."""

    account: str
    token: str
    issued_at: float | None = None
    authenticated_at: float | None = None
    expires_at: float | None = None
    rotated_from: str | None = None
    cookie_flags: Mapping[str, bool | str] | None = None

    @property
    def fingerprint(self) -> str:
        """Return a non-reversible token fingerprint for cross-observation comparison."""
        return hashlib.sha256(self.token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionIssue:
    """One normalized session-management issue."""

    code: str
    title: str
    severity: str
    evidence: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class SessionAnalysis:
    """Session inventory summary and lifecycle observations."""

    token_count: int
    unique_fingerprints: int
    accounts: tuple[str, ...]
    issues: tuple[SessionIssue, ...]


def analyze_sessions(tokens: Sequence[SessionToken], *, now: float | None = None) -> SessionAnalysis:
    """Analyze supplied tokens for reuse, fixation, rotation, expiry and cookie hardening."""
    current = float(now if now is not None else time.time())
    issues: list[SessionIssue] = []
    fingerprints: dict[str, list[SessionToken]] = {}
    for item in tokens:
        if not item.account.strip():
            raise ValueError("session account label must not be empty")
        if not item.token:
            raise ValueError("session token must not be empty")
        fingerprints.setdefault(item.fingerprint, []).append(item)
        if item.expires_at is None:
            issues.append(SessionIssue("session.expiry.missing", "Session has no observed expiry", "low", f"account={item.account}", "Use bounded server-side or token expiry and enforce it consistently."))
        elif item.expires_at <= current:
            issues.append(SessionIssue("session.expired.present", "Expired session token remains in the test inventory", "info", f"account={item.account}; expires_at={item.expires_at}", "Confirm expired tokens are rejected at protected endpoints."))
        if item.issued_at is not None and item.expires_at is not None:
            lifetime = item.expires_at - item.issued_at
            if lifetime > 30 * 24 * 60 * 60:
                issues.append(SessionIssue("session.lifetime.long", "Session lifetime exceeds 30 days", "medium", f"account={item.account}; lifetime_seconds={lifetime}", "Use risk-appropriate shorter sessions and reauthentication for sensitive actions."))
            if lifetime < 0:
                issues.append(SessionIssue("session.lifetime.invalid", "Session expires before it is issued", "high", f"account={item.account}", "Reject temporally inconsistent session records."))
        flags = {str(key).casefold(): value for key, value in dict(item.cookie_flags or {}).items()}
        if flags:
            if not bool(flags.get("secure")):
                issues.append(SessionIssue("cookie.secure.missing", "Session cookie is missing Secure", "high", f"account={item.account}", "Set Secure on authentication cookies."))
            if not bool(flags.get("httponly")):
                issues.append(SessionIssue("cookie.httponly.missing", "Session cookie is missing HttpOnly", "medium", f"account={item.account}", "Set HttpOnly unless client-side script access is explicitly required."))
            same_site = str(flags.get("samesite") or "").casefold()
            if same_site not in {"lax", "strict", "none"}:
                issues.append(SessionIssue("cookie.samesite.missing", "Session cookie has no recognized SameSite value", "medium", f"account={item.account}; samesite={same_site or 'missing'}", "Set an explicit SameSite policy appropriate for the application flow."))
            if same_site == "none" and not bool(flags.get("secure")):
                issues.append(SessionIssue("cookie.samesite_none_insecure", "SameSite=None cookie is not Secure", "high", f"account={item.account}", "Pair SameSite=None with Secure."))

    for fingerprint, observations in fingerprints.items():
        accounts = sorted({item.account for item in observations})
        if len(accounts) > 1:
            issues.append(SessionIssue("session.cross_account_reuse", "Identical session token observed for multiple accounts", "critical", f"fingerprint={fingerprint[:16]}; accounts={','.join(accounts)}", "Issue unique session identifiers per authenticated principal and investigate fixation/reuse."))
        if len(observations) > 1:
            sorted_obs = sorted(observations, key=lambda item: item.authenticated_at or item.issued_at or 0.0)
            if len({item.account for item in observations}) == 1:
                login_times = [item.authenticated_at for item in sorted_obs if item.authenticated_at is not None]
                if len(login_times) >= 2:
                    issues.append(SessionIssue("session.rotation.possible_failure", "Same session token observed across multiple authentication events", "medium", f"fingerprint={fingerprint[:16]}; account={sorted_obs[0].account}", "Rotate the session identifier on authentication and privilege changes."))

    token_by_fp = {item.fingerprint: item for item in tokens}
    for item in tokens:
        if item.rotated_from:
            prior_fp = hashlib.sha256(item.rotated_from.encode("utf-8")).hexdigest()
            if prior_fp == item.fingerprint:
                issues.append(SessionIssue("session.rotation.no_change", "Session rotation retained the same token", "high", f"account={item.account}; fingerprint={item.fingerprint[:16]}", "Generate a new session identifier after authentication/privilege transitions."))
            elif prior_fp not in token_by_fp:
                issues.append(SessionIssue("session.rotation.unobserved_parent", "Rotated session references an unobserved prior token", "info", f"account={item.account}", "Capture pre/post authentication sessions together when validating rotation."))

    return SessionAnalysis(
        token_count=len(tokens),
        unique_fingerprints=len(fingerprints),
        accounts=tuple(sorted({item.account for item in tokens})),
        issues=tuple(issues),
    )
