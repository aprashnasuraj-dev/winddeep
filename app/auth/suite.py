"""Fifty-technique authentication assurance suite with guarded replay execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.auth.protocols import JWTAnalysis, OAuthAnalysis, SAMLAnalysis
from app.auth.session_analysis import SessionAnalysis
from app.capture.replay_client import ReplayClient, ReplayPlan
from app.engine.scan_context import ScanContext
from app.security.preflight import PreFlightGuard


@dataclass(frozen=True, slots=True)
class AuthTechnique:
    """Metadata for one concrete authentication-security validation technique."""

    id: str
    category: str
    name: str
    severity_hint: str
    execution: str
    description: str
    issue_codes: tuple[str, ...] = ()
    requires_two_accounts: bool = False
    requires_replay: bool = False


@dataclass(frozen=True, slots=True)
class AuthTestResult:
    """Normalized technique result."""

    technique_id: str
    status: str
    severity: str
    summary: str
    evidence: dict[str, Any]


def _t(id_: str, category: str, name: str, severity: str, execution: str, description: str, *codes: str, two: bool = False, replay: bool = False) -> AuthTechnique:
    return AuthTechnique(id_, category, name, severity, execution, description, tuple(codes), two, replay)


AUTH_TECHNIQUES: tuple[AuthTechnique, ...] = (
    _t("JWT-01", "jwt", "Unsigned algorithm rejection", "critical", "offline", "Detect tokens declaring alg=none and require rejection.", "jwt.alg.none"),
    _t("JWT-02", "jwt", "Algorithm allowlist enforcement", "high", "offline", "Require an explicit accepted signing algorithm.", "jwt.alg.missing"),
    _t("JWT-03", "jwt", "Symmetric signing secret hygiene", "medium", "offline", "Identify HMAC-signed JWTs that require strong shared-secret controls.", "jwt.alg.symmetric"),
    _t("JWT-04", "jwt", "kid trust boundary", "high", "offline", "Detect path/URL-like key identifiers.", "jwt.kid.untrusted"),
    _t("JWT-05", "jwt", "jku trust boundary", "high", "offline", "Detect token-controlled JWK URLs requiring strict allowlisting.", "jwt.jku.scheme", "jwt.jku.trust"),
    _t("JWT-06", "jwt", "x5u trust boundary", "high", "offline", "Detect token-controlled certificate URLs requiring strict allowlisting.", "jwt.x5u.scheme", "jwt.x5u.trust"),
    _t("JWT-07", "jwt", "Expiration enforcement", "medium", "offline", "Check presence and temporal consistency of exp.", "jwt.exp.missing", "jwt.exp.expired"),
    _t("JWT-08", "jwt", "Issued/not-before validation", "medium", "offline", "Check iat and nbf sanity.", "jwt.iat.missing", "jwt.iat.future", "jwt.nbf.future"),
    _t("JWT-09", "jwt", "Issuer binding", "high", "offline", "Require and validate the expected issuer.", "jwt.iss.missing", "jwt.iss.mismatch"),
    _t("JWT-10", "jwt", "Audience binding", "high", "offline", "Require and validate the intended audience.", "jwt.aud.missing", "jwt.aud.mismatch"),
    _t("JWT-11", "jwt", "Access-token lifetime", "medium", "offline", "Detect invalid or unusually long access-token lifetimes.", "jwt.lifetime.negative", "jwt.lifetime.long"),
    _t("JWT-12", "jwt", "Expired-token replay rejection", "high", "replay", "Replay an operator-supplied expired token against a captured protected request.", replay=True),

    _t("OAUTH-01", "oauth", "state binding", "high", "offline", "Require CSRF state on authorization requests.", "oauth.state.missing"),
    _t("OAUTH-02", "oauth", "OIDC nonce binding", "high", "offline", "Require nonce in OpenID Connect requests.", "oidc.nonce.missing"),
    _t("OAUTH-03", "oauth", "PKCE presence", "medium", "offline", "Require PKCE on authorization-code requests.", "oauth.pkce.missing"),
    _t("OAUTH-04", "oauth", "PKCE S256", "medium", "offline", "Require S256 rather than plain/unspecified PKCE.", "oauth.pkce.weak_method"),
    _t("OAUTH-05", "oauth", "Front-channel token response", "medium", "offline", "Flag implicit/hybrid front-channel token delivery.", "oauth.implicit"),
    _t("OAUTH-06", "oauth", "Redirect URI transport", "high", "offline", "Detect insecure non-loopback HTTP redirect URIs.", "oauth.redirect.http"),
    _t("OAUTH-07", "oauth", "Redirect URI exactness", "medium", "offline", "Detect fragment-bearing redirect configuration requiring exact registration.", "oauth.redirect.fragment"),
    _t("OAUTH-08", "oauth", "Authorization-code single use", "high", "replay", "Verify a user-supplied already-consumed authorization artifact is rejected.", replay=True),
    _t("OAUTH-09", "oauth", "Refresh-token rotation", "high", "replay", "Verify a user-supplied rotated refresh/session token no longer authorizes protected access.", replay=True),
    _t("OAUTH-10", "oauth", "Cross-client token rejection", "high", "replay", "Verify a token issued for another client/account is not accepted at this protected resource.", two=True, replay=True),

    _t("SAML-01", "saml", "Response/assertion signature", "critical", "offline", "Require a validated XML signature on consumed SAML data.", "saml.signature.missing"),
    _t("SAML-02", "saml", "Signed assertion consumption", "high", "offline", "Ensure the application consumes the exact signed assertion.", "saml.assertion.unsigned"),
    _t("SAML-03", "saml", "Audience restriction", "high", "offline", "Require and validate SAML AudienceRestriction.", "saml.audience.missing", "saml.audience.mismatch"),
    _t("SAML-04", "saml", "Recipient binding", "high", "offline", "Require SubjectConfirmationData Recipient to match the ACS.", "saml.recipient.missing", "saml.recipient.mismatch"),
    _t("SAML-05", "saml", "Request/response binding", "medium", "offline", "Bind SP-initiated responses to one-time request IDs.", "saml.inresponseto.missing"),
    _t("SAML-06", "saml", "Assertion replay rejection", "high", "replay", "Verify a previously accepted operator-supplied assertion/session is rejected when replay is prohibited.", replay=True),
    _t("SAML-07", "saml", "Cross-account assertion rejection", "critical", "replay", "Compare equivalent requests with assertions from two supplied accounts.", two=True, replay=True),
    _t("SAML-08", "saml", "Post-logout assertion/session rejection", "high", "replay", "Verify a session/assertion captured before logout no longer authorizes protected access.", replay=True),

    _t("SESSION-01", "session", "Cross-account session reuse", "critical", "offline", "Detect identical session identifiers across distinct accounts.", "session.cross_account_reuse", two=True),
    _t("SESSION-02", "session", "Login session rotation", "high", "offline", "Detect identical identifiers across multiple authentication events.", "session.rotation.possible_failure", "session.rotation.no_change"),
    _t("SESSION-03", "session", "Privilege-change rotation", "high", "replay", "Compare pre/post privilege-change sessions supplied by the operator.", replay=True),
    _t("SESSION-04", "session", "Logout invalidation", "high", "replay", "Verify a pre-logout token no longer accesses a captured protected resource.", replay=True),
    _t("SESSION-05", "session", "Session expiration", "medium", "offline", "Check observed session expiry and lifetime.", "session.expiry.missing", "session.expired.present", "session.lifetime.long", "session.lifetime.invalid"),
    _t("SESSION-06", "session", "Secure cookie flag", "high", "offline", "Require Secure on authentication cookies.", "cookie.secure.missing"),
    _t("SESSION-07", "session", "HttpOnly cookie flag", "medium", "offline", "Require HttpOnly unless script access is explicitly necessary.", "cookie.httponly.missing"),
    _t("SESSION-08", "session", "SameSite policy", "medium", "offline", "Require an explicit and internally consistent SameSite policy.", "cookie.samesite.missing", "cookie.samesite_none_insecure"),
    _t("SESSION-09", "session", "Anonymous access control", "critical", "replay", "Remove authentication from a captured protected safe-method request and compare the response.", replay=True),
    _t("SESSION-10", "session", "Horizontal token isolation", "critical", "replay", "Replay a captured protected request using a second operator-owned account token.", two=True, replay=True),

    _t("MFA-01", "mfa_reset", "OTP single-use", "high", "workflow", "Verify a successfully consumed OTP cannot be reused within the authorized test workflow."),
    _t("MFA-02", "mfa_reset", "OTP expiry", "high", "workflow", "Verify an operator-supplied expired OTP is rejected without brute force."),
    _t("MFA-03", "mfa_reset", "OTP attempt throttling", "high", "workflow", "Verify documented/observed attempt throttling using a low bounded request budget."),
    _t("MFA-04", "mfa_reset", "MFA state enforcement", "critical", "workflow", "Verify protected application state is not issued before MFA completion."),
    _t("MFA-05", "mfa_reset", "MFA recovery-code single use", "high", "workflow", "Verify an operator-owned consumed recovery code cannot be reused."),
    _t("MFA-06", "mfa_reset", "Password-reset token expiry", "high", "workflow", "Verify an operator-supplied expired reset token is rejected."),
    _t("MFA-07", "mfa_reset", "Password-reset token single use", "critical", "workflow", "Verify a consumed reset token cannot be replayed."),
    _t("MFA-08", "mfa_reset", "Reset invalidates active sessions", "high", "replay", "Verify a pre-reset session token supplied by the operator is invalidated when policy requires it.", replay=True),
    _t("MFA-09", "mfa_reset", "Reset account binding", "critical", "workflow", "Verify a reset artifact cannot change another operator-owned test account.", two=True),
    _t("MFA-10", "mfa_reset", "Enumeration response parity", "medium", "workflow", "Compare bounded reset/login responses for owned test identities and a designated non-existent test identity."),
)

if len(AUTH_TECHNIQUES) != 50 or len({item.id for item in AUTH_TECHNIQUES}) != 50:
    raise RuntimeError("AUTH_TECHNIQUES must contain exactly 50 unique techniques")


class AuthBypassSuite:
    """Correlate offline protocol evidence and execute bounded guarded replays."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, preflight: PreFlightGuard, replay_client: ReplayClient) -> None:
        self.preflight = preflight
        self.replay_client = replay_client

    @staticmethod
    def offline_results(
        *,
        jwt: JWTAnalysis | None = None,
        oauth: OAuthAnalysis | None = None,
        saml: SAMLAnalysis | None = None,
        sessions: SessionAnalysis | None = None,
    ) -> list[AuthTestResult]:
        """Map analyzer issue codes onto the 50-technique registry."""
        issue_map: dict[str, Any] = {}
        for analysis in (jwt, oauth, saml, sessions):
            if analysis is None:
                continue
            for issue in analysis.issues:
                issue_map[issue.code] = issue
        results: list[AuthTestResult] = []
        for technique in AUTH_TECHNIQUES:
            if technique.execution != "offline":
                continue
            matched = [issue_map[code] for code in technique.issue_codes if code in issue_map]
            if matched:
                severity = max((str(item.severity) for item in matched), key=_severity_rank)
                results.append(AuthTestResult(technique.id, "finding", severity, technique.name, {"issues": [item.code for item in matched], "evidence": [item.evidence for item in matched]}))
            else:
                results.append(AuthTestResult(technique.id, "pass", "info", technique.name, {"issue_codes_checked": list(technique.issue_codes)}))
        return results

    async def replay_variant(
        self,
        *,
        technique_id: str,
        context: ScanContext,
        flow_id: int,
        token: str | None = None,
        remove_authorization: bool = False,
        headers: Mapping[str, str] | None = None,
        allow_state_change: bool = False,
    ) -> AuthTestResult:
        """Replay one operator-specified auth variant after consent/scope/rate checks.

        By default only GET/HEAD/OPTIONS flows can execute. This avoids accidental
        state changes while still enabling high-value authorization validation.
        """
        technique = self._technique(technique_id)
        if not technique.requires_replay:
            raise ValueError(f"technique {technique_id} is not a replay technique")
        if not context.consent_id:
            raise PermissionError("auth replay requires a signed consent id")
        try:
            self.preflight.authorize_scan(target=context.target, consent_id=context.consent_id)
            plan = self.replay_client.prepare(flow_id)
            context.require_in_scope(plan.url)
            if plan.method not in self.SAFE_METHODS and not allow_state_change:
                raise PermissionError(f"state-changing method {plan.method} requires explicit allow_state_change=True")
            if remove_authorization:
                plan.headers = {key: value for key, value in plan.headers.items() if key.casefold() not in {"authorization", "cookie"}}
            for key, value in (headers or {}).items():
                plan.set_header(key, value)
            if token is not None:
                plan.set_token(token)
            await self.preflight.acquire_rate("auth-replay")
            result = await self.replay_client.execute(plan)
            original = self.replay_client.flows.get_flow_by_id(flow_id)
            finding = self._looks_authorized_like_original(original or {}, result)
            return AuthTestResult(
                technique_id=technique.id,
                status="finding" if finding else "pass",
                severity=technique.severity_hint if finding else "info",
                summary=technique.name,
                evidence={
                    "flow_id": flow_id,
                    "method": plan.method,
                    "status": result.get("status"),
                    "original_status": (original or {}).get("status"),
                    "body_changed": ((result.get("diff") or {}).get("body") or {}).get("changed"),
                    "authorization_variant": "removed" if remove_authorization else "supplied" if token is not None else "headers-only",
                },
            )
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _looks_authorized_like_original(original: Mapping[str, Any], replay: Mapping[str, Any]) -> bool:
        original_status = original.get("status")
        replay_status = replay.get("status")
        if original_status is None or replay_status is None:
            return False
        if int(original_status) >= 400:
            return False
        if int(replay_status) != int(original_status):
            return False
        diff = replay.get("diff") or {}
        body = diff.get("body") if isinstance(diff, Mapping) else {}
        if isinstance(body, Mapping):
            before = int(body.get("before_length") or 0)
            after = int(body.get("after_length") or 0)
            if before == 0 and after == 0:
                return True
            denominator = max(before, after, 1)
            return abs(before - after) / denominator <= 0.10
        return True

    @staticmethod
    def _technique(technique_id: str) -> AuthTechnique:
        for technique in AUTH_TECHNIQUES:
            if technique.id == technique_id:
                return technique
        raise KeyError(f"unknown auth technique: {technique_id}")


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value.casefold(), 0)
