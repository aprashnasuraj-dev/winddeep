"""Offline JWT, OAuth/OIDC, and SAML protocol analyzers for Windeep."""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


class ProtocolAnalysisError(ValueError):
    """Raised when authentication protocol input cannot be parsed safely."""


@dataclass(frozen=True, slots=True)
class ProtocolIssue:
    """One normalized protocol-hardening observation."""

    code: str
    title: str
    severity: str
    evidence: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class JWTAnalysis:
    """Decoded JWT metadata and security observations without signature bypass attempts."""

    header: dict[str, Any]
    claims: dict[str, Any]
    issues: tuple[ProtocolIssue, ...]
    lifetime_seconds: float | None


@dataclass(frozen=True, slots=True)
class OAuthAnalysis:
    """OAuth/OIDC request metadata and security observations."""

    parameters: dict[str, str]
    issues: tuple[ProtocolIssue, ...]


@dataclass(frozen=True, slots=True)
class SAMLAnalysis:
    """SAML response/assertion metadata and security observations."""

    root_tag: str
    issuer: str | None
    audience: str | None
    recipient: str | None
    signed_response: bool
    signed_assertion: bool
    issues: tuple[ProtocolIssue, ...]


def _b64url_json(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolAnalysisError("JWT segment is not valid base64url JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolAnalysisError("JWT header/claims must be JSON objects")
    return value


def analyze_jwt(token: str, *, now: float | None = None, expected_issuer: str | None = None, expected_audience: str | None = None) -> JWTAnalysis:
    """Analyze JWT structure and claim/header hardening without modifying or signing tokens."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ProtocolAnalysisError("JWT must contain exactly three compact segments")
    header = _b64url_json(parts[0])
    claims = _b64url_json(parts[1])
    issues: list[ProtocolIssue] = []
    alg = str(header.get("alg") or "").strip()
    if not alg:
        issues.append(ProtocolIssue("jwt.alg.missing", "JWT algorithm is missing", "high", "header.alg is absent", "Reject tokens without an explicit allowed algorithm."))
    elif alg.casefold() == "none":
        issues.append(ProtocolIssue("jwt.alg.none", "Unsigned JWT algorithm declared", "critical", "header.alg=none", "Reject unsigned tokens and enforce an algorithm allowlist."))
    elif alg.upper().startswith("HS"):
        issues.append(ProtocolIssue("jwt.alg.symmetric", "Symmetric JWT signing requires strong secret management", "info", f"header.alg={alg}", "Use a high-entropy secret and avoid sharing verification material with untrusted components."))

    for pointer in ("jku", "x5u"):
        value = header.get(pointer)
        if isinstance(value, str) and value:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme not in {"https"}:
                issues.append(ProtocolIssue(f"jwt.{pointer}.scheme", f"JWT {pointer} uses a non-HTTPS URL", "high", value, "Pin trusted key sources and require HTTPS."))
            else:
                issues.append(ProtocolIssue(f"jwt.{pointer}.trust", f"JWT {pointer} key URL must be allowlisted", "medium", value, "Do not trust token-controlled key URLs without a strict issuer-bound allowlist."))
    kid = header.get("kid")
    if isinstance(kid, str) and any(marker in kid for marker in ("../", "..\\", "file:", "http://", "https://")):
        issues.append(ProtocolIssue("jwt.kid.untrusted", "JWT key id contains path/URL-like input", "high", kid, "Treat kid only as an opaque identifier resolved from a fixed local key set."))
    crit = header.get("crit")
    if crit is not None and not isinstance(crit, list):
        issues.append(ProtocolIssue("jwt.crit.invalid", "JWT crit header has an unexpected type", "medium", repr(crit), "Reject malformed critical-header declarations."))

    current = float(now if now is not None else time.time())
    exp = claims.get("exp")
    iat = claims.get("iat")
    nbf = claims.get("nbf")
    if exp is None:
        issues.append(ProtocolIssue("jwt.exp.missing", "JWT has no expiration", "medium", "claim exp is absent", "Issue short-lived access tokens with exp."))
    elif isinstance(exp, (int, float)) and float(exp) < current:
        issues.append(ProtocolIssue("jwt.exp.expired", "JWT is expired", "info", f"exp={exp}", "Reject expired tokens consistently at every authorization boundary."))
    if iat is None:
        issues.append(ProtocolIssue("jwt.iat.missing", "JWT has no issued-at claim", "low", "claim iat is absent", "Include iat to support lifecycle and rotation analysis."))
    elif isinstance(iat, (int, float)) and float(iat) > current + 300:
        issues.append(ProtocolIssue("jwt.iat.future", "JWT issued-at time is in the future", "medium", f"iat={iat}", "Reject implausible issue times with a small clock-skew allowance."))
    if isinstance(nbf, (int, float)) and float(nbf) > current + 300:
        issues.append(ProtocolIssue("jwt.nbf.future", "JWT is not yet valid", "info", f"nbf={nbf}", "Enforce nbf with bounded clock skew."))

    if expected_issuer is not None and claims.get("iss") != expected_issuer:
        issues.append(ProtocolIssue("jwt.iss.mismatch", "JWT issuer does not match the expected issuer", "high", f"iss={claims.get('iss')!r}", "Bind verification keys and accepted claims to the expected issuer."))
    if expected_audience is not None:
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else list(aud) if isinstance(aud, list) else []
        if expected_audience not in audiences:
            issues.append(ProtocolIssue("jwt.aud.mismatch", "JWT audience does not include the expected audience", "high", f"aud={aud!r}", "Require the intended audience at the receiving service."))
    if "iss" not in claims:
        issues.append(ProtocolIssue("jwt.iss.missing", "JWT has no issuer claim", "low", "claim iss is absent", "Include and verify iss for multi-issuer environments."))
    if "aud" not in claims:
        issues.append(ProtocolIssue("jwt.aud.missing", "JWT has no audience claim", "medium", "claim aud is absent", "Include and verify aud at resource servers."))
    if "jti" not in claims:
        issues.append(ProtocolIssue("jwt.jti.missing", "JWT has no token identifier", "info", "claim jti is absent", "Consider jti where revocation/replay detection is required."))

    lifetime: float | None = None
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = float(exp) - float(iat)
        if lifetime < 0:
            issues.append(ProtocolIssue("jwt.lifetime.negative", "JWT expiration precedes issue time", "high", f"lifetime={lifetime}", "Reject temporally inconsistent tokens."))
        elif lifetime > 24 * 60 * 60:
            issues.append(ProtocolIssue("jwt.lifetime.long", "JWT access-token lifetime is long", "medium", f"lifetime_seconds={lifetime}", "Prefer short-lived access tokens and refresh-token rotation."))
    return JWTAnalysis(header=header, claims=claims, issues=tuple(issues), lifetime_seconds=lifetime)


def _coerce_params(value: str | Mapping[str, Any]) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in value.items() if item is not None}
    raw = value.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    else:
        pairs = urllib.parse.parse_qsl(raw.lstrip("?"), keep_blank_values=True)
    return {key: item for key, item in pairs}


def analyze_oauth(request_or_params: str | Mapping[str, Any], *, oidc: bool | None = None) -> OAuthAnalysis:
    """Analyze OAuth/OIDC authorization request parameters without sending traffic."""
    params = _coerce_params(request_or_params)
    issues: list[ProtocolIssue] = []
    response_type = params.get("response_type", "")
    scope = params.get("scope", "")
    is_oidc = bool(oidc) if oidc is not None else "openid" in scope.split()
    if not params.get("state"):
        issues.append(ProtocolIssue("oauth.state.missing", "OAuth authorization request has no state", "high", "state is absent", "Use an unpredictable state value and bind it to the browser session."))
    if is_oidc and not params.get("nonce"):
        issues.append(ProtocolIssue("oidc.nonce.missing", "OIDC request has no nonce", "high", "nonce is absent", "Use and verify a nonce for OIDC authentication requests."))
    if "token" in response_type.split() or "id_token" in response_type.split():
        issues.append(ProtocolIssue("oauth.implicit", "Front-channel token response type is requested", "medium", f"response_type={response_type}", "Prefer authorization code flow with PKCE where supported."))
    code_challenge = params.get("code_challenge")
    challenge_method = params.get("code_challenge_method")
    if "code" in response_type.split() and not code_challenge:
        issues.append(ProtocolIssue("oauth.pkce.missing", "Authorization-code request has no PKCE challenge", "medium", "code_challenge is absent", "Use PKCE, especially for public/native/browser clients."))
    elif code_challenge and challenge_method.casefold() != "s256":
        issues.append(ProtocolIssue("oauth.pkce.weak_method", "PKCE does not use S256", "medium", f"code_challenge_method={challenge_method or 'plain'}", "Use S256 PKCE challenges."))
    redirect_uri = params.get("redirect_uri")
    if redirect_uri:
        parsed = urllib.parse.urlsplit(redirect_uri)
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            issues.append(ProtocolIssue("oauth.redirect.http", "OAuth redirect URI is non-HTTPS", "high", redirect_uri, "Use pre-registered HTTPS redirect URIs except loopback native-app redirects."))
        if parsed.fragment:
            issues.append(ProtocolIssue("oauth.redirect.fragment", "OAuth redirect URI contains a fragment", "medium", redirect_uri, "Register exact redirect URIs without fragments."))
    if params.get("prompt") == "none" and not is_oidc:
        issues.append(ProtocolIssue("oauth.prompt.none", "prompt=none appears outside an identified OIDC request", "low", "prompt=none", "Confirm silent authentication is expected and issuer-bound."))
    if "offline_access" in scope.split() and not is_oidc:
        issues.append(ProtocolIssue("oauth.offline_access", "offline_access scope is requested outside identified OIDC flow", "low", scope, "Grant refresh/offline access only to clients that require it."))
    return OAuthAnalysis(parameters=params, issues=tuple(issues))


def _decode_xml(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value.strip()
    else:
        raw = value.strip().encode("utf-8")
    if raw.startswith(b"<"):
        return raw
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise ProtocolAnalysisError("SAML input is neither XML nor valid base64") from exc


def _find_text(root: ET.Element, suffix: str) -> str | None:
    for element in root.iter():
        if element.tag.endswith(suffix) and element.text and element.text.strip():
            return element.text.strip()
    return None


def _find_attr(root: ET.Element, suffix: str, attribute: str) -> str | None:
    for element in root.iter():
        if element.tag.endswith(suffix):
            value = element.attrib.get(attribute)
            if value:
                return value
    return None


def analyze_saml(xml_or_base64: str | bytes, *, expected_audience: str | None = None, expected_recipient: str | None = None) -> SAMLAnalysis:
    """Analyze SAML XML signatures/conditions with external-entity resolution disabled by ElementTree."""
    raw = _decode_xml(xml_or_base64)
    if len(raw) > 2_000_000:
        raise ProtocolAnalysisError("SAML document exceeds 2 MB analysis limit")
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ProtocolAnalysisError("SAML document contains a DTD/entity declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ProtocolAnalysisError("invalid SAML XML") from exc
    signatures = [element for element in root.iter() if element.tag.endswith("Signature")]
    response_signed = any(element in list(root) for element in signatures)
    assertion_nodes = [element for element in root.iter() if element.tag.endswith("Assertion")]
    assertion_signed = any(any(child.tag.endswith("Signature") for child in list(assertion)) for assertion in assertion_nodes)
    issuer = _find_text(root, "Issuer")
    audience = _find_text(root, "Audience")
    recipient = _find_attr(root, "SubjectConfirmationData", "Recipient")
    issues: list[ProtocolIssue] = []
    if not response_signed and not assertion_signed:
        issues.append(ProtocolIssue("saml.signature.missing", "SAML response/assertion has no XML signature", "critical", "no ds:Signature element under response/assertion", "Require cryptographic signatures and validate against pinned IdP metadata."))
    elif not assertion_signed:
        issues.append(ProtocolIssue("saml.assertion.unsigned", "SAML assertion is not directly signed", "medium", "response may be signed but assertion is not", "Ensure the implementation validates the exact signed element it consumes."))
    if audience is None:
        issues.append(ProtocolIssue("saml.audience.missing", "SAML assertion has no audience restriction", "high", "Audience is absent", "Require and validate AudienceRestriction for the service provider."))
    elif expected_audience is not None and audience != expected_audience:
        issues.append(ProtocolIssue("saml.audience.mismatch", "SAML audience does not match the service provider", "high", f"audience={audience}", "Reject assertions for other audiences."))
    if recipient is None:
        issues.append(ProtocolIssue("saml.recipient.missing", "SAML subject confirmation has no recipient", "medium", "Recipient is absent", "Validate Recipient/Destination against the exact ACS endpoint."))
    elif expected_recipient is not None and recipient != expected_recipient:
        issues.append(ProtocolIssue("saml.recipient.mismatch", "SAML recipient does not match the expected ACS", "high", f"recipient={recipient}", "Reject assertions addressed to another recipient."))
    in_response_to = root.attrib.get("InResponseTo")
    if in_response_to is None:
        issues.append(ProtocolIssue("saml.inresponseto.missing", "SAML response is not bound to an authentication request", "medium", "InResponseTo is absent", "For SP-initiated SSO, bind responses to one-time request IDs."))
    return SAMLAnalysis(root_tag=root.tag, issuer=issuer, audience=audience, recipient=recipient, signed_response=response_signed, signed_assertion=assertion_signed, issues=tuple(issues))
