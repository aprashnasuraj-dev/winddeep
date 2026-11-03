"""Deterministic V6 proof validators over already-captured authorized HTTP flows.

These validators perform no network activity and make no submission decision.
They only decide whether a narrowly defined, class-specific evidence invariant is
present between an explicit candidate flow and a matched control flow.  The
returned proof_context can be bound into an EvidenceBundleStore and must still
pass verification, tester triage, and human approval.
"""
from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ProofValidationError(ValueError):
    """Raised when controlled proof inputs are malformed or unsafe."""


def _bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    return str(value).encode("utf-8")


def _headers(flow: Mapping[str, Any]) -> dict[str, str]:
    raw = flow.get("response_headers")
    if not isinstance(raw, Mapping):
        return {}
    return {str(key).casefold(): str(value).strip() for key, value in raw.items()}


def _status(flow: Mapping[str, Any]) -> int:
    try:
        return int(flow.get("status"))
    except (TypeError, ValueError) as exc:
        raise ProofValidationError("proof flow is missing a valid HTTP status") from exc


def _flow_id(flow: Mapping[str, Any]) -> int:
    try:
        value = int(flow["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofValidationError("proof flow requires a persisted integer id") from exc
    if value < 1:
        raise ProofValidationError("proof flow id must be positive")
    return value


def _request_surface(flow: Mapping[str, Any]) -> tuple[str, str, str, str]:
    method = str(flow.get("method") or "").upper()
    if method not in _SAFE_METHODS:
        raise ProofValidationError(f"proof validation refuses state-changing method: {method or 'unknown'}")
    parsed = urlsplit(str(flow.get("url") or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProofValidationError("proof flow requires a valid HTTP(S) URL")
    return method, parsed.scheme, parsed.netloc.casefold(), parsed.path or "/"


def _same_surface(candidate: Mapping[str, Any], control: Mapping[str, Any]) -> None:
    if _request_surface(candidate) != _request_surface(control):
        raise ProofValidationError("candidate and control must cover the same method and HTTP resource")
    if _flow_id(candidate) == _flow_id(control):
        raise ProofValidationError("candidate and control must be distinct persisted flows")


def _proof(
    candidate: Mapping[str, Any],
    control: Mapping[str, Any],
    *,
    security_property: str,
    expected_behavior: str,
    observed_behavior: str,
) -> dict[str, Any]:
    return {
        "security_property": security_property,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "candidate_flow_ids": [_flow_id(candidate)],
        "control_flow_ids": [_flow_id(control)],
    }


class ControlledProofValidator:
    """Class-specific evidence checks used by the V6 lab and manual validators."""

    SUPPORTED_CLASSES = frozenset(
        {
            "authorization_boundary",
            "session_invalidation",
            "credentialed_cors",
            "open_redirect",
            "sensitive_marker_exposure",
        }
    )

    @classmethod
    def validate(
        cls,
        vulnerability_class: str,
        *,
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        name = str(vulnerability_class).strip().casefold()
        if name not in cls.SUPPORTED_CLASSES:
            raise ProofValidationError(f"unsupported proof class: {vulnerability_class}")
        _same_surface(candidate, control)
        ctx = dict(context or {})
        method = getattr(cls, f"_validate_{name}")
        return method(candidate, control, ctx)

    @staticmethod
    def _validate_authorization_boundary(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if context.get("candidate_expected_denied") is not True:
            raise ProofValidationError("authorization proof requires candidate_expected_denied=true")
        candidate_status, control_status = _status(candidate), _status(control)
        if not (200 <= candidate_status < 300 and control_status in {401, 403}):
            return None
        return _proof(
            candidate,
            control,
            security_property="A caller explicitly expected to be denied must not receive the protected resource.",
            expected_behavior=f"The candidate is denied consistently with the matched control (HTTP {control_status}).",
            observed_behavior=f"The candidate received HTTP {candidate_status} while the matched control was denied.",
        )

    @staticmethod
    def _validate_session_invalidation(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if str(context.get("candidate_session_state") or "").casefold() != "invalidated":
            raise ProofValidationError("session proof requires candidate_session_state=invalidated")
        candidate_status, control_status = _status(candidate), _status(control)
        if not (200 <= candidate_status < 300 and control_status in {401, 403}):
            return None
        return _proof(
            candidate,
            control,
            security_property="An invalidated session must no longer authorize access to the protected resource.",
            expected_behavior=f"The invalidated session is denied like the matched unauthenticated/invalid control (HTTP {control_status}).",
            observed_behavior=f"The invalidated session still received HTTP {candidate_status}.",
        )

    @staticmethod
    def _validate_credentialed_cors(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        origin = str(context.get("untrusted_origin") or "").strip()
        parsed_origin = urlsplit(origin)
        if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.hostname:
            raise ProofValidationError("CORS proof requires a valid untrusted_origin")
        candidate_headers = _headers(candidate)
        control_headers = _headers(control)
        allow_origin = candidate_headers.get("access-control-allow-origin", "")
        credentials = candidate_headers.get("access-control-allow-credentials", "").casefold()
        control_origin = control_headers.get("access-control-allow-origin", "")
        if not (
            allow_origin == origin
            and credentials == "true"
            and control_origin != origin
        ):
            return None
        return _proof(
            candidate,
            control,
            security_property="Credentialed cross-origin responses must not authorize an explicitly untrusted origin.",
            expected_behavior=f"The untrusted origin {origin} is not granted credentialed CORS access.",
            observed_behavior=f"The response granted Access-Control-Allow-Origin: {origin} with credentials enabled.",
        )

    @staticmethod
    def _validate_open_redirect(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        external_host = str(context.get("external_host") or "").strip().casefold().rstrip(".")
        if not external_host:
            raise ProofValidationError("open-redirect proof requires external_host")
        candidate_status, control_status = _status(candidate), _status(control)
        candidate_location = _headers(candidate).get("location", "")
        control_location = _headers(control).get("location", "")
        candidate_host = (urlsplit(candidate_location).hostname or "").casefold().rstrip(".")
        control_host = (urlsplit(control_location).hostname or "").casefold().rstrip(".")
        source_host = (urlsplit(str(candidate.get("url") or "")).hostname or "").casefold().rstrip(".")
        if not (
            300 <= candidate_status < 400
            and candidate_host == external_host
            and candidate_host != source_host
            and not (300 <= control_status < 400 and control_host == external_host)
        ):
            return None
        return _proof(
            candidate,
            control,
            security_property="Redirect destinations must remain within the intended trusted destination policy.",
            expected_behavior=f"The request does not redirect to the external host {external_host}.",
            observed_behavior=f"The candidate response redirected to external host {external_host}.",
        )

    @staticmethod
    def _validate_sensitive_marker_exposure(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        marker = context.get("marker")
        marker_bytes = _bytes(marker)
        if len(marker_bytes) < 8:
            raise ProofValidationError("sensitive-marker proof requires an operator-supplied marker of at least 8 bytes")
        candidate_body = _bytes(candidate.get("response_body"))
        control_body = _bytes(control.get("response_body"))
        # compare_digest avoids using an early-exit equality check for the exact
        # marker value while containment determines whether the captured proof
        # actually exposes the marker.
        if hmac.compare_digest(candidate_body, control_body):
            return None
        if marker_bytes not in candidate_body or marker_bytes in control_body:
            return None
        return _proof(
            candidate,
            control,
            security_property="A sensitive operator-supplied marker must not be exposed in the candidate response.",
            expected_behavior="The marker is absent, matching the control response.",
            observed_behavior="The candidate response contains the exact operator-supplied sensitive marker while the control does not.",
        )


__all__ = ["ControlledProofValidator", "ProofValidationError"]
