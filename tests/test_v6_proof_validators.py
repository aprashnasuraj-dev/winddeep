"""V6 controlled proof validator matrix: positive and patched negative controls."""
from __future__ import annotations

from copy import deepcopy

import pytest

from app.evidence import proof_validators as proof_module
from app.evidence.proof_validators import ControlledProofValidator, ProofValidationError


def _flow(
    flow_id: int,
    *,
    status: int = 200,
    url: str = "https://example.test/resource/7",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> dict:
    return {
        "id": flow_id,
        "method": method,
        "url": url,
        "status": status,
        "response_headers": dict(headers or {}),
        "response_body": body,
    }


@pytest.mark.parametrize(
    ("vulnerability_class", "candidate", "control", "context"),
    [
        (
            "authorization_boundary",
            _flow(1, status=200, body=b'{"id":7,"owner":"other"}'),
            _flow(2, status=403, body=b'{"error":"forbidden"}'),
            {"candidate_expected_denied": True},
        ),
        (
            "session_invalidation",
            _flow(3, status=200, body=b'{"account":"alice"}'),
            _flow(4, status=401, body=b'{"error":"unauthorized"}'),
            {"candidate_session_state": "invalidated"},
        ),
        (
            "credentialed_cors",
            _flow(
                5,
                headers={
                    "Access-Control-Allow-Origin": "https://untrusted.example",
                    "Access-Control-Allow-Credentials": "true",
                },
            ),
            _flow(6, headers={"Access-Control-Allow-Origin": "https://trusted.example"}),
            {"untrusted_origin": "https://untrusted.example"},
        ),
        (
            "open_redirect",
            _flow(7, status=302, headers={"Location": "https://outside.example/landing"}),
            _flow(8, status=302, headers={"Location": "https://example.test/home"}),
            {"external_host": "outside.example"},
        ),
        (
            "sensitive_marker_exposure",
            _flow(9, body=b'{"debug":"V6-CANARY-123456789"}'),
            _flow(10, body=b'{"debug":"redacted"}'),
            {"marker": "V6-CANARY-123456789"},
        ),
    ],
)
def test_five_v6_classes_emit_structured_proof_on_controlled_vulnerable_fixture(
    vulnerability_class: str,
    candidate: dict,
    control: dict,
    context: dict,
) -> None:
    result = ControlledProofValidator.validate(
        vulnerability_class,
        candidate=candidate,
        control=control,
        context=context,
    )
    assert result is not None
    assert result["security_property"]
    assert result["expected_behavior"]
    assert result["observed_behavior"]
    assert result["candidate_flow_ids"] == [candidate["id"]]
    assert result["control_flow_ids"] == [control["id"]]


@pytest.mark.parametrize(
    ("vulnerability_class", "candidate", "control", "context"),
    [
        (
            "authorization_boundary",
            _flow(21, status=403),
            _flow(22, status=403),
            {"candidate_expected_denied": True},
        ),
        (
            "session_invalidation",
            _flow(23, status=401),
            _flow(24, status=401),
            {"candidate_session_state": "invalidated"},
        ),
        (
            "credentialed_cors",
            _flow(
                25,
                headers={
                    "Access-Control-Allow-Origin": "https://trusted.example",
                    "Access-Control-Allow-Credentials": "true",
                },
            ),
            _flow(26, headers={"Access-Control-Allow-Origin": "https://trusted.example"}),
            {"untrusted_origin": "https://untrusted.example"},
        ),
        (
            "open_redirect",
            _flow(27, status=302, headers={"Location": "https://example.test/home"}),
            _flow(28, status=302, headers={"Location": "https://example.test/home"}),
            {"external_host": "outside.example"},
        ),
        (
            "sensitive_marker_exposure",
            _flow(29, body=b'{"debug":"redacted"}'),
            _flow(30, body=b'{"debug":"redacted"}'),
            {"marker": "V6-CANARY-123456789"},
        ),
    ],
)
def test_five_v6_classes_emit_zero_proof_on_matched_patched_fixture(
    vulnerability_class: str,
    candidate: dict,
    control: dict,
    context: dict,
) -> None:
    assert (
        ControlledProofValidator.validate(
            vulnerability_class,
            candidate=candidate,
            control=control,
            context=context,
        )
        is None
    )


def test_v6_proof_validators_reject_unsafe_or_ambiguous_inputs() -> None:
    candidate = _flow(41)
    control = _flow(42, status=403)

    with pytest.raises(ProofValidationError, match="unsupported"):
        ControlledProofValidator.validate("made_up", candidate=candidate, control=control)

    same = deepcopy(candidate)
    with pytest.raises(ProofValidationError, match="distinct"):
        ControlledProofValidator.validate(
            "authorization_boundary",
            candidate=candidate,
            control=same,
            context={"candidate_expected_denied": True},
        )

    post_candidate = _flow(43, method="POST")
    post_control = _flow(44, method="POST", status=403)
    with pytest.raises(ProofValidationError, match="state-changing"):
        ControlledProofValidator.validate(
            "authorization_boundary",
            candidate=post_candidate,
            control=post_control,
            context={"candidate_expected_denied": True},
        )

    different_resource = _flow(45, url="https://example.test/other")
    with pytest.raises(ProofValidationError, match="same method and HTTP resource"):
        ControlledProofValidator.validate(
            "authorization_boundary",
            candidate=candidate,
            control=different_resource,
            context={"candidate_expected_denied": True},
        )


def test_v6_proof_validators_require_explicit_class_context() -> None:
    with pytest.raises(ProofValidationError, match="candidate_expected_denied"):
        ControlledProofValidator.validate(
            "authorization_boundary",
            candidate=_flow(51),
            control=_flow(52, status=403),
            context={},
        )
    with pytest.raises(ProofValidationError, match="candidate_session_state"):
        ControlledProofValidator.validate(
            "session_invalidation",
            candidate=_flow(53),
            control=_flow(54, status=401),
            context={},
        )
    with pytest.raises(ProofValidationError, match="untrusted_origin"):
        ControlledProofValidator.validate(
            "credentialed_cors",
            candidate=_flow(55),
            control=_flow(56),
            context={"untrusted_origin": "not-a-url"},
        )
    with pytest.raises(ProofValidationError, match="external_host"):
        ControlledProofValidator.validate(
            "open_redirect",
            candidate=_flow(57, status=302),
            control=_flow(58, status=200),
            context={},
        )
    with pytest.raises(ProofValidationError, match="at least 8 bytes"):
        ControlledProofValidator.validate(
            "sensitive_marker_exposure",
            candidate=_flow(59, body=b"short"),
            control=_flow(60),
            context={"marker": "short"},
        )

def test_v6_proof_validator_normalization_and_invalid_flow_edges() -> None:
    assert proof_module._bytes(None) == b""
    assert proof_module._bytes(memoryview(b"marker")) == b"marker"
    assert proof_module._bytes(1234) == b"1234"
    assert proof_module._headers({"response_headers": "not-a-mapping"}) == {}

    with pytest.raises(ProofValidationError, match="valid HTTP status"):
        proof_module._status({"status": "not-an-integer"})
    with pytest.raises(ProofValidationError, match="persisted integer id"):
        proof_module._flow_id({})
    with pytest.raises(ProofValidationError, match="positive"):
        proof_module._flow_id({"id": 0})
    with pytest.raises(ProofValidationError, match="state-changing"):
        proof_module._request_surface({"method": "PATCH", "url": "https://example.test/resource"})
    with pytest.raises(ProofValidationError, match="valid HTTP\(S\) URL"):
        proof_module._request_surface({"method": "GET", "url": "not-a-url"})


def test_v6_proof_validator_rejects_near_misses_without_promoting_them() -> None:
    # Authorization: a redirect is not evidence of protected-resource access.
    assert ControlledProofValidator.validate(
        "authorization_boundary",
        candidate=_flow(71, status=302),
        control=_flow(72, status=403),
        context={"candidate_expected_denied": True},
    ) is None

    # Session invalidation: a still-denied session is the patched behavior.
    assert ControlledProofValidator.validate(
        "session_invalidation",
        candidate=_flow(73, status=403),
        control=_flow(74, status=401),
        context={"candidate_session_state": "invalidated"},
    ) is None

    # CORS: credentials alone are insufficient without the untrusted origin.
    assert ControlledProofValidator.validate(
        "credentialed_cors",
        candidate=_flow(
            75,
            headers={
                "Access-Control-Allow-Origin": "https://trusted.example",
                "Access-Control-Allow-Credentials": "true",
            },
        ),
        control=_flow(76, headers={"Access-Control-Allow-Origin": "https://trusted.example"}),
        context={"untrusted_origin": "https://untrusted.example"},
    ) is None

    # Redirect: a same-origin Location must not promote.
    assert ControlledProofValidator.validate(
        "open_redirect",
        candidate=_flow(77, status=302, headers={"Location": "/home"}),
        control=_flow(78, status=200),
        context={"external_host": "outside.example"},
    ) is None

    # Sensitive marker: identical candidate/control bodies are not a difference.
    identical = b'{"debug":"V6-CANARY-EDGE-123456"}'
    assert ControlledProofValidator.validate(
        "sensitive_marker_exposure",
        candidate=_flow(79, body=identical),
        control=_flow(80, body=identical),
        context={"marker": "V6-CANARY-EDGE-123456"},
    ) is None

    # If the marker is also present in the control, there is no candidate-only leak.
    assert ControlledProofValidator.validate(
        "sensitive_marker_exposure",
        candidate=_flow(81, body=b"prefix V6-CANARY-CONTROL-123 suffix"),
        control=_flow(82, body=b"V6-CANARY-CONTROL-123"),
        context={"marker": "V6-CANARY-CONTROL-123"},
    ) is None

