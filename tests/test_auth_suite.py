"""Tests for Windeep's guarded fifty-technique authentication suite."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.auth.protocols import ProtocolIssue, JWTAnalysis
from app.auth.suite import AUTH_TECHNIQUES, AuthBypassSuite
from app.capture.replay_client import ReplayPlan
from app.engine.scan_context import ScanContext


class FakePreflight:
    """Record authorization/rate calls made by the suite."""

    def __init__(self) -> None:
        self.authorized: list[tuple[str, str]] = []
        self.rates: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str):
        self.authorized.append((target, consent_id))
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        self.rates.append(key)


class FakeFlows:
    def __init__(self, method: str = "GET") -> None:
        self.flow = {"id": 1, "method": method, "url": "https://example.com/private", "status": 200, "request_headers": {"Authorization": "Bearer current"}, "response_body": b"A" * 100}

    def get_flow_by_id(self, flow_id: int):
        return dict(self.flow) if flow_id == 1 else None


class FakeReplay:
    def __init__(self, method: str = "GET", replay_status: int = 200, after_length: int = 98) -> None:
        self.flows = FakeFlows(method)
        self.replay_status = replay_status
        self.after_length = after_length

    def prepare(self, flow_id: int) -> ReplayPlan:
        flow = self.flows.get_flow_by_id(flow_id)
        assert flow is not None
        return ReplayPlan(flow_id=1, method=flow["method"], url=flow["url"], headers=dict(flow["request_headers"]), body=b"")

    async def execute(self, plan: ReplayPlan):
        return {"status": self.replay_status, "diff": {"body": {"before_length": 100, "after_length": self.after_length, "changed": self.after_length != 100}}}


def _ctx() -> ScanContext:
    return ScanContext(target="example.com", scope=["example.com"], consent_id="consent-1")


def test_registry_contains_exactly_fifty_unique_techniques() -> None:
    assert len(AUTH_TECHNIQUES) == 50
    assert len({item.id for item in AUTH_TECHNIQUES}) == 50
    assert {item.category for item in AUTH_TECHNIQUES} == {"jwt", "oauth", "saml", "session", "mfa_reset"}


def test_offline_results_map_protocol_issue_to_technique() -> None:
    jwt = JWTAnalysis(header={"alg": "none"}, claims={}, lifetime_seconds=None, issues=(ProtocolIssue("jwt.alg.none", "Unsigned", "critical", "alg=none", "reject"),))
    results = AuthBypassSuite.offline_results(jwt=jwt)
    by_id = {item.technique_id: item for item in results}
    assert by_id["JWT-01"].status == "finding"
    assert by_id["JWT-01"].severity == "critical"
    assert by_id["JWT-02"].status == "pass"


def test_unknown_technique_is_rejected() -> None:
    with pytest.raises(KeyError):
        AuthBypassSuite._technique("NOPE")


@pytest.mark.asyncio
async def test_state_changing_replay_requires_explicit_opt_in() -> None:
    guard = FakePreflight()
    suite = AuthBypassSuite(guard, FakeReplay(method="POST"))  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="allow_state_change"):
        await suite.replay_variant(technique_id="SESSION-09", context=_ctx(), flow_id=1, remove_authorization=True)
    assert guard.authorized == [("example.com", "consent-1")]


@pytest.mark.asyncio
async def test_anonymous_get_replay_is_guarded_and_can_surface_finding() -> None:
    guard = FakePreflight()
    replay = FakeReplay(method="GET", replay_status=200, after_length=96)
    suite = AuthBypassSuite(guard, replay)  # type: ignore[arg-type]
    result = await suite.replay_variant(technique_id="SESSION-09", context=_ctx(), flow_id=1, remove_authorization=True)
    assert result.status == "finding"
    assert result.severity == "critical"
    assert guard.rates == ["auth-replay"]
    assert guard.authorized == [("example.com", "consent-1")]


@pytest.mark.asyncio
async def test_changed_authorization_response_passes_check() -> None:
    guard = FakePreflight()
    suite = AuthBypassSuite(guard, FakeReplay(method="GET", replay_status=401, after_length=20))  # type: ignore[arg-type]
    result = await suite.replay_variant(technique_id="SESSION-10", context=_ctx(), flow_id=1, token="other-owned-account-token")
    assert result.status == "pass"
    assert result.severity == "info"


@pytest.mark.asyncio
async def test_missing_consent_blocks_before_replay() -> None:
    guard = FakePreflight()
    suite = AuthBypassSuite(guard, FakeReplay())  # type: ignore[arg-type]
    context = ScanContext(target="example.com", scope=["example.com"])
    with pytest.raises(PermissionError, match="signed consent"):
        await suite.replay_variant(technique_id="SESSION-09", context=context, flow_id=1, remove_authorization=True)
