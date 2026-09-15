"""Release coverage for the 160 evidence-driven test-pack registry."""

from __future__ import annotations

import asyncio

import pytest

from app.modules.test_packs import HunterContext, TESTS, all_tests, list_test_metadata, run_selected_tests


def _cls(slug: str):
    return next(cls for cls in all_tests() if cls.spec.slug == slug)


@pytest.mark.asyncio
async def test_test_pack_prerequisites_fail_closed() -> None:
    missing_target = await _cls("missing_csp")().run({})
    assert missing_target["status"] == "skipped"

    auth = await _cls("session_fixation_indicator")().run(HunterContext(target_url="https://example.com"))
    assert auth["status"] == "skipped" and "Authenticated" in auth["details"]

    two_accounts = await _cls("cross_user_object_read_signal")().run(
        HunterContext(target_url="https://example.com", authenticated=True, account_count=1)
    )
    assert two_accounts["status"] == "skipped" and "Two explicitly" in two_accounts["details"]

    mobile = await _cls("android_debuggable_flag")().run(HunterContext(target_url="https://example.com"))
    assert mobile["status"] == "skipped" and "mobile artifact" in mobile["details"]


@pytest.mark.asyncio
async def test_explicit_signal_and_manual_review_paths() -> None:
    observed = await _cls("prompt_injection_boundary")().run(
        HunterContext(target_url="https://example.com", signals={"PROMPT_INJECTION_BOUNDARY"})
    )
    assert observed["status"] == "observed"
    assert observed["passed"] is True
    assert observed["confidence"] == 0.8
    assert observed["evidence"]["signals"] == ["prompt_injection_boundary"]

    manual = await _cls("price_field_client_control")().run(
        HunterContext(target_url="https://example.com", authenticated=True, account_count=2)
    )
    assert manual["status"] == "skipped"
    assert manual["execution_mode"] == "manual_review"

    quiet = await _cls("metadata_endpoint_exposure")().run(HunterContext(target_url="https://example.com"))
    assert quiet["status"] == "not_observed"


@pytest.mark.asyncio
async def test_passive_header_cookie_error_and_token_observations() -> None:
    flows = [
        {
            "id": 11,
            "response_headers": {
                "Server": "ExampleServer/2.4",
                "Access-Control-Allow-Origin": "*",
                "Set-Cookie": "sid=abc",
            },
            "response_body": b"Traceback: SQLSTATE example exception",
            "request_headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJleHAiOjF9.signature"},
        }
    ]
    ctx = HunterContext(target_url="https://example.com", flows=flows, authenticated=True, account_count=2)
    expected_indicators = {
        "missing_csp",
        "clickjacking_exposure",
        "cookie_secure_flag_weakness",
        "cookie_httponly_weakness",
        "cookie_samesite_weakness",
        "cors_wildcard_origin",
        "verbose_error_disclosure",
        "server_version_disclosure",
        "jwt_expiration_validation",
    }
    for slug in expected_indicators:
        result = await _cls(slug)().run(ctx)
        assert result["status"] == "review", (slug, result)
        assert result["passed"] is False
        assert result["confidence"] == 0.35
        assert result["evidence"]


@pytest.mark.asyncio
async def test_cookie_and_header_helpers_ignore_unusable_evidence() -> None:
    ctx = HunterContext(
        target_url="https://example.com",
        flows=[{"id": 1, "response_headers": "not-a-mapping", "response_body": None}],
    )
    assert (await _cls("missing_csp")().run(ctx))["status"] == "not_observed"
    assert (await _cls("cookie_secure_flag_weakness")().run(ctx))["status"] == "not_observed"
    assert (await _cls("verbose_error_disclosure")().run(ctx))["status"] == "not_observed"


@pytest.mark.asyncio
async def test_run_selected_tests_filters_packs_ids_and_mapping_context() -> None:
    metadata = list_test_metadata()
    assert len(metadata) == 160
    assert len(all_tests()) == 160
    assert set(TESTS) == {
        "browser_fidelity",
        "human_multistage",
        "auth_session",
        "idor_bola",
        "business_logic",
        "mobile_deep_dive",
        "ai_automation",
        "wild_cards",
    }
    selected = await run_selected_tests(
        {"target": "https://example.com", "signals": ["missing_csp"], "authenticated": True, "account_count": 2},
        packs=["browser_fidelity"],
        test_ids=["missing_csp", "cors_wildcard_origin"],
    )
    by_id = {item["test_id"]: item for item in selected}
    assert set(by_id) == {"missing_csp", "cors_wildcard_origin"}
    assert by_id["missing_csp"]["status"] == "observed"


@pytest.mark.asyncio
async def test_runner_normalizes_test_exceptions(monkeypatch) -> None:
    cls = _cls("metadata_endpoint_exposure")

    async def broken(_self, _ctx):
        raise RuntimeError("synthetic release test failure")

    monkeypatch.setattr(cls, "run", broken)
    results = await run_selected_tests(
        HunterContext(target_url="https://example.com"),
        packs=["wild_cards"],
        test_ids=["metadata_endpoint_exposure"],
    )
    assert results[0]["status"] == "error"
    assert "synthetic release test failure" in results[0]["details"]


@pytest.mark.asyncio
async def test_runner_propagates_cancellation(monkeypatch) -> None:
    cls = _cls("metadata_endpoint_exposure")

    async def cancelled(_self, _ctx):
        raise asyncio.CancelledError()

    monkeypatch.setattr(cls, "run", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await run_selected_tests(
            HunterContext(target_url="https://example.com"),
            packs=["wild_cards"],
            test_ids=["metadata_endpoint_exposure"],
        )
