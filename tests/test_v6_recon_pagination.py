"""V6 regression coverage for recon completeness and non-filtering scope classification."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.tools import builtin_fallbacks as bf
from app.tools import builtin_integrations as bi


class FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._payload


class FakeClient:
    def __init__(self, responses: list[FakeResponse], calls: list[dict[str, Any]]) -> None:
        self._responses = responses
        self._calls = calls

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self._calls.append({"url": url, **kwargs})
        return self._responses.pop(0)


def _install_client(monkeypatch: pytest.MonkeyPatch, module: Any, payloads: list[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    responses = [FakeResponse(payload) for payload in payloads]

    def factory(*args: Any, **kwargs: Any) -> FakeClient:
        del args, kwargs
        return FakeClient(responses, calls)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)
    return calls


@pytest.mark.asyncio
async def test_wayback_resume_pagination_collects_more_than_500_without_result_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = ["original", "statuscode", "timestamp"]
    first_rows = [
        [f"https://example.test/archive/{index}", "200", f"202601{index % 28 + 1:02d}000000"]
        for index in range(501)
    ]
    second_rows = [
        [f"https://example.test/archive/{index}", "200", f"202602{index % 28 + 1:02d}000000"]
        for index in range(501, 641)
    ]
    calls = _install_client(
        monkeypatch,
        bf,
        [
            [headers, *first_rows, [], ["resume-key-1"]],
            [headers, *second_rows],
        ],
    )

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(bf.asyncio, "sleep", no_sleep)
    rows = await bf._wayback_cdx("example.test", "gau")

    assert len(rows) == 641
    assert rows[0]["endpoint"] == "https://example.test/archive/0"
    assert rows[-1]["endpoint"] == "https://example.test/archive/640"
    assert len(calls) == 2
    assert calls[0]["params"]["showResumeKey"] == "true"
    assert calls[0]["params"]["limit"] == "5000"  # transport page size, not an overall cap
    assert "resumeKey" not in calls[0]["params"]
    assert calls[1]["params"]["resumeKey"] == "resume-key-1"


@pytest.mark.asyncio
async def test_fallback_crtsh_does_not_truncate_after_500_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = [{"name_value": f"host-{index}.example.test"} for index in range(621)]
    _install_client(monkeypatch, bf, [payload])
    rows = await bf._crtsh("example.test", "crtsh")
    assert len(rows) == 621
    assert rows[-1]["endpoint"] == "host-620.example.test"


@pytest.mark.asyncio
async def test_builtin_crtsh_does_not_truncate_after_500_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = [{"name_value": f"host-{index}.example.test"} for index in range(623)]
    _install_client(monkeypatch, bi, [payload])
    rows = await bi._crtsh("example.test", {})
    assert len(rows) == 623
    assert rows[-1]["endpoint"] == "host-622.example.test"
