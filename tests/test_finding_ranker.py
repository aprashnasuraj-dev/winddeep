"""Tests for deterministic Brain finding prioritization."""

from app.brain.finding_ranker import FindingRanker


def test_score_uses_cvss_for_impact() -> None:
    ranked = FindingRanker().score(
        {"id": 1, "cvss_score": 9.0, "exploitability": 0.5, "confidence": 0.8}
    )
    assert ranked.impact == 0.9
    assert ranked.score == 36.0


def test_score_falls_back_to_severity() -> None:
    ranked = FindingRanker().score(
        {"severity": "high", "exploitability": 1.0, "confidence": 1.0}
    )
    assert ranked.impact == 0.85
    assert ranked.score == 85.0


def test_exploitability_is_reduced_by_constraints() -> None:
    ranker = FindingRanker()
    constrained = ranker.score(
        {
            "severity": "high",
            "confidence": 1.0,
            "requires_auth": True,
            "requires_two_accounts": True,
            "user_interaction": True,
            "attack_complexity": "high",
        }
    )
    simple = ranker.score(
        {"severity": "high", "confidence": 1.0, "attack_complexity": "low"}
    )
    assert constrained.exploitability < simple.exploitability


def test_explicit_factors_are_clamped() -> None:
    ranked = FindingRanker().score(
        {"severity": "critical", "exploitability": 3.0, "confidence": -2.0}
    )
    assert ranked.exploitability == 1.0
    assert ranked.confidence == 0.0
    assert ranked.score == 0.0


def test_rank_orders_highest_score_first() -> None:
    rows = FindingRanker().rank(
        [
            {"id": "low", "severity": "low", "exploitability": 0.4, "confidence": 0.4},
            {"id": "high", "severity": "critical", "exploitability": 0.9, "confidence": 0.9},
            {"id": "mid", "severity": "medium", "exploitability": 0.7, "confidence": 0.7},
        ]
    )
    assert [row.finding["id"] for row in rows] == ["high", "mid", "low"]


def test_verified_signal_increases_default_exploitability() -> None:
    ranker = FindingRanker()
    verified = ranker.score({"severity": "medium", "confidence": 1.0, "verified": True})
    unverified = ranker.score({"severity": "medium", "confidence": 1.0, "verified": False})
    assert verified.exploitability > unverified.exploitability
