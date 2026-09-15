"""P7 release contract for the Windeep platform threat model."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v3_threat_model_covers_required_platform_threats() -> None:
    text = (ROOT / "docs" / "threat_model.md").read_text(encoding="utf-8")
    required = (
        "Prompt injection from malicious target content",
        "Artifact path traversal",
        "SSRF against the loopback control plane",
        "Compromised tool binary",
        "Leaked master key",
        "Operator-supplied redaction regex DoS",
        "Authorization-diff session misuse",
        "Web3 write-RPC escalation",
        "Crash-resume state confusion",
        "Slow-client backpressure",
        "Plaintext temp or orphan-process leakage",
    )
    for heading in required:
        assert heading in text
    assert text.count("**Threat.**") >= len(required)
    assert text.count("**Mitigation.**") >= len(required)
    assert text.count("**Tests.**") >= len(required)
    assert text.count("**Residual risk.**") >= len(required)


def test_threat_model_reflects_p1_as_landed_not_skipped() -> None:
    text = (ROOT / "docs" / "threat_model.md").read_text(encoding="utf-8").casefold()
    assert "p1 remains skipped" not in text
    assert "skipped p1" not in text
    assert "p1 forensic capture" in text


def test_every_required_threat_section_names_a_concrete_test_surface() -> None:
    text = (ROOT / "docs" / "threat_model.md").read_text(encoding="utf-8")
    required_files = (
        "test_p1_forensic_capture.py",
        "test_p4_hard_middle.py",
        "test_p5_web3_depth.py",
        "test_p6_operational.py",
        "test_p6_operational_depth.py",
    )
    for name in required_files:
        assert name in text


def test_p7_cannot_close_with_placeholder_or_uncovered_attack_surface() -> None:
    text = (ROOT / "docs" / "threat_model.md").read_text(encoding="utf-8").casefold()
    forbidden = ("todo threat", "tbd mitigation", "residual risk: none", "no residual risk")
    assert all(token not in text for token in forbidden)
    assert "phase cannot close" in text
    assert "uncovered threat" in text
