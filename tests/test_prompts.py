"""Contract tests for Windeep Brain prompt templates."""

from app.brain import prompts


def test_hypothesis_prompt_requires_json_and_context_marker() -> None:
    value = prompts.HYPOTHESIS_GEN_PROMPT
    assert "Return JSON only" in value
    assert '"hypotheses"' in value
    assert '"confidence"' in value
    assert "{context_json}" in value


def test_payload_prompt_is_non_destructive() -> None:
    value = prompts.PAYLOAD_SYNTH_PROMPT
    assert "non-destructive" in value
    assert "benign unique marker" in value
    assert "credential theft" in value
    assert '"probes"' in value


def test_chain_prompt_distinguishes_relationship_from_proof() -> None:
    value = prompts.CHAIN_BUILDER_PROMPT
    assert "not proof of exploitation" in value
    assert '"edges"' in value
    assert '"weight"' in value


def test_report_prompt_requires_limit_and_verified_evidence() -> None:
    value = prompts.REPORT_WRITER_PROMPT
    assert "verified supplied evidence" in value
    assert '"limitations"' in value
    assert '"impact"' in value


def test_self_critic_prompt_has_pass_fail_schema() -> None:
    value = prompts.SELF_CRITIC_PROMPT
    assert '"decision": "PASS|FAIL"' in value
    assert "outside scope" in value
    assert "scanner-only" in value


def test_impact_prompt_separates_demonstrated_from_unverified() -> None:
    value = prompts.IMPACT_NARRATOR_PROMPT
    assert '"demonstrated"' in value
    assert '"not_demonstrated"' in value
    assert "Never upgrade possibility" in value


def test_rejection_prompt_generalizes_lessons() -> None:
    value = prompts.REJECTION_LEARNER_PROMPT
    assert "without storing secrets or personal data" in value
    assert '"lessons"' in value
    assert '"future_check"' in value
