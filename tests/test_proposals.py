from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pytest_mock import MockerFixture

from detect_forge.stale._proposals import (
    OPENAI_API_KEY_ENV,
    generate_proposal,
    render_prompt,
)
from detect_forge.stale.models import DetectionRule, DiffProposal


def _make_sigma_rule() -> DetectionRule:
    return DetectionRule(
        rule_id="abc-123",
        title="PowerShell Encoded Command",
        description="Detects encoded PS commands.",
        technique_ids=["T1059.001"],
        source_file=Path("/rules/ps.yml"),
        raw_tags=["attack.t1059.001"],
    )


def _make_elastic_rule() -> DetectionRule:
    return DetectionRule(
        rule_id="def-456",
        title="Suspicious IPC via Outlook",
        description="Detects IPC patterns via Outlook COM.",
        technique_ids=["T1114"],
        source_file=Path("/rules/outlook.toml"),
        raw_tags=[],
    )


def test_render_prompt_sigma_includes_yaml_marker() -> None:
    rule = _make_sigma_rule()
    prompt = render_prompt(
        rule=rule,
        original_rule_text="title: original\ndetection: ...\n",
        original_format="sigma",
        technique_id="T1059.001",
        technique_name="PowerShell",
        technique_description="Adversaries may abuse PowerShell.",
        similarity_score=0.42,
        threshold=0.65,
        today="2026/05/11",
    )
    assert "Rule format: sigma" in prompt
    assert "T1059.001" in prompt
    assert "PowerShell" in prompt
    assert "Adversaries may abuse PowerShell." in prompt
    assert "0.42" in prompt
    assert "title: original" in prompt
    assert "2026/05/11" in prompt


def test_render_prompt_elastic_signals_toml_format() -> None:
    rule = _make_elastic_rule()
    prompt = render_prompt(
        rule=rule,
        original_rule_text='[rule]\nname = "original"\n',
        original_format="elastic",
        technique_id="T1114",
        technique_name="Email Collection",
        technique_description="Adversaries may target email.",
        similarity_score=0.50,
        threshold=0.65,
        today="2026/05/11",
    )
    assert "Rule format: elastic" in prompt
    assert "TOML for Elastic" in prompt
    assert "T1114" in prompt


def test_generate_proposal_returns_diff_proposal_on_success(mocker: MockerFixture) -> None:
    """OpenAI client returns a parsed DiffProposal; generate_proposal forwards it."""
    fake_proposal = DiffProposal(
        proposed_rule="title: rewritten\nid: abc-123\n",
        explanation="Updated tags to match current T1059.001 scope.",
        changed_fields=["tags", "description"],
        confidence=0.78,
    )
    fake_completion = MagicMock()
    fake_completion.choices = [MagicMock()]
    fake_completion.choices[0].message.parsed = fake_proposal
    fake_completion.choices[0].message.refusal = None

    fake_client = MagicMock()
    fake_client.beta.chat.completions.parse.return_value = fake_completion
    mocker.patch(
        "detect_forge.stale._proposals.openai.OpenAI",
        return_value=fake_client,
    )

    rule = _make_sigma_rule()
    result = generate_proposal(
        rule=rule,
        original_rule_text="title: original\n",
        original_format="sigma",
        technique_id="T1059.001",
        technique_name="PowerShell",
        technique_description="Adversaries may abuse PowerShell.",
        similarity_score=0.42,
        threshold=0.65,
        llm_model="gpt-4o-mini",
        api_key="sk-test",
        today="2026/05/11",
    )
    assert result == fake_proposal
    fake_client.beta.chat.completions.parse.assert_called_once()
    call_kwargs = fake_client.beta.chat.completions.parse.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4o-mini"
    assert call_kwargs["response_format"] is DiffProposal


def test_generate_proposal_returns_none_on_refusal(mocker: MockerFixture) -> None:
    """If OpenAI refuses to respond, generate_proposal returns None."""
    fake_completion = MagicMock()
    fake_completion.choices = [MagicMock()]
    fake_completion.choices[0].message.parsed = None
    fake_completion.choices[0].message.refusal = "I cannot help with that."

    fake_client = MagicMock()
    fake_client.beta.chat.completions.parse.return_value = fake_completion
    mocker.patch(
        "detect_forge.stale._proposals.openai.OpenAI",
        return_value=fake_client,
    )

    rule = _make_sigma_rule()
    result = generate_proposal(
        rule=rule,
        original_rule_text="title: original\n",
        original_format="sigma",
        technique_id="T1059.001",
        technique_name="PowerShell",
        technique_description="Adversaries may abuse PowerShell.",
        similarity_score=0.42,
        threshold=0.65,
        llm_model="gpt-4o-mini",
        api_key="sk-test",
        today="2026/05/11",
    )
    assert result is None


def test_generate_proposal_returns_none_on_openai_exception(mocker: MockerFixture) -> None:
    """OpenAI API errors are caught and logged; function returns None."""
    fake_client = MagicMock()
    fake_client.beta.chat.completions.parse.side_effect = RuntimeError("API down")
    mocker.patch(
        "detect_forge.stale._proposals.openai.OpenAI",
        return_value=fake_client,
    )

    rule = _make_sigma_rule()
    result = generate_proposal(
        rule=rule,
        original_rule_text="title: original\n",
        original_format="sigma",
        technique_id="T1059.001",
        technique_name="PowerShell",
        technique_description="Adversaries may abuse PowerShell.",
        similarity_score=0.42,
        threshold=0.65,
        llm_model="gpt-4o-mini",
        api_key="sk-test",
        today="2026/05/11",
    )
    assert result is None


def test_openai_api_key_env_constant() -> None:
    assert OPENAI_API_KEY_ENV == "OPENAI_API_KEY"


def test_validate_sigma_proposal_accepts_valid_yaml() -> None:
    """A syntactically valid Sigma rule must validate."""
    from detect_forge.stale._proposals import validate_proposed_rule

    valid_sigma = """\
title: Valid Sigma Test
id: 11111111-2222-3333-4444-555555555555
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
    condition: selection
"""
    assert validate_proposed_rule(valid_sigma, "sigma") is True


def test_validate_sigma_proposal_rejects_invalid_yaml() -> None:
    """A YAML parsing failure or non-Sigma-shaped doc must fail validation."""
    from detect_forge.stale._proposals import validate_proposed_rule

    not_yaml = "this is not yaml :: at all ::\nbroken: ["
    assert validate_proposed_rule(not_yaml, "sigma") is False


def test_validate_sigma_proposal_rejects_yaml_without_title() -> None:
    """Sigma rules must have at minimum a title — pySigma's contract."""
    from detect_forge.stale._proposals import validate_proposed_rule

    no_title = "detection: { selection: {}, condition: selection }"
    assert validate_proposed_rule(no_title, "sigma") is False


def test_validate_elastic_proposal_accepts_valid_toml() -> None:
    from detect_forge.stale._proposals import validate_proposed_rule

    valid_elastic = """\
[metadata]
creation_date = "2024/01/01"

[rule]
name = "Valid Elastic Test"
rule_id = "abc"
"""
    assert validate_proposed_rule(valid_elastic, "elastic") is True


def test_validate_elastic_proposal_rejects_invalid_toml() -> None:
    from detect_forge.stale._proposals import validate_proposed_rule

    not_toml = "[unclosed bracket\nthis = is broken"
    assert validate_proposed_rule(not_toml, "elastic") is False


def test_validate_elastic_proposal_rejects_toml_without_rule_name() -> None:
    """An Elastic rule without rule.name fails our minimum-shape check."""
    from detect_forge.stale._proposals import validate_proposed_rule

    no_name = "[metadata]\n[rule]\nrule_id = \"x\"\n"
    assert validate_proposed_rule(no_name, "elastic") is False


def test_validate_unknown_format_returns_false() -> None:
    """Unknown format strings reject silently to keep callers simple."""
    from detect_forge.stale._proposals import validate_proposed_rule

    assert validate_proposed_rule("anything", "unknown") is False
