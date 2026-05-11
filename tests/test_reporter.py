from __future__ import annotations

import json

import pytest

from detect_forge.stale.reporter import render


def test_json_render_parses_as_json(sample_report) -> None:
    out = render(sample_report, output_format="json", min_severity="low")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "scores" in parsed


def test_html_render_contains_doctype_and_title(sample_report) -> None:
    out = render(sample_report, output_format="html", min_severity="low")
    assert "<!DOCTYPE html>" in out
    assert "Detect-Forge Stale Report" in out


def test_html_render_shows_summary_counts(sample_report) -> None:
    out = render(sample_report, output_format="html", min_severity="low")
    # The summary stats block shows total_rules=5 and the domain name.
    assert "5" in out
    assert "enterprise-attack" in out


def test_html_render_includes_rule_rows(sample_report) -> None:
    out = render(sample_report, output_format="html", min_severity="low")
    assert "Critical Test Rule" in out
    assert "T1059" in out
    assert "badge-critical" in out


def test_html_render_filters_by_min_severity(sample_report) -> None:
    out = render(sample_report, output_format="html", min_severity="high")
    assert "Critical Test Rule" in out
    assert "High Test Rule" in out
    assert "Medium Test Rule" not in out
    assert "Low Test Rule" not in out


def test_unknown_format_raises(sample_report) -> None:
    with pytest.raises(ValueError):
        render(sample_report, output_format="xml", min_severity="low")


def test_filter_scores_drops_below_threshold(sample_report) -> None:
    from detect_forge.stale.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "high")
    severities = {s.worst_severity for s in filtered.scores}
    assert severities <= {"critical", "high"}
    # The original report is not mutated.
    assert len(sample_report.scores) == 5


def test_filter_scores_info_threshold_keeps_all(sample_report) -> None:
    from detect_forge.stale.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "info")
    assert len(filtered.scores) == len(sample_report.scores)


def test_filter_scores_raises_on_unknown_level(sample_report) -> None:
    import pytest

    from detect_forge.stale.reporter import _filter_scores

    with pytest.raises(KeyError):
        _filter_scores(sample_report, "extreme")


def test_json_filters_by_min_severity(sample_report) -> None:
    output = render(sample_report, output_format="json", min_severity="high")
    data = json.loads(output)
    returned_severities = {s["worst_severity"] for s in data["scores"]}
    assert returned_severities <= {"critical", "high"}
    assert len(data["scores"]) == 2


def test_json_summary_unchanged_by_filter(sample_report) -> None:
    """The filter drops scores; summary counters stay authoritative."""
    output = render(sample_report, output_format="json", min_severity="critical")
    data = json.loads(output)
    # Summary reflects the ORIGINAL counts — not the filtered scores.
    assert data["summary"]["total_rules"] == 5
    assert data["summary"]["critical"] == 1


def test_terminal_render_contains_rule_titles(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    assert "Critical Test Rule" in out
    assert "High Test Rule" in out
    assert "Medium Test Rule" in out


def test_terminal_render_contains_summary(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    # Summary panel mentions the CRITICAL count and domain.
    assert "CRITICAL" in out
    assert "5" in out  # total_rules
    assert "enterprise-attack" in out


def test_terminal_render_has_no_rich_markup_leaks(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="low")
    # Style markers must not appear as literal text.
    assert "[critical]" not in out
    assert "[/critical]" not in out
    assert "[high]" not in out


def test_terminal_filters_by_min_severity(sample_report) -> None:
    out = render(sample_report, output_format="terminal", min_severity="high")
    assert "Critical Test Rule" in out
    assert "High Test Rule" in out
    # Below-threshold rules must not appear in the table.
    assert "Medium Test Rule" not in out
    assert "Low Test Rule" not in out


def test_html_renders_unicode_em_dash_not_entity_reference(sample_report) -> None:
    """Regression: with autoescape=True, a literal `&mdash;` string becomes
    `&amp;mdash;` in output (browsers render the literal text). Use the
    Unicode em-dash character instead so it passes through unchanged.
    """
    out = render(sample_report, output_format="html", min_severity="low")
    # The double-escaped form must NOT appear.
    assert "&amp;mdash;" not in out
    # The current Rule (low severity, days_stale=0, kind=current) should
    # display an em-dash in the Days Stale column.
    assert "—" in out  # U+2014


def test_terminal_report_omits_similarity_column_without_semantic_findings(
    sample_report,
) -> None:
    """No semantic_drift findings → no Similarity column header."""
    from detect_forge.stale.reporter import render

    output = render(sample_report, output_format="terminal", min_severity="info")
    assert "Similarity" not in output


def test_terminal_report_shows_similarity_column_with_semantic_findings() -> None:
    """At least one semantic_drift finding → Similarity column appears with the score."""
    from datetime import UTC, datetime
    from pathlib import Path

    from detect_forge.stale.models import (
        ReportSummary,
        RuleScore,
        StalenessReport,
        TechniqueFinding,
    )
    from detect_forge.stale.reporter import render

    finding = TechniqueFinding(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        technique_modified=datetime(2025, 1, 1, tzinfo=UTC),
        rule_effective_date=None,
        days_stale=0,
        severity="medium",
        kind="semantic_drift",
        similarity_score=0.42,
    )
    score = RuleScore(
        rule_id="r1",
        title="Misaligned Rule",
        source_file=Path("/rules/r.yml"),
        status="stable",
        findings=[finding],
        worst_severity="medium",
        worst_days_stale=0,
        has_attack_tags=True,
    )
    summary = ReportSummary(
        total_rules=1, rules_with_findings=1,
        critical=0, high=0, medium=1, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    report = StalenessReport(summary=summary, scores=[score])

    output = render(report, output_format="terminal", min_severity="info")
    assert "Similarity" in output
    assert "0.42" in output


def test_json_output_unconditionally_includes_similarity_score(sample_report) -> None:
    """JSON serializes similarity_score on every finding (null on non-semantic)."""
    import json

    from detect_forge.stale.reporter import render

    output = render(sample_report, output_format="json", min_severity="info")
    data = json.loads(output)
    # sample_report has no semantic_drift findings, but the field must still
    # appear with null on every finding for forward compatibility.
    for score in data["scores"]:
        for finding in score["findings"]:
            assert "similarity_score" in finding
            assert finding["similarity_score"] is None


def test_terminal_report_omits_proposals_section_when_none_present(
    sample_report,
) -> None:
    """A report with no proposals doesn't add any LLM Proposal panel."""
    from detect_forge.stale.reporter import render

    output = render(sample_report, output_format="terminal", min_severity="info")
    assert "LLM Diff Proposal" not in output


def test_terminal_report_renders_proposal_when_present() -> None:
    """A proposal on a RuleScore should appear as a Rich panel + YAML body."""
    from datetime import UTC, datetime
    from pathlib import Path

    from detect_forge.stale.models import (
        DiffProposal,
        ReportSummary,
        RuleScore,
        StalenessReport,
    )
    from detect_forge.stale.reporter import render

    proposal = DiffProposal(
        proposed_rule="title: Rewritten Test Rule\nid: abc\n",
        explanation="Updated the description to reflect T1059.001.",
        changed_fields=["description"],
        confidence=0.84,
    )
    score = RuleScore(
        rule_id="r1",
        title="Test Rule",
        source_file=Path("/rules/r.yml"),
        status="stable",
        findings=[],
        worst_severity="medium",
        worst_days_stale=0,
        has_attack_tags=True,
        proposals=[proposal],
    )
    summary = ReportSummary(
        total_rules=1, rules_with_findings=1,
        critical=0, high=0, medium=1, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    report = StalenessReport(summary=summary, scores=[score])

    output = render(report, output_format="terminal", min_severity="info")
    assert "LLM Diff Proposal" in output
    assert "Test Rule" in output
    assert "0.84" in output
    assert "description" in output
    assert "Rewritten Test Rule" in output


def test_terminal_proposal_uses_toml_syntax_for_elastic_rules() -> None:
    """A proposal on an Elastic .toml rule renders the body with TOML highlighting."""
    from datetime import UTC, datetime
    from pathlib import Path

    from detect_forge.stale.models import (
        DiffProposal,
        ReportSummary,
        RuleScore,
        StalenessReport,
    )
    from detect_forge.stale.reporter import render

    proposal = DiffProposal(
        proposed_rule='[rule]\nname = "Rewritten Elastic"\n',
        explanation="x",
        changed_fields=[],
        confidence=0.7,
    )
    score = RuleScore(
        rule_id="r1",
        title="Test Elastic",
        source_file=Path("/rules/r.toml"),
        status="production",
        findings=[],
        worst_severity="medium",
        worst_days_stale=0,
        has_attack_tags=True,
        proposals=[proposal],
    )
    summary = ReportSummary(
        total_rules=1, rules_with_findings=1,
        critical=0, high=0, medium=1, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    report = StalenessReport(summary=summary, scores=[score])

    output = render(report, output_format="terminal", min_severity="info")
    assert "Rewritten Elastic" in output


def test_terminal_proposal_filtered_when_below_min_severity() -> None:
    """A proposal attached to a low-severity rule is filtered when min_severity=critical."""
    from datetime import UTC, datetime
    from pathlib import Path

    from detect_forge.stale.models import (
        DiffProposal,
        ReportSummary,
        RuleScore,
        StalenessReport,
    )
    from detect_forge.stale.reporter import render

    proposal = DiffProposal(
        proposed_rule="title: Below-Threshold Proposal\n",
        explanation="should be filtered",
        changed_fields=[],
        confidence=0.5,
    )
    # worst_severity="medium" is below "critical".
    score = RuleScore(
        rule_id="r1",
        title="Medium Severity Rule",
        source_file=Path("/rules/r.yml"),
        status="stable",
        findings=[],
        worst_severity="medium",
        worst_days_stale=0,
        has_attack_tags=True,
        proposals=[proposal],
    )
    summary = ReportSummary(
        total_rules=1, rules_with_findings=1,
        critical=0, high=0, medium=1, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    report = StalenessReport(summary=summary, scores=[score])

    output = render(report, output_format="terminal", min_severity="critical")
    assert "Below-Threshold Proposal" not in output
    assert "LLM Diff Proposal" not in output


def test_terminal_proposal_rendered_when_score_meets_min_severity() -> None:
    """When the score's severity meets the threshold, the proposal still renders."""
    from datetime import UTC, datetime
    from pathlib import Path

    from detect_forge.stale.models import (
        DiffProposal,
        ReportSummary,
        RuleScore,
        StalenessReport,
    )
    from detect_forge.stale.reporter import render

    proposal = DiffProposal(
        proposed_rule="title: High Severity Rewrite\n",
        explanation="visible at high threshold",
        changed_fields=["description"],
        confidence=0.9,
    )
    score = RuleScore(
        rule_id="r2",
        title="High Severity Rule",
        source_file=Path("/rules/h.yml"),
        status="stable",
        findings=[],
        worst_severity="high",
        worst_days_stale=200,
        has_attack_tags=True,
        proposals=[proposal],
    )
    summary = ReportSummary(
        total_rules=1, rules_with_findings=1,
        critical=0, high=1, medium=0, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    report = StalenessReport(summary=summary, scores=[score])

    output = render(report, output_format="terminal", min_severity="high")
    assert "High Severity Rewrite" in output
    assert "LLM Diff Proposal" in output
