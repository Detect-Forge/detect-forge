from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


def _make_report(
    *,
    rule_results=None,
    technique_rollups=None,
    rules_silent_on_all=0,
    priority_silent=0,
    priority_total=0,
):
    from detect_forge.backtest.models import BacktestReport, BacktestSummary
    now = datetime.now(UTC)
    s = BacktestSummary(
        rules_parsed=len(rule_results or []),
        rules_fires=0,
        rules_partial=0,
        rules_silent_on_all=rules_silent_on_all,
        rules_untested=0,
        rules_unsupported=0,
        techniques_in_scope=len(technique_rollups or []),
        techniques_verified=0,
        techniques_silent=0,
        techniques_untested=0,
        priority_total=priority_total,
        priority_verified=0,
        priority_silent=priority_silent,
        priority_untested=0,
        datasets_consulted=0,
        mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    return BacktestReport(
        summary=s,
        rule_results=rule_results or [],
        technique_rollups=technique_rollups or [],
    )


def test_terminal_render_empty_report_includes_headline() -> None:
    from detect_forge.backtest.reporter import render
    out = render(_make_report(), output_format="terminal")
    assert "Adversarial Backtest" in out


def test_terminal_render_shows_silent_on_all_count() -> None:
    from detect_forge.backtest.reporter import render
    out = render(_make_report(rules_silent_on_all=3), output_format="terminal")
    assert "Silent on all" in out
    assert "3" in out


def test_terminal_render_lists_silent_rules() -> None:
    from detect_forge.backtest.models import RuleResult
    from detect_forge.backtest.reporter import render
    rr = RuleResult(
        rule_id="r1", rule_title="Broken Rule",
        source_file=Path("/r/broken.yml"),
        rule_format="sigma", status="silent_on_all",
    )
    out = render(_make_report(rule_results=[rr], rules_silent_on_all=1), output_format="terminal")
    assert "Broken Rule" in out or "broken.yml" in out


def test_terminal_render_shows_priority_silent_when_present() -> None:
    from detect_forge.backtest.reporter import render
    out = render(
        _make_report(priority_silent=2, priority_total=10),
        output_format="terminal",
    )
    assert "Priority silent" in out or "priority silent" in out.lower()
    assert "2" in out


def test_terminal_render_technique_rollup_includes_priority_silent_critical() -> None:
    """Priority-silent technique rollup line includes the technique id + name + tactic."""
    from detect_forge.backtest.models import TechniqueRollup
    from detect_forge.backtest.reporter import render

    rollup = TechniqueRollup(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic_ids=["execution"],
        status="silent",
        is_priority=True,
        rules_tagged=3,
        rules_fired=0,
        datasets_available=2,
    )
    out = render(
        _make_report(technique_rollups=[rollup], priority_silent=1, priority_total=1),
        output_format="terminal",
    )
    assert "T1059.001" in out
    assert "PowerShell" in out
    assert "Execution" in out  # tactic name from lookup_tactic("execution") → "Execution"
    assert "3 rules tagged" in out
    assert "0 fired" in out


def test_terminal_render_unsupported_section() -> None:
    from detect_forge.backtest.models import RuleResult
    from detect_forge.backtest.reporter import render
    rr = RuleResult(
        rule_id="r1", rule_title="ESQL rule",
        source_file=Path("/r/esql.toml"),
        rule_format="elastic", status="unsupported",
        unsupported_reason="ES|QL matcher deferred to v0.2",
    )
    out = render(_make_report(rule_results=[rr]), output_format="terminal")
    assert "Unsupported" in out or "unsupported" in out.lower()
    assert "ES|QL" in out or "esql" in out.lower()


def test_json_render_is_valid_json_with_required_keys() -> None:
    import json

    from detect_forge.backtest.reporter import render
    out = render(_make_report(), output_format="json")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "rule_results" in parsed
    assert "technique_rollups" in parsed
    assert parsed["summary"]["attack_domain"] == "enterprise-attack"


def test_json_render_includes_rule_status_details() -> None:
    import json

    from detect_forge.backtest.models import RuleResult
    from detect_forge.backtest.reporter import render
    rr = RuleResult(
        rule_id="r1", rule_title="x", source_file=Path("/r.yml"),
        rule_format="sigma", status="silent_on_all",
    )
    out = render(_make_report(rule_results=[rr], rules_silent_on_all=1), output_format="json")
    parsed = json.loads(out)
    assert parsed["rule_results"][0]["status"] == "silent_on_all"


def test_json_render_unknown_format_raises() -> None:
    import pytest

    from detect_forge.backtest.reporter import render
    with pytest.raises(ValueError, match="unknown output_format"):
        render(_make_report(), output_format="ascii-art")


def test_html_render_includes_doctype_and_title() -> None:
    from detect_forge.backtest.reporter import render
    out = render(_make_report(), output_format="html")
    assert "<!DOCTYPE html>" in out
    assert "Detect-Forge Backtest Report" in out


def test_html_render_summary_stat_cards() -> None:
    from detect_forge.backtest.reporter import render
    out = render(_make_report(rules_silent_on_all=2), output_format="html")
    assert "Silent on all" in out or "silent_on_all" in out
    assert "2" in out


def test_html_render_silent_rule_cards() -> None:
    from detect_forge.backtest.models import RuleResult
    from detect_forge.backtest.reporter import render
    rr = RuleResult(
        rule_id="r1", rule_title="Broken",
        source_file=Path("/r/broken.yml"),
        rule_format="sigma", status="silent_on_all",
    )
    out = render(_make_report(rule_results=[rr], rules_silent_on_all=1), output_format="html")
    assert "Broken" in out or "broken.yml" in out


def test_html_render_unsupported_section_when_present() -> None:
    from detect_forge.backtest.models import RuleResult
    from detect_forge.backtest.reporter import render
    rr = RuleResult(
        rule_id="r1", rule_title="x",
        source_file=Path("/r.toml"),
        rule_format="elastic", status="unsupported",
        unsupported_reason="ES|QL",
    )
    out = render(_make_report(rule_results=[rr]), output_format="html")
    assert "Unsupported" in out
    assert "ES|QL" in out or "ES&#124;QL" in out


def test_navigator_render_emits_required_top_level_keys() -> None:
    import json

    from detect_forge.backtest.reporter import render
    out = render(_make_report(), output_format="navigator")
    parsed = json.loads(out)
    assert "domain" in parsed
    assert "versions" in parsed
    assert "techniques" in parsed
    assert parsed["domain"] == "enterprise-attack"


def test_navigator_render_maps_status_to_color() -> None:
    import json

    from detect_forge.backtest.models import TechniqueRollup
    from detect_forge.backtest.reporter import render
    verified = TechniqueRollup(
        technique_id="T1059.001", technique_name="PS", status="verified",
        rules_tagged=1, rules_fired=1, datasets_available=1,
    )
    silent = TechniqueRollup(
        technique_id="T1059.002", technique_name="AS", status="silent",
        rules_tagged=1, rules_fired=0, datasets_available=1,
    )
    untested = TechniqueRollup(
        technique_id="T1059.003", technique_name="WC", status="untested",
        rules_tagged=1, rules_fired=0, datasets_available=0,
    )
    priority_silent = TechniqueRollup(
        technique_id="T1078", technique_name="VA", status="silent",
        is_priority=True, rules_tagged=1, rules_fired=0, datasets_available=1,
    )
    rollups = [verified, silent, untested, priority_silent]
    out = render(
        _make_report(technique_rollups=rollups, priority_silent=1),
        output_format="navigator",
    )
    parsed = json.loads(out)
    by_id = {t["techniqueID"]: t for t in parsed["techniques"]}
    assert by_id["T1059.001"]["color"] == "#4caf50"  # verified
    assert by_id["T1059.002"]["color"] == "#f44336"  # silent
    assert by_id["T1059.003"]["color"] == "#9e9e9e"  # untested
    assert by_id["T1078"]["color"] == "#d32f2f"      # priority silent


def test_navigator_render_includes_legend_items() -> None:
    import json

    from detect_forge.backtest.reporter import render
    out = render(_make_report(), output_format="navigator")
    parsed = json.loads(out)
    labels = [item["label"] for item in parsed.get("legendItems", [])]
    assert any("verified" in lbl.lower() for lbl in labels)
    assert any("silent" in lbl.lower() for lbl in labels)


def test_navigator_render_priority_untested_uses_distinct_gray() -> None:
    import json

    from detect_forge.backtest.models import TechniqueRollup
    from detect_forge.backtest.reporter import render
    pu = TechniqueRollup(
        technique_id="T1078", technique_name="VA", status="untested",
        is_priority=True, rules_tagged=1, rules_fired=0, datasets_available=0,
    )
    out = render(_make_report(technique_rollups=[pu]), output_format="navigator")
    parsed = json.loads(out)
    by_id = {t["techniqueID"]: t for t in parsed["techniques"]}
    assert by_id["T1078"]["color"] == "#bdbdbd"
