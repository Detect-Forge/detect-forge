from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest


def test_technique_result_minimal_construction() -> None:
    from detect_forge.backtest.models import TechniqueResult

    tr = TechniqueResult(
        rule_id="r1",
        rule_title="Test Rule",
        technique_id="T1059",
        status="silent",
        datasets_tested=1,
        datasets_fired=0,
    )
    assert tr.status == "silent"
    assert tr.fires == []


def test_technique_result_rejects_unknown_fire_status() -> None:
    from detect_forge.backtest.models import TechniqueResult

    with pytest.raises(ValueError):
        TechniqueResult(
            rule_id="r1",
            rule_title="x",
            technique_id="T1059",
            status="totally-broken",  # type: ignore[arg-type]
            datasets_tested=0,
            datasets_fired=0,
        )


def test_rule_result_rejects_unknown_rule_status() -> None:
    from detect_forge.backtest.models import RuleResult

    with pytest.raises(ValueError):
        RuleResult(
            rule_id="r1",
            rule_title="x",
            source_file=Path("/r.yml"),
            rule_format="sigma",
            status="invalid",  # type: ignore[arg-type]
        )


def test_backtest_summary_required_fields() -> None:
    from detect_forge.backtest.models import BacktestSummary

    now = datetime.now(UTC)
    s = BacktestSummary(
        rules_parsed=10,
        rules_fires=5,
        rules_partial=1,
        rules_silent_on_all=2,
        rules_untested=1,
        rules_unsupported=1,
        techniques_in_scope=15,
        techniques_verified=8,
        techniques_silent=3,
        techniques_untested=4,
        priority_total=25,
        priority_verified=10,
        priority_silent=5,
        priority_untested=10,
        datasets_consulted=47,
        mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    assert s.priority_silent == 5
    assert s.rules_silent_on_all == 2


def test_backtest_report_defaults_to_empty_lists() -> None:
    from detect_forge.backtest.models import BacktestReport, BacktestSummary

    now = datetime.now(UTC)
    summary = BacktestSummary(
        rules_parsed=0, rules_fires=0, rules_partial=0,
        rules_silent_on_all=0, rules_untested=0, rules_unsupported=0,
        techniques_in_scope=0, techniques_verified=0,
        techniques_silent=0, techniques_untested=0,
        priority_total=0, priority_verified=0,
        priority_silent=0, priority_untested=0,
        datasets_consulted=0, mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=now, generated_at=now,
    )
    report = BacktestReport(summary=summary)
    assert report.rule_results == []
    assert report.technique_rollups == []
