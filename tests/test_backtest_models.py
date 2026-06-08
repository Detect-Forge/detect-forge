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


def test_matcher_protocol_signature() -> None:
    """Matcher protocol has supports() and match()."""
    import inspect

    from detect_forge.backtest.matchers._base import Matcher

    members = dict(inspect.getmembers(Matcher))
    assert "supports" in members
    assert "match" in members


def test_select_matcher_routes_by_suffix(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from pathlib import Path

    from detect_forge.backtest.matchers._base import select_matcher
    from detect_forge.stale.models import DetectionRule

    sigma_rule = DetectionRule(
        title="s",
        technique_ids=["T1059"],
        source_file=Path("/r.yml"),
        raw_tags=[],
    )
    elastic_rule = DetectionRule(
        title="e",
        technique_ids=["T1059"],
        source_file=Path("/r.toml"),
        raw_tags=[],
    )
    _, fmt_sigma = select_matcher(sigma_rule)
    _, fmt_elastic = select_matcher(elastic_rule)
    assert fmt_sigma == "sigma"
    assert fmt_elastic == "elastic"


def test_public_api_exports_include_required_symbols() -> None:
    from detect_forge import backtest

    expected = {
        "BacktestReport", "BacktestSummary",
        "FireRecord", "FireStatus",
        "RuleResult", "RuleStatus",
        "TechniqueResult", "TechniqueRollup", "TechniqueStatus",
        "scan_backtest",
    }
    assert expected.issubset(set(backtest.__all__))
    for name in expected:
        assert hasattr(backtest, name)


def test_scan_backtest_signature_has_required_kwargs() -> None:
    import inspect

    from detect_forge.backtest import scan_backtest

    params = inspect.signature(scan_backtest).parameters
    for required in [
        "rule_dir", "domain", "cache_dir", "cache_ttl_hours", "no_cache",
        "priority_list", "platform", "technique_filter", "mordor_source",
    ]:
        assert required in params, f"missing kwarg: {required}"


def test_scan_backtest_rejects_invalid_platform() -> None:
    """Invalid platform values fail loud rather than silently producing zero fires."""
    from detect_forge.backtest import scan_backtest

    with pytest.raises(ValueError, match="platform must be one of"):
        scan_backtest(Path("/nonexistent"), platform="freebsd")


def test_scan_backtest_empty_rule_dir_returns_zero_report(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """An empty rule directory produces a valid BacktestReport with all-zero counters."""
    from unittest.mock import patch

    from detect_forge.backtest import scan_backtest

    # Mock build_index and MordorCorpus to avoid network/IO. We use real
    # parse_rule_dir, which returns [] for an empty directory, exercising the
    # downstream orchestrator path.
    with (
        patch("detect_forge.backtest.build_index") as mock_build_index,
        patch("detect_forge.backtest.MordorCorpus") as mock_corpus_cls,
    ):
        from datetime import UTC, datetime

        from detect_forge.stale.models import AttackIndex

        mock_build_index.return_value = AttackIndex(
            techniques={}, fetched_at=datetime.now(UTC),
        )
        mock_corpus = mock_corpus_cls.return_value
        mock_corpus.datasets_for.return_value = []
        mock_corpus.datasets_consulted.return_value = 0
        mock_corpus.source_label.return_value = "empty"

        report = scan_backtest(tmp_path)

    assert report.summary.rules_parsed == 0
    assert report.summary.rules_fires == 0
    assert report.summary.rules_silent_on_all == 0
    assert report.summary.rules_untested == 0
    assert report.rule_results == []
    assert report.technique_rollups == []
