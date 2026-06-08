from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pytest_mock import MockerFixture


def _make_stale(critical: int = 0):  # type: ignore[no-untyped-def]
    from detect_forge.stale.models import ReportSummary, StalenessReport
    return StalenessReport(summary=ReportSummary(
        total_rules=10, rules_with_findings=critical, critical=critical,
        high=0, medium=0, low=0, no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC), attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    ))


def _make_coverage(priority_gap: int = 0):  # type: ignore[no-untyped-def]
    from detect_forge.coverage.models import CoverageReport, CoverageSummary
    return CoverageReport(summary=CoverageSummary(
        total_techniques=10, full=8, shallow=0, gap=2,
        priority_total=2, priority_full=2-priority_gap, priority_shallow=0,
        priority_gap=priority_gap,
        rules_parsed=10, rules_with_unknown_tags=0, migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    ))


def _make_backtest(priority_silent: int = 0, silent_on_all: int = 0):  # type: ignore[no-untyped-def]
    from detect_forge.backtest.models import BacktestReport, BacktestSummary
    return BacktestReport(summary=BacktestSummary(
        rules_parsed=10, rules_fires=10, rules_partial=0,
        rules_silent_on_all=silent_on_all, rules_untested=0,
        rules_unsupported=0,
        techniques_in_scope=10, techniques_verified=10,
        techniques_silent=0, techniques_untested=0,
        priority_total=2, priority_verified=2-priority_silent,
        priority_silent=priority_silent, priority_untested=0,
        datasets_consulted=0, mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    ))


def test_run_audit_all_pass_no_gate(mocker: MockerFixture, tmp_path: Path) -> None:
    """All 3 subcommands clean → audit_would_gate False, exit code 0."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 return_value=_make_stale(critical=0))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=0))
    mocker.patch("detect_forge.audit.orchestrator.scan_backtest",
                 return_value=_make_backtest())
    rules_dir = tmp_path
    report = run_audit(rules_dir, enabled={"stale", "coverage", "backtest"})

    assert report.summary.audit_would_gate is False
    assert report.summary.subcommands_ran == 3
    assert report.summary.subcommands_errored == 0


def test_run_audit_gate_fires_when_all_three_gate(
    mocker: MockerFixture, tmp_path: Path,
) -> None:
    """All 3 standalone gates fire → audit gate fires (strict-AND)."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 return_value=_make_stale(critical=3))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=2))
    mocker.patch("detect_forge.audit.orchestrator.scan_backtest",
                 return_value=_make_backtest(priority_silent=1))
    report = run_audit(tmp_path, enabled={"stale", "coverage", "backtest"})

    assert report.summary.audit_would_gate is True
    for sr in report.sub_results:
        assert sr.would_gate is True


def test_run_audit_gate_silent_when_only_two_gate(
    mocker: MockerFixture, tmp_path: Path,
) -> None:
    """Strict-AND: 2 of 3 firing → audit gate does NOT fire."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 return_value=_make_stale(critical=3))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=0))  # CLEAN
    mocker.patch("detect_forge.audit.orchestrator.scan_backtest",
                 return_value=_make_backtest(priority_silent=1))
    report = run_audit(tmp_path, enabled={"stale", "coverage", "backtest"})

    assert report.summary.audit_would_gate is False


def test_run_audit_skipped_subcommands_dont_count_for_gate(
    mocker: MockerFixture, tmp_path: Path,
) -> None:
    """Only enabled subcommands count for the strict-AND. Skipped = not enabled."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 return_value=_make_stale(critical=3))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=2))
    report = run_audit(tmp_path, enabled={"stale", "coverage"})

    assert report.summary.subcommands_ran == 2
    assert report.summary.subcommands_skipped == 1
    # Both enabled gate → audit gates
    assert report.summary.audit_would_gate is True
    # Backtest entry exists but is marked skipped
    backtest_entry = next(sr for sr in report.sub_results if sr.subcommand == "backtest")
    assert backtest_entry.status == "skipped"


def test_run_audit_failure_isolation_one_errored(
    mocker: MockerFixture, tmp_path: Path,
) -> None:
    """A crashing subcommand doesn't suppress the others."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 side_effect=RuntimeError("cache missing"))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=0))
    mocker.patch("detect_forge.audit.orchestrator.scan_backtest",
                 return_value=_make_backtest())
    report = run_audit(tmp_path, enabled={"stale", "coverage", "backtest"})

    assert report.summary.subcommands_errored == 1
    assert report.summary.subcommands_ran == 2
    # Errored subcommand can't gate → strict-AND can't be all-true
    assert report.summary.audit_would_gate is False
    stale_entry = next(sr for sr in report.sub_results if sr.subcommand == "stale")
    assert stale_entry.status == "errored"
    assert "RuntimeError" in (stale_entry.error or "")
    assert "cache missing" in (stale_entry.error or "")


def test_run_audit_gate_strategy_never_overrides_to_false(
    mocker: MockerFixture, tmp_path: Path,
) -> None:
    """gate_strategy='never' overrides even when all subcommands gate."""
    from detect_forge.audit.orchestrator import run_audit

    mocker.patch("detect_forge.audit.orchestrator.scan_stale",
                 return_value=_make_stale(critical=3))
    mocker.patch("detect_forge.audit.orchestrator.scan_coverage",
                 return_value=_make_coverage(priority_gap=2))
    mocker.patch("detect_forge.audit.orchestrator.scan_backtest",
                 return_value=_make_backtest(priority_silent=1))
    report = run_audit(
        tmp_path,
        enabled={"stale", "coverage", "backtest"},
        gate_strategy="never",
    )

    assert report.summary.audit_would_gate is False
