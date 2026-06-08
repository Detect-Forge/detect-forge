from __future__ import annotations

from datetime import UTC, datetime


def test_audit_summary_constructs_with_all_fields() -> None:
    """AuditSummary requires all summary fields; scores nullable."""
    from detect_forge.audit.models import AuditSummary

    s = AuditSummary(
        rules_scanned=31,
        stale_health=87,
        coverage_completeness=72,
        backtest_verification_rate=48,
        subcommands_ran=3,
        subcommands_skipped=0,
        subcommands_errored=0,
        audit_would_gate=True,
        attack_domain="enterprise-attack",
        generated_at=datetime.now(UTC),
        elapsed_seconds=4.2,
    )
    assert s.audit_would_gate is True


def test_audit_sub_result_allows_only_one_report_kind() -> None:
    """AuditSubResult with status='ran' carries exactly the matching report."""
    from detect_forge.audit.models import AuditSubResult
    from detect_forge.coverage.models import CoverageReport, CoverageSummary

    cov_summary = CoverageSummary(
        total_techniques=10, full=5, shallow=2, gap=3,
        priority_total=2, priority_full=1, priority_shallow=0, priority_gap=1,
        rules_parsed=10, rules_with_unknown_tags=0, migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    )
    cov_report = CoverageReport(summary=cov_summary)
    sr = AuditSubResult(
        subcommand="coverage", status="ran", would_gate=True,
        score=50, coverage_report=cov_report,
    )
    assert sr.coverage_report is cov_report
    assert sr.stale_report is None
    assert sr.backtest_report is None


def test_audit_sub_result_errored_status_carries_error_text() -> None:
    """status='errored' populates error; the report fields stay None."""
    from detect_forge.audit.models import AuditSubResult

    sr = AuditSubResult(
        subcommand="stale", status="errored",
        error="RuntimeError: cache directory missing",
    )
    assert sr.error == "RuntimeError: cache directory missing"
    assert sr.stale_report is None
    assert sr.score is None
    assert sr.would_gate is False


def test_audit_report_roundtrips_through_json() -> None:
    """AuditReport.model_dump_json() round-trips through model_validate_json()."""
    from detect_forge.audit.models import AuditReport, AuditSubResult, AuditSummary

    summary = AuditSummary(
        rules_scanned=0, stale_health=None, coverage_completeness=None,
        backtest_verification_rate=None, subcommands_ran=0,
        subcommands_skipped=3, subcommands_errored=0,
        audit_would_gate=False, attack_domain="enterprise-attack",
        generated_at=datetime.now(UTC), elapsed_seconds=0.0,
    )
    sub_results = [
        AuditSubResult(subcommand="stale", status="skipped"),
        AuditSubResult(subcommand="coverage", status="skipped"),
        AuditSubResult(subcommand="backtest", status="skipped"),
    ]
    original = AuditReport(summary=summary, sub_results=sub_results)
    payload = original.model_dump_json()
    restored = AuditReport.model_validate_json(payload)
    assert restored.summary.rules_scanned == 0
    assert len(restored.sub_results) == 3
