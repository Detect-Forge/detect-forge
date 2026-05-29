from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest


def test_technique_coverage_minimal_construction() -> None:
    from detect_forge.coverage.models import TechniqueCoverage

    tc = TechniqueCoverage(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        is_subtechnique=False,
        state="gap",
    )
    assert tc.state == "gap"
    assert tc.rule_count == 0
    assert tc.rule_sources == []
    assert tc.is_priority is False
    assert tc.parent_id is None
    assert tc.tactic_ids == []


def test_technique_coverage_rejects_unknown_state() -> None:
    from detect_forge.coverage.models import TechniqueCoverage

    with pytest.raises(ValueError):
        TechniqueCoverage(
            technique_id="T1059",
            technique_name="x",
            is_subtechnique=False,
            state="not-a-state",  # type: ignore[arg-type]
        )


def test_tactic_rollup_construction() -> None:
    from detect_forge.coverage.models import TacticRollup

    r = TacticRollup(
        tactic_id="TA0002",
        tactic_name="Execution",
        total_techniques=14,
        full_count=5,
        shallow_count=2,
        gap_count=7,
        priority_gap_count=2,
    )
    assert r.gap_count == 7


def test_migration_item_replacement_id_optional() -> None:
    from detect_forge.coverage.models import MigrationItem

    m = MigrationItem(
        rule_source=Path("/rules/old.yml"),
        rule_title="Old Rule",
        deprecated_technique_id="T1086",
        reason="revoked",
    )
    assert m.replacement_id is None


def test_coverage_summary_required_fields() -> None:
    from detect_forge.coverage.models import CoverageSummary

    now = datetime.now(UTC)
    s = CoverageSummary(
        total_techniques=200,
        full=10,
        shallow=5,
        gap=185,
        priority_total=25,
        priority_full=3,
        priority_shallow=2,
        priority_gap=20,
        rules_parsed=31,
        rules_with_unknown_tags=2,
        migrations_needed=1,
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    assert s.priority_gap == 20


def test_coverage_report_aggregates_components() -> None:
    from detect_forge.coverage.models import (
        CoverageReport,
        CoverageSummary,
    )

    now = datetime.now(UTC)
    summary = CoverageSummary(
        total_techniques=0,
        full=0,
        shallow=0,
        gap=0,
        priority_total=0,
        priority_full=0,
        priority_shallow=0,
        priority_gap=0,
        rules_parsed=0,
        rules_with_unknown_tags=0,
        migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    report = CoverageReport(
        summary=summary,
        techniques=[],
        tactic_rollups=[],
        migrations=[],
    )
    assert report.summary.priority_gap == 0
    assert report.techniques == []


def test_public_api_exports_include_required_symbols() -> None:
    from detect_forge import coverage

    expected = {
        "CoverageReport",
        "CoverageState",
        "CoverageSummary",
        "MigrationItem",
        "TacticRollup",
        "TechniqueCoverage",
        "scan_coverage",
    }
    assert expected.issubset(set(coverage.__all__))
    # And all are actually importable.
    for name in expected:
        assert hasattr(coverage, name)


def test_scan_coverage_signature_has_required_kwargs() -> None:
    import inspect

    from detect_forge.coverage import scan_coverage

    params = inspect.signature(scan_coverage).parameters
    assert "rule_dir" in params
    assert "domain" in params
    assert "cache_dir" in params
    assert "cache_ttl_hours" in params
    assert "no_cache" in params
    assert "priority_list" in params
