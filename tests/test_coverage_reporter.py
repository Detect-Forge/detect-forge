from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from detect_forge.coverage.models import (
    CoverageReport,
    CoverageSummary,
    TechniqueCoverage,
)


# --------------------------------------------------------------------- helper
def _make_report(
    *,
    techniques: list[TechniqueCoverage] | None = None,
    tactic_rollups: list | None = None,
    migrations: list | None = None,
    priority_gap: int = 0,
) -> CoverageReport:
    techs = techniques or []
    now = datetime.now(UTC)
    summary = CoverageSummary(
        total_techniques=len(techs),
        full=sum(1 for t in techs if t.state == "full"),
        shallow=sum(1 for t in techs if t.state == "shallow"),
        gap=sum(1 for t in techs if t.state == "gap"),
        priority_total=sum(1 for t in techs if t.is_priority),
        priority_full=sum(1 for t in techs if t.is_priority and t.state == "full"),
        priority_shallow=sum(
            1 for t in techs if t.is_priority and t.state == "shallow"
        ),
        priority_gap=priority_gap,
        rules_parsed=0,
        rules_with_unknown_tags=0,
        migrations_needed=len(migrations or []),
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    return CoverageReport(
        summary=summary,
        techniques=techs,
        tactic_rollups=tactic_rollups or [],
        migrations=migrations or [],
    )


def _make_technique(
    *,
    technique_id: str = "T1059",
    state: str = "gap",
    is_priority: bool = False,
    tactic_ids: list[str] | None = None,
    is_sub: bool = False,
    rule_sources: list[Path] | None = None,
) -> TechniqueCoverage:
    return TechniqueCoverage(
        technique_id=technique_id,
        technique_name=f"Name for {technique_id}",
        is_subtechnique=is_sub,
        tactic_ids=tactic_ids or [],
        state=state,  # type: ignore[arg-type]
        rule_count=len(rule_sources or []),
        rule_sources=rule_sources or [],
        is_priority=is_priority,
    )


# --------------------------------------------------------------------- tests
def test_terminal_render_empty_report_includes_headline() -> None:
    from detect_forge.coverage.reporter import render

    report = _make_report()
    out = render(report, output_format="terminal")
    assert "ATT&CK Coverage" in out
    assert "Techniques in scope:" in out


def test_terminal_render_shows_priority_gap_count_when_present() -> None:
    from detect_forge.coverage.reporter import render

    tech = _make_technique(technique_id="T1078", state="gap", is_priority=True)
    report = _make_report(techniques=[tech], priority_gap=1)
    out = render(report, output_format="terminal")
    assert "Priority GAPS: 1" in out or "Priority GAPS:1" in out or "PRIORITY GAPS" in out.upper()


def test_terminal_render_shows_tactic_rollup_table() -> None:
    from detect_forge.coverage.models import TacticRollup
    from detect_forge.coverage.reporter import render

    rollup = TacticRollup(
        tactic_id="TA0002",
        tactic_name="Execution",
        total_techniques=10,
        full_count=2,
        shallow_count=1,
        gap_count=7,
        priority_gap_count=1,
    )
    report = _make_report(tactic_rollups=[rollup])
    out = render(report, output_format="terminal")
    assert "Execution" in out
    assert "TA0002" in out


def test_terminal_render_lists_top_priority_gaps() -> None:
    from detect_forge.coverage.reporter import render

    tech = _make_technique(
        technique_id="T1078",
        state="gap",
        is_priority=True,
        tactic_ids=["initial-access"],
    )
    report = _make_report(techniques=[tech], priority_gap=1)
    out = render(report, output_format="terminal")
    assert "T1078" in out
    # Tactic should appear somewhere near the listing
    assert "Initial Access" in out or "initial-access" in out


def test_terminal_render_shows_migration_needed_section_when_present() -> None:
    from detect_forge.coverage.models import MigrationItem
    from detect_forge.coverage.reporter import render

    item = MigrationItem(
        rule_source=Path("/rules/old.yml"),
        rule_title="Old rule",
        deprecated_technique_id="T1086",
        reason="revoked",
        replacement_id="T1059.001",
    )
    report = _make_report(migrations=[item])
    out = render(report, output_format="terminal")
    assert "Migration" in out or "migration" in out.lower()
    assert "T1086" in out
    assert "T1059.001" in out


def test_json_render_is_valid_json_with_required_keys() -> None:
    import json

    from detect_forge.coverage.reporter import render

    report = _make_report()
    out = render(report, output_format="json")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "techniques" in parsed
    assert "tactic_rollups" in parsed
    assert "migrations" in parsed
    assert parsed["summary"]["attack_domain"] == "enterprise-attack"


def test_json_render_includes_per_technique_details() -> None:
    import json

    from detect_forge.coverage.reporter import render

    tech = _make_technique(technique_id="T1078", state="gap", is_priority=True)
    report = _make_report(techniques=[tech], priority_gap=1)
    out = render(report, output_format="json")
    parsed = json.loads(out)
    assert parsed["techniques"][0]["technique_id"] == "T1078"
    assert parsed["techniques"][0]["state"] == "gap"
    assert parsed["techniques"][0]["is_priority"] is True


def test_json_render_unknown_format_raises() -> None:
    import pytest

    from detect_forge.coverage.reporter import render

    report = _make_report()
    with pytest.raises(ValueError, match="unknown output_format"):
        render(report, output_format="ascii-art")
