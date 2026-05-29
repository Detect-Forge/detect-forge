from __future__ import annotations

from datetime import UTC, datetime

import pytest

from detect_forge.stale.models import (
    AttackIndex,
    AttackTechnique,
    DetectionRule,
    FindingKind,
    ReportSummary,
    RuleScore,
    SeverityLevel,
    StalenessReport,
    TechniqueFinding,
)


def test_attack_technique_full_shape() -> None:
    t = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        modified=datetime(2024, 10, 17, 15, 19, 6, tzinfo=UTC),
        is_subtechnique=True,
        deprecated=False,
        tactic_ids=["execution"],
        stix_id="attack-pattern--00000000-0000-0000-0000-000000001060",
    )
    assert t.technique_id == "T1059.001"
    assert t.is_subtechnique is True
    assert t.deprecated is False
    assert t.tactic_ids == ["execution"]
    assert t.modified.tzinfo is not None


def test_attack_technique_requires_core_fields() -> None:
    with pytest.raises(ValueError):
        AttackTechnique()  # type: ignore[call-arg]


def test_attack_index_shape() -> None:
    idx = AttackIndex(
        techniques={},
        fetched_at=datetime(2026, 4, 17, tzinfo=UTC),
    )
    assert idx.techniques == {}
    assert idx.source_domain == "enterprise-attack"
    assert idx.attack_version is None
    assert idx.fetched_at.tzinfo is not None


def test_detection_rule_minimal_construction() -> None:
    from pathlib import Path

    r = DetectionRule(
        title="PowerShell Encoded Command",
        source_file=Path("/rules/ps.yml"),
    )
    assert r.title == "PowerShell Encoded Command"
    assert r.source_file == Path("/rules/ps.yml")
    assert r.rule_id is None
    assert r.status is None
    assert r.rule_date is None
    assert r.modified_date is None
    assert r.technique_ids == []
    assert r.raw_tags == []


def test_detection_rule_full_construction() -> None:
    from datetime import date
    from pathlib import Path

    r = DetectionRule(
        rule_id="10598928-44a9-4730-b79f-69b62fe73666",
        title="PowerShell Encoded Command",
        status="test",
        rule_date=date(2024, 3, 15),
        modified_date=date(2024, 11, 1),
        technique_ids=["T1059.001"],
        source_file=Path("/rules/ps.yml"),
        raw_tags=["attack.execution", "attack.t1059.001"],
    )
    assert r.technique_ids == ["T1059.001"]
    assert r.rule_date is not None
    assert r.rule_date.year == 2024
    assert r.modified_date is not None
    assert r.modified_date.month == 11
    assert "attack.t1059.001" in r.raw_tags


def test_severity_level_values() -> None:
    for v in ("critical", "high", "medium", "low", "info"):
        s: SeverityLevel = v  # type: ignore[assignment]
        assert s == v


def test_finding_kind_values() -> None:
    for v in (
        "stale",
        "current",
        "no_attack_tags",
        "no_rule_date",
        "deprecated_technique",
        "unknown_technique",
    ):
        k: FindingKind = v  # type: ignore[assignment]
        assert k == v


def test_technique_finding_full_shape() -> None:
    from datetime import UTC
    from datetime import date as _date
    from datetime import datetime as _datetime

    f = TechniqueFinding(
        technique_id="T1059.001",
        technique_name="PowerShell",
        technique_modified=_datetime(2024, 10, 17, tzinfo=UTC),
        rule_effective_date=_date(2023, 1, 1),
        days_stale=290,
        severity="high",
        kind="stale",
    )
    assert f.technique_id == "T1059.001"
    assert f.severity == "high"
    assert f.kind == "stale"
    assert f.days_stale == 290


def test_rule_score_minimal_construction() -> None:
    from pathlib import Path

    score = RuleScore(
        rule_id=None,
        title="Bare Rule",
        source_file=Path("/rules/bare.yml"),
        status=None,
        findings=[],
        worst_severity="info",
        worst_days_stale=0,
        has_attack_tags=False,
    )
    assert score.has_attack_tags is False
    assert score.worst_severity == "info"


def test_staleness_report_has_severity() -> None:
    from datetime import UTC
    from datetime import datetime as _datetime
    from pathlib import Path

    critical_score = RuleScore(
        rule_id="r1",
        title="Critical Rule",
        source_file=Path("/rules/crit.yml"),
        status="stable",
        findings=[],
        worst_severity="critical",
        worst_days_stale=400,
        has_attack_tags=True,
    )
    summary = ReportSummary(
        total_rules=1,
        rules_with_findings=1,
        critical=1,
        high=0,
        medium=0,
        low=0,
        no_attack_tags=0,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=_datetime(2026, 4, 17, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=_datetime(2026, 4, 17, tzinfo=UTC),
    )
    report = StalenessReport(summary=summary, scores=[critical_score])

    assert report.has_severity("critical") is True
    assert report.has_severity("low") is False


def test_attack_technique_accepts_description() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackTechnique

    t = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters.",
        modified=datetime(2025, 1, 1, tzinfo=UTC),
        is_subtechnique=False,
        stix_id="attack-pattern--abc",
    )
    assert t.description == "Adversaries may abuse command and script interpreters."


def test_attack_technique_description_defaults_to_none() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackTechnique

    t = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        modified=datetime(2025, 1, 1, tzinfo=UTC),
        is_subtechnique=False,
        stix_id="attack-pattern--abc",
    )
    assert t.description is None


def test_detection_rule_accepts_description() -> None:
    from pathlib import Path

    from detect_forge.stale.models import DetectionRule

    r = DetectionRule(
        title="t",
        source_file=Path("/tmp/r.yml"),
        description="A rule that detects something specific.",
    )
    assert r.description == "A rule that detects something specific."


def test_detection_rule_description_defaults_to_none() -> None:
    from pathlib import Path

    from detect_forge.stale.models import DetectionRule

    r = DetectionRule(title="t", source_file=Path("/tmp/r.yml"))
    assert r.description is None


def test_finding_kind_includes_semantic_drift() -> None:
    # Type-level membership — the literal must include "semantic_drift".
    k: FindingKind = "semantic_drift"  # type: ignore[assignment]
    assert k == "semantic_drift"


def test_technique_finding_accepts_similarity_score() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import TechniqueFinding

    f = TechniqueFinding(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        technique_modified=datetime(2025, 1, 1, tzinfo=UTC),
        rule_effective_date=None,
        days_stale=0,
        severity="medium",
        kind="semantic_drift",
        similarity_score=0.42,
    )
    assert f.similarity_score == 0.42
    assert f.kind == "semantic_drift"


def test_technique_finding_similarity_score_defaults_to_none() -> None:
    from detect_forge.stale.models import TechniqueFinding

    f = TechniqueFinding(
        technique_id="T1059",
        days_stale=0,
        severity="low",
        kind="current",
    )
    assert f.similarity_score is None


def test_empty_staleness_report_has_no_severity() -> None:
    from datetime import UTC
    from datetime import datetime as _datetime

    summary = ReportSummary(
        total_rules=0,
        rules_with_findings=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        no_attack_tags=0,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=_datetime(2026, 4, 17, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=_datetime(2026, 4, 17, tzinfo=UTC),
    )
    report = StalenessReport(summary=summary, scores=[])
    assert report.has_severity("critical") is False


def test_diff_proposal_full_construction() -> None:
    from detect_forge.stale.models import DiffProposal

    p = DiffProposal(
        proposed_rule="title: rewritten\nid: abc\n",
        explanation="Updated description to match T1003.001 current scope.",
        changed_fields=["description", "tags"],
        confidence=0.85,
    )
    assert p.proposed_rule.startswith("title: rewritten")
    assert "description" in p.changed_fields
    assert p.confidence == 0.85


def test_diff_proposal_confidence_must_be_in_range() -> None:
    from detect_forge.stale.models import DiffProposal

    with pytest.raises(ValueError):
        DiffProposal(
            proposed_rule="x",
            explanation="y",
            changed_fields=[],
            confidence=1.5,
        )


def test_diff_proposal_confidence_rejects_negative() -> None:
    from detect_forge.stale.models import DiffProposal

    with pytest.raises(ValueError):
        DiffProposal(
            proposed_rule="x",
            explanation="y",
            changed_fields=[],
            confidence=-0.1,
        )


def test_rule_score_proposals_defaults_to_empty_list() -> None:
    from pathlib import Path

    from detect_forge.stale.models import RuleScore

    score = RuleScore(
        rule_id=None,
        title="No Proposals",
        source_file=Path("/r"),
        status=None,
        findings=[],
        worst_severity="info",
        worst_days_stale=0,
        has_attack_tags=False,
    )
    assert score.proposals == []


def test_rule_score_accepts_proposals() -> None:
    from pathlib import Path

    from detect_forge.stale.models import DiffProposal, RuleScore

    p = DiffProposal(
        proposed_rule="x",
        explanation="y",
        changed_fields=[],
        confidence=0.5,
    )
    score = RuleScore(
        rule_id=None,
        title="With Proposal",
        source_file=Path("/r"),
        status=None,
        findings=[],
        worst_severity="medium",
        worst_days_stale=0,
        has_attack_tags=True,
        proposals=[p],
    )
    assert len(score.proposals) == 1
    assert score.proposals[0].confidence == 0.5


def test_attack_technique_parent_id_defaults_to_none() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackTechnique

    t = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        modified=datetime.now(UTC),
        is_subtechnique=False,
        stix_id="attack-pattern--test",
    )
    assert t.parent_id is None
    assert t.replacement_id is None


def test_attack_technique_parent_id_holds_value() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackTechnique

    t = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        modified=datetime.now(UTC),
        is_subtechnique=True,
        parent_id="T1059",
        stix_id="attack-pattern--test-sub",
    )
    assert t.parent_id == "T1059"


def test_attack_technique_replacement_id_holds_value() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackTechnique

    t = AttackTechnique(
        technique_id="T1086",
        name="PowerShell (revoked)",
        modified=datetime.now(UTC),
        is_subtechnique=False,
        revoked=True,
        replacement_id="T1059.001",
        stix_id="attack-pattern--test-revoked",
    )
    assert t.replacement_id == "T1059.001"


def test_attack_index_subtechniques_of_returns_children() -> None:
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackIndex, AttackTechnique

    now = datetime.now(UTC)
    parent = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        modified=now,
        is_subtechnique=False,
        stix_id="ap--p",
    )
    sub_a = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        modified=now,
        is_subtechnique=True,
        parent_id="T1059",
        stix_id="ap--sa",
    )
    sub_b = AttackTechnique(
        technique_id="T1059.002",
        name="AppleScript",
        modified=now,
        is_subtechnique=True,
        parent_id="T1059",
        stix_id="ap--sb",
    )
    other = AttackTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        modified=now,
        is_subtechnique=False,
        stix_id="ap--o",
    )

    idx = AttackIndex(
        techniques={
            "T1059": parent,
            "T1059.001": sub_a,
            "T1059.002": sub_b,
            "T1078": other,
        },
        fetched_at=now,
    )
    assert set(idx.subtechniques_of("T1059")) == {"T1059.001", "T1059.002"}
    assert idx.subtechniques_of("T1078") == []
    assert idx.subtechniques_of("T9999") == []  # unknown parent


def test_attack_index_subtechniques_of_ignores_subtechnique_input() -> None:
    """Passing a sub-technique ID returns []; only parents have children."""
    from datetime import UTC, datetime

    from detect_forge.stale.models import AttackIndex, AttackTechnique

    now = datetime.now(UTC)
    sub = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        modified=now,
        is_subtechnique=True,
        parent_id="T1059",
        stix_id="ap--sa",
    )
    idx = AttackIndex(techniques={"T1059.001": sub}, fetched_at=now)
    assert idx.subtechniques_of("T1059.001") == []
