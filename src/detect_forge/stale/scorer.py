from __future__ import annotations

import logging
from datetime import UTC, date, datetime

from .models import (
    AttackIndex,
    DetectionRule,
    ReportSummary,
    RuleScore,
    SeverityLevel,
    StalenessReport,
    TechniqueFinding,
)

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity(days_stale: int) -> SeverityLevel:
    if days_stale >= 365:
        return "critical"
    if days_stale >= 180:
        return "high"
    if days_stale >= 90:
        return "medium"
    return "low"


def _score_technique(
    technique_id: str,
    rule_effective_date: date | None,
    index: AttackIndex,
) -> TechniqueFinding:
    # Use UTC date to match technique modified timestamps (stored in UTC).
    today = datetime.now(UTC).date()
    tech = index.techniques.get(technique_id)

    if tech is None:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=None,
            technique_modified=None,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="info",
            kind="unknown_technique",
        )

    if tech.revoked:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="high",
            kind="revoked_technique",
        )

    if tech.deprecated:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="high",
            kind="deprecated_technique",
        )

    technique_date = tech.modified.date()

    if rule_effective_date is None:
        days_stale = (today - technique_date).days
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=None,
            days_stale=days_stale,
            severity=_severity(days_stale),
            kind="no_rule_date",
        )

    if rule_effective_date >= technique_date:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="low",
            kind="current",
        )

    # Rule predates the technique's last modification: stale.
    # Staleness = how old MITRE's technique info is (bounded by technique_date, not by rule age).
    days_stale = (today - technique_date).days
    return TechniqueFinding(
        technique_id=technique_id,
        technique_name=tech.name,
        technique_modified=tech.modified,
        rule_effective_date=rule_effective_date,
        days_stale=days_stale,
        severity=_severity(days_stale),
        kind="stale",
    )



def score_rule(rule: DetectionRule, index: AttackIndex) -> RuleScore:
    effective_date = rule.modified_date or rule.rule_date

    if not rule.technique_ids:
        return RuleScore(
            rule_id=rule.rule_id,
            title=rule.title,
            source_file=rule.source_file,
            status=rule.status,
            findings=[],
            worst_severity="info",
            worst_days_stale=0,
            has_attack_tags=False,
        )

    findings = [
        _score_technique(tid, effective_date, index) for tid in rule.technique_ids
    ]
    # Derive both from the same winning finding: severity first, then days_stale for tie-break.
    worst_finding = max(
        findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.days_stale)
    )
    worst = worst_finding.severity
    worst_days = worst_finding.days_stale

    return RuleScore(
        rule_id=rule.rule_id,
        title=rule.title,
        source_file=rule.source_file,
        status=rule.status,
        findings=findings,
        worst_severity=worst,
        worst_days_stale=worst_days,
        has_attack_tags=True,
    )


def score_rules(rules: list[DetectionRule], index: AttackIndex) -> StalenessReport:
    """Score rules against an ATT&CK index.

    Returns a StalenessReport with scores sorted worst-first.
    """
    scores = [score_rule(r, index) for r in rules]

    scores.sort(
        key=lambda s: (_SEVERITY_ORDER[s.worst_severity], s.worst_days_stale),
        reverse=True,
    )

    def _count(sev: SeverityLevel) -> int:
        return sum(1 for s in scores if s.worst_severity == sev)

    summary = ReportSummary(
        total_rules=len(rules),
        rules_with_findings=sum(
            1 for s in scores if s.worst_severity != "low" or not s.has_attack_tags
        ),
        critical=_count("critical"),
        high=_count("high"),
        medium=_count("medium"),
        low=_count("low"),
        no_attack_tags=sum(1 for s in scores if not s.has_attack_tags),
        unknown_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "unknown_technique"
        ),
        deprecated_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "deprecated_technique"
        ),
        revoked_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "revoked_technique"
        ),
        generated_at=datetime.now(UTC),
        attack_domain=index.source_domain,
        attack_fetched_at=index.fetched_at,
    )

    return StalenessReport(summary=summary, scores=scores)
