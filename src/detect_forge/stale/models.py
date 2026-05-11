from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class AttackTechnique(BaseModel):
    """A single ATT&CK technique or sub-technique with its staleness-relevant metadata."""

    technique_id: str
    name: str
    modified: datetime
    is_subtechnique: bool
    deprecated: bool = False
    revoked: bool = False
    tactic_ids: list[str] = Field(default_factory=list)
    stix_id: str


class AttackIndex(BaseModel):
    """Full ATT&CK index keyed by technique_id (e.g. T1059.001) with fetch metadata."""

    techniques: dict[str, AttackTechnique] = Field(default_factory=dict)
    fetched_at: datetime
    # TODO: populated from x-mitre-collection identity object in a future task.
    attack_version: str | None = None
    source_domain: str = "enterprise-attack"


class DetectionRule(BaseModel):
    """A parsed detection rule with the fields relevant to staleness scoring.

    Common shape for both Sigma (YAML) and Elastic Detection Rules (TOML);
    populated by the per-format parsers in this package.
    """

    rule_id: str | None = None
    title: str
    status: str | None = None
    rule_date: date | None = None
    modified_date: date | None = None
    technique_ids: list[str] = Field(default_factory=list)
    source_file: Path
    raw_tags: list[str] = Field(default_factory=list)


SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
FindingKind = Literal[
    "stale",
    "current",
    "no_attack_tags",
    "no_rule_date",
    "deprecated_technique",
    "revoked_technique",
    "unknown_technique",
]


class TechniqueFinding(BaseModel):
    """Staleness result for one technique referenced by one rule."""

    technique_id: str
    technique_name: str | None = None
    technique_modified: datetime | None = None
    rule_effective_date: date | None = None
    days_stale: int
    severity: SeverityLevel
    kind: FindingKind


class RuleScore(BaseModel):
    """Aggregated staleness score for a single detection rule."""

    rule_id: str | None = None
    title: str
    source_file: Path
    status: str | None = None
    findings: list[TechniqueFinding] = Field(default_factory=list)
    worst_severity: SeverityLevel
    worst_days_stale: int
    has_attack_tags: bool


class ReportSummary(BaseModel):
    total_rules: int
    rules_with_findings: int
    critical: int
    high: int
    medium: int
    low: int
    no_attack_tags: int
    unknown_techniques: int
    deprecated_techniques: int
    revoked_techniques: int
    generated_at: datetime
    attack_domain: str
    attack_fetched_at: datetime


class StalenessReport(BaseModel):
    summary: ReportSummary
    scores: list[RuleScore] = Field(default_factory=list)

    def has_severity(self, level: SeverityLevel) -> bool:
        return any(s.worst_severity == level for s in self.scores)
