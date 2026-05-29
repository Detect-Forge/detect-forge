"""Pydantic data model for the ``backtest`` subcommand.

FireStatus is the per-(rule, technique) verdict. TechniqueResult is the atomic
unit. RuleResult and TechniqueRollup are two cuts of the same data, mirroring
coverage's TechniqueCoverage + TacticRollup precedent. BacktestSummary holds
top-of-report stats including both gate inputs (rules_silent_on_all,
priority_silent). BacktestReport is the final object passed to renderers.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

FireStatus = Literal["verified", "silent", "untested"]
"""Per-(rule, technique) pair status."""

RuleStatus = Literal["fires", "partial", "silent_on_all", "untested", "unsupported"]
"""Per-rule rollup status. ``silent_on_all`` gates the broken-rule CI check."""

TechniqueStatus = Literal["verified", "silent", "untested"]
"""Per-technique rollup status across all tagged rules."""


class FireRecord(BaseModel):
    """One occurrence of a rule firing on an event within a dataset."""

    rule_id: str
    technique_id: str
    dataset_id: str
    event_index: int


class TechniqueResult(BaseModel):
    """Per-(rule, technique) pair — the atomic backtest unit."""

    rule_id: str
    rule_title: str
    technique_id: str
    status: FireStatus
    datasets_tested: int
    datasets_fired: int
    fires: list[FireRecord] = Field(default_factory=list)


class RuleResult(BaseModel):
    """Per-rule view across all its tagged techniques."""

    rule_id: str
    rule_title: str
    source_file: Path
    rule_format: Literal["sigma", "elastic"]
    status: RuleStatus
    technique_results: list[TechniqueResult] = Field(default_factory=list)
    unsupported_reason: str | None = None


class TechniqueRollup(BaseModel):
    """Per-technique view across all rules tagged with it."""

    technique_id: str
    technique_name: str
    tactic_ids: list[str] = Field(default_factory=list)
    status: TechniqueStatus
    is_priority: bool = False
    rules_tagged: int
    rules_fired: int
    datasets_available: int


class BacktestSummary(BaseModel):
    """Top-of-report stats; both gate inputs live here."""

    rules_parsed: int
    rules_fires: int
    rules_partial: int
    rules_silent_on_all: int
    rules_untested: int
    rules_unsupported: int

    techniques_in_scope: int
    techniques_verified: int
    techniques_silent: int
    techniques_untested: int

    priority_total: int
    priority_verified: int
    priority_silent: int
    priority_untested: int

    datasets_consulted: int
    mordor_source: str
    attack_domain: str
    attack_fetched_at: datetime
    generated_at: datetime


class BacktestReport(BaseModel):
    """Final report passed to renderers."""

    summary: BacktestSummary
    rule_results: list[RuleResult] = Field(default_factory=list)
    technique_rollups: list[TechniqueRollup] = Field(default_factory=list)
