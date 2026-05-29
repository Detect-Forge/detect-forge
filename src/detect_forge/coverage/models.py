"""Pydantic data model for the ``coverage`` subcommand.

CoverageState is the per-technique classification. A TechniqueCoverage groups one
technique's state with the rules that established it. TacticRollup aggregates by
tactic. MigrationItem flags rules pointing at deprecated/revoked techniques.
CoverageSummary holds the top-of-report stats including the CI-gate input
``priority_gap``. CoverageReport is the final object passed to renderers.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

CoverageState = Literal["full", "shallow", "gap"]
"""Per-technique coverage classification:

- ``full``: at least one rule is tagged with this exact technique_id (or sub-technique_id).
- ``shallow``: only the parent technique is tagged; this sub-technique has no
  dedicated rule.
- ``gap``: no rules reference this technique at any level.
"""


class TechniqueCoverage(BaseModel):
    """Coverage state for a single technique or sub-technique."""

    technique_id: str
    technique_name: str
    is_subtechnique: bool
    parent_id: str | None = None
    tactic_ids: list[str] = Field(default_factory=list)
    state: CoverageState
    # rule_count and rule_sources reflect the rules that determined this state:
    #   state="full"    → exact-match rules only
    #   state="shallow" → parent-only (propagated) rules only
    #   state="gap"     → empty
    rule_count: int = 0
    rule_sources: list[Path] = Field(default_factory=list)
    is_priority: bool = False


class TacticRollup(BaseModel):
    """Per-tactic aggregation."""

    tactic_id: str
    """Either a TA-prefixed ID like ``TA0002`` (known tactic) or the raw shortname."""
    tactic_name: str
    total_techniques: int
    full_count: int
    shallow_count: int
    gap_count: int
    priority_gap_count: int


class MigrationItem(BaseModel):
    """A rule references a deprecated or revoked ATT&CK technique."""

    rule_source: Path
    rule_title: str
    deprecated_technique_id: str
    reason: Literal["deprecated", "revoked"]
    replacement_id: str | None = None


class CoverageSummary(BaseModel):
    """Top-of-report stats. ``priority_gap`` drives the CI gate."""

    total_techniques: int
    full: int
    shallow: int
    gap: int
    priority_total: int
    priority_full: int
    priority_shallow: int
    priority_gap: int
    rules_parsed: int
    rules_with_unknown_tags: int
    migrations_needed: int
    attack_domain: str
    attack_fetched_at: datetime
    generated_at: datetime


class CoverageReport(BaseModel):
    """Final coverage report passed to renderers."""

    summary: CoverageSummary
    techniques: list[TechniqueCoverage] = Field(default_factory=list)
    tactic_rollups: list[TacticRollup] = Field(default_factory=list)
    migrations: list[MigrationItem] = Field(default_factory=list)
