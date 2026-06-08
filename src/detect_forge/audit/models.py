"""Pydantic models for the audit subcommand.

AuditReport is the public surface — passed to reporters and rendered.
Per spec §7, AuditSubResult is a tagged union over the 3 subcommand
report types; exactly one of {stale_report, coverage_report,
backtest_report} is populated when status == "ran".
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from ..backtest.models import BacktestReport
from ..coverage.models import CoverageReport
from ..stale.models import StalenessReport

SubcommandName = Literal["stale", "coverage", "backtest"]
SubResultStatus = Literal["ran", "skipped", "errored"]


class AuditSubResult(BaseModel):
    """Wraps a single subcommand's outcome.

    When ``status == "ran"``: the matching ``*_report`` field is populated;
    ``error`` is None; ``would_gate`` and ``score`` are meaningful.
    When ``status == "skipped"`` or ``"errored"``: all ``*_report`` fields
    are None; ``score`` is None; ``would_gate`` is False.
    """

    subcommand: SubcommandName
    status: SubResultStatus
    error: str | None = None
    would_gate: bool = False
    score: int | None = None

    stale_report: StalenessReport | None = None
    coverage_report: CoverageReport | None = None
    backtest_report: BacktestReport | None = None


class AuditSummary(BaseModel):
    """Top-of-report stats. ``audit_would_gate`` drives the CI exit code."""

    rules_scanned: int
    """How many rules were discovered in the rule_dir (after parse)."""

    stale_health: int | None
    """Per spec §6: 100 * (total_rules - critical) / total_rules. None if skipped/errored."""
    coverage_completeness: int | None
    """100 * full / total_techniques."""
    backtest_verification_rate: int | None
    """100 * rules_fires / (rules_parsed - rules_unsupported)."""

    subcommands_ran: int
    subcommands_skipped: int
    subcommands_errored: int

    audit_would_gate: bool
    """True when every enabled subcommand's ``would_gate`` predicate is True."""

    attack_domain: str
    generated_at: datetime
    elapsed_seconds: float


class AuditReport(BaseModel):
    """Final audit report passed to renderers."""

    summary: AuditSummary
    sub_results: list[AuditSubResult] = Field(default_factory=list)
    """Always 3 entries when produced by run_audit(), ordered stale → coverage → backtest."""
