"""Score derivation + gate predicates per spec §5-6.

Scores are 0-100 integer percentages. They're descriptive, not
prescriptive — audit makes no threshold recommendation; engineers decide.

Gate predicates return True when a subcommand's standalone CI gate
WOULD have fired given its report. The orchestrator AND-combines these
to derive ``audit_would_gate`` per spec §5.

Both layers are intentionally split from the orchestrator so they're
heavily unit-testable without spinning up real subcommand runs.
"""

from __future__ import annotations

from ..backtest.models import BacktestReport
from ..coverage.models import CoverageReport
from ..stale.models import StalenessReport

# ---------- score derivation ----------

def stale_health(report: StalenessReport) -> int | None:
    """% of rules without critical findings. None if no rules.

    Formula: 100 * (total_rules - critical) / total_rules
    """
    total = report.summary.total_rules
    if total <= 0:
        return None
    healthy = total - report.summary.critical
    return int(round(100 * healthy / total))


def coverage_completeness(report: CoverageReport) -> int | None:
    """% of techniques with FULL coverage. None if no techniques in scope.

    Formula: 100 * full / total_techniques
    """
    total = report.summary.total_techniques
    if total <= 0:
        return None
    return int(round(100 * report.summary.full / total))


def backtest_verification_rate(report: BacktestReport) -> int | None:
    """% of SUPPORTED rules that fire on Mordor. None if no supported rules.

    Formula: 100 * rules_fires / (rules_parsed - rules_unsupported)
    The denominator excludes unsupported rules so the metric reflects how
    well the *evaluable* corpus performs, not how much of it is evaluable.
    """
    supported = report.summary.rules_parsed - report.summary.rules_unsupported
    if supported <= 0:
        return None
    return int(round(100 * report.summary.rules_fires / supported))


# ---------- gate predicates ----------

def stale_would_gate(report: StalenessReport) -> bool:
    """Stale gates when ANY finding is critical. Mirrors stale CLI's exit-2 logic."""
    return report.summary.critical > 0


def coverage_would_gate(report: CoverageReport) -> bool:
    """Coverage gates when priority_gap > 0 (gate_on_priority_gaps applied separately)."""
    return report.summary.priority_gap > 0


def backtest_would_gate(report: BacktestReport) -> bool:
    """Backtest gates on priority silence OR broken rules (the two-gate semantics).

    Config gate flags (gate_on_priority_silence, gate_on_broken_rules) are
    NOT consulted here by design — these predicates report the raw report
    state. Callers apply config filtering before invoking.
    """
    s = report.summary
    return s.priority_silent > 0 or s.rules_silent_on_all > 0
