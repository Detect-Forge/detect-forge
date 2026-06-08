"""The audit meta-subcommand.

Composes stale + coverage + backtest into a unified report.
Public entry point: ``scan_audit(rule_dir, **kwargs)``.

See ``docs/superpowers/specs/2026-06-08-audit-design.md`` for design.
"""

from __future__ import annotations

from .models import (
    AuditReport,
    AuditSubResult,
    AuditSummary,
    SubcommandName,
    SubResultStatus,
)
from .orchestrator import run_audit as scan_audit

__all__ = [
    "AuditReport",
    "AuditSubResult",
    "AuditSummary",
    "SubResultStatus",
    "SubcommandName",
    "scan_audit",
]
