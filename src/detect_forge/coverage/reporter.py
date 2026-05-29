"""Format dispatcher for coverage reports.

One function per format. Each function takes a CoverageReport and returns a
str ready to write to a file or stdout. The terminal renderer uses Rich; JSON,
HTML, and Navigator-JSON are populated in subsequent commits.
"""

from __future__ import annotations

from io import StringIO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..console import theme
from ._tactics import lookup_tactic
from .models import CoverageReport


def render(report: CoverageReport, output_format: str = "terminal") -> str:
    """Render a CoverageReport in the requested format. Raises on unknown format."""
    if output_format == "terminal":
        return _render_terminal(report)
    if output_format == "json":
        return report.model_dump_json(indent=2)
    raise ValueError(f"unknown output_format: {output_format!r}")


def _render_terminal(report: CoverageReport) -> str:
    buf = StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        highlight=False,
        width=130,
        theme=theme,
    )
    s = report.summary

    # ---- Summary panel ----
    def pct(n: int) -> float:
        return (100 * n / s.total_techniques) if s.total_techniques else 0.0

    summary_lines = [
        f"Techniques in scope: {s.total_techniques}   Rules parsed: {s.rules_parsed}",
        (
            f"[low]Full: {s.full} ({pct(s.full):.1f}%)[/low]   "
            f"[medium]Shallow: {s.shallow} ({pct(s.shallow):.1f}%)[/medium]   "
            f"[critical]Gaps: {s.gap} ({pct(s.gap):.1f}%)[/critical]"
        ),
        "",
        f"Priority list techniques: {s.priority_total}",
        (
            f"[low]Priority full: {s.priority_full}[/low]   "
            f"[medium]Priority shallow: {s.priority_shallow}[/medium]   "
            f"[critical]Priority GAPS: {s.priority_gap}[/critical]"
            + ("  ← gates CI" if s.priority_gap else "")
        ),
    ]
    title = f"ATT&CK Coverage — {s.attack_domain}"
    console.print(Panel("\n".join(summary_lines), title=title, expand=False))

    # ---- Tactic rollup ----
    if report.tactic_rollups:
        console.print()
        console.print("Per-tactic coverage:")
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Tactic", max_width=42, no_wrap=True)
        table.add_column("Total", justify="right", width=6)
        table.add_column("Full", justify="right", width=6)
        table.add_column("Shallow", justify="right", width=8)
        table.add_column("Gap", justify="right", width=6)
        table.add_column("Priority Gap", justify="right", width=14)
        for r in report.tactic_rollups:
            table.add_row(
                f"{r.tactic_name} ({r.tactic_id})",
                str(r.total_techniques),
                f"[low]{r.full_count}[/low]" if r.full_count else "0",
                f"[medium]{r.shallow_count}[/medium]" if r.shallow_count else "0",
                f"[critical]{r.gap_count}[/critical]" if r.gap_count else "0",
                (
                    f"[critical]{r.priority_gap_count}[/critical]"
                    if r.priority_gap_count
                    else "0"
                ),
            )
        console.print(table)

    # ---- Top priority gaps detail ----
    priority_gaps = [
        t for t in report.techniques if t.is_priority and t.state == "gap"
    ]
    if priority_gaps:
        console.print()
        console.print("Top priority gaps (no detection coverage):")
        for t in priority_gaps[:10]:
            tactic_label = ""
            if t.tactic_ids:
                _, name = lookup_tactic(t.tactic_ids[0])
                tactic_label = f"  ({name})"
            console.print(
                f"  [critical]{t.technique_id}[/critical]  "
                f"{t.technique_name}{tactic_label}"
            )

    # ---- Migration needed section ----
    if report.migrations:
        console.print()
        console.print("Migration needed:")
        for m in report.migrations:
            tail = (
                f"  ({m.reason}, replaced by {m.replacement_id})"
                if m.replacement_id
                else f"  ({m.reason})"
            )
            console.print(
                f"  [medium]{m.rule_source.name}[/medium]  →  "
                f"{m.deprecated_technique_id}{tail}"
            )

    return buf.getvalue()
