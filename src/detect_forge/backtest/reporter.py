"""Format dispatcher for backtest reports.

One function per format. Terminal uses Rich; JSON, HTML, Navigator land
in subsequent tasks.
"""

from __future__ import annotations

from io import StringIO

from jinja2 import Environment, PackageLoader
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..console import theme
from ..coverage._tactics import lookup_tactic
from .models import BacktestReport


def render(report: BacktestReport, output_format: str = "terminal") -> str:
    if output_format == "terminal":
        return _render_terminal(report)
    if output_format == "json":
        return report.model_dump_json(indent=2)
    if output_format == "html":
        return _render_html(report)
    raise ValueError(
        f"unknown output_format: {output_format!r}. "
        f"Valid values will be: terminal, json, html, navigator. "
        f"Only 'terminal', 'json', and 'html' are implemented in this commit."
    )


def _render_html(report: BacktestReport) -> str:
    env = Environment(
        loader=PackageLoader("detect_forge.backtest", "templates"),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(
        summary=report.summary,
        rule_results=report.rule_results,
        technique_rollups=report.technique_rollups,
    )


def _render_terminal(report: BacktestReport) -> str:
    buf = StringIO()
    console = Console(
        file=buf, force_terminal=True, highlight=False, width=130, theme=theme,
    )
    s = report.summary

    # ---- Summary panel ----
    summary_lines = [
        f"Rules parsed: {s.rules_parsed}   Datasets consulted: {s.datasets_consulted}",
        (
            f"[low]Fires: {s.rules_fires}[/low]   "
            f"[medium]Partial: {s.rules_partial}[/medium]   "
            f"[critical]Silent on all: {s.rules_silent_on_all}[/critical]"
            + ("  ← broken-rule gate" if s.rules_silent_on_all else "")
        ),
        (
            f"[info]Untested: {s.rules_untested}[/info]   "
            f"[info]Unsupported: {s.rules_unsupported}[/info]"
        ),
        "",
        f"Priority list techniques: {s.priority_total}",
        (
            f"[low]Priority verified: {s.priority_verified}[/low]   "
            f"[critical]Priority silent: {s.priority_silent}[/critical]"
            + ("  ← priority-silence gate" if s.priority_silent else "")
        ),
        f"[info]Priority untested: {s.priority_untested}[/info]",
    ]
    title = f"Adversarial Backtest — Security-Datasets ({s.mordor_source or 'unknown'})"
    console.print(Panel("\n".join(summary_lines), title=title, expand=False))

    # ---- Silent-on-all rules table ----
    silent_rules = [r for r in report.rule_results if r.status == "silent_on_all"]
    if silent_rules:
        console.print()
        console.print("Silent-on-all rules (broken — no targeted dataset fires):")
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Rule", max_width=42, no_wrap=True)
        table.add_column("Format", width=8)
        table.add_column("Techniques", width=20)
        table.add_column("Tested", width=12)
        for r in silent_rules:
            tids = ", ".join(p.technique_id for p in r.technique_results)
            datasets = sum(p.datasets_tested for p in r.technique_results)
            tids_display = tids if len(tids) <= 20 else tids[:19] + "…"
            table.add_row(
                r.source_file.name,
                r.rule_format,
                tids_display,
                f"{datasets} datasets",
            )
        console.print(table)

    # ---- Per-technique status (priority silent first) ----
    if report.technique_rollups:
        console.print()
        console.print("Per-technique status (priority silent first):")
        for t in report.technique_rollups[:15]:
            label = "[critical]" if t.is_priority and t.status == "silent" else ""
            close = "[/critical]" if label else ""
            tactic_label = ""
            if t.tactic_ids:
                _, tname = lookup_tactic(t.tactic_ids[0])
                tactic_label = f"  ({tname})"
            console.print(
                f"  {label}{t.technique_id}{close}  {t.technique_name}"
                f"{tactic_label}  "
                f"({t.rules_tagged} rules tagged, {t.rules_fired} fired)"
            )
        total_rollups = len(report.technique_rollups)
        if total_rollups > 15:
            console.print(f"  … {total_rollups - 15} more not shown")

    # ---- Unsupported rules ----
    unsupported = [r for r in report.rule_results if r.status == "unsupported"]
    if unsupported:
        console.print()
        console.print("Unsupported (skipped at v0.1):")
        for r in unsupported:
            console.print(
                f"  {r.source_file.name}  ({r.unsupported_reason or 'unknown'})"
            )

    return buf.getvalue()
