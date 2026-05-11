from __future__ import annotations

from io import StringIO

from jinja2 import Environment, PackageLoader
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..console import theme
from .models import StalenessReport

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _filter_scores(report: StalenessReport, min_severity: str) -> StalenessReport:
    """Return a copy of `report` with scores below `min_severity` dropped.

    The original report is not mutated. Raises KeyError if `min_severity` is
    not a known severity level.
    """
    threshold = _SEVERITY_RANK[min_severity]
    kept = [
        s for s in report.scores if _SEVERITY_RANK[s.worst_severity] >= threshold
    ]
    return report.model_copy(update={"scores": kept})


def _render_terminal(report: StalenessReport, min_severity: str) -> str:
    """Render a Rich summary panel + findings table to a string."""
    threshold = _SEVERITY_RANK[min_severity]
    buf = StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        highlight=False,
        width=130,
        theme=theme,
    )

    s = report.summary
    summary_text = (
        f"Rules scanned: {s.total_rules}   "
        f"[critical]CRITICAL: {s.critical}[/critical]   "
        f"[high]HIGH: {s.high}[/high]   "
        f"[medium]MEDIUM: {s.medium}[/medium]   "
        f"[low]LOW: {s.low}[/low]\n"
        f"ATT&CK: {s.attack_domain} \u00b7 No tags: {s.no_attack_tags} "
        f"\u00b7 Unknown: {s.unknown_techniques} "
        f"\u00b7 Deprecated: {s.deprecated_techniques} "
        f"\u00b7 Revoked: {s.revoked_techniques}"
    )
    console.print(Panel(summary_text, title="Detect-Forge Stale Report", expand=False))

    has_semantic = any(
        f.kind == "semantic_drift"
        for score in report.scores
        for f in score.findings
    )

    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", max_width=40, no_wrap=True)
    table.add_column("Technique", width=12)
    table.add_column("Days Stale", justify="right", width=11)
    if has_semantic:
        table.add_column("Similarity", justify="right", width=10)
    table.add_column("Rule Date", width=11)
    table.add_column("ATT&CK Modified", width=16)
    table.add_column("File", max_width=40, no_wrap=True)

    for score in report.scores:
        if _SEVERITY_RANK[score.worst_severity] < threshold:
            continue
        for finding in score.findings:
            if _SEVERITY_RANK[finding.severity] < threshold:
                continue
            sev = finding.severity
            row = [
                f"[{sev}]{sev.upper()}[/{sev}]",
                score.title[:40],
                finding.technique_id,
                str(finding.days_stale) if finding.days_stale else "\u2014",
            ]
            if has_semantic:
                row.append(
                    f"{finding.similarity_score:.2f}"
                    if finding.similarity_score is not None
                    else "\u2014"
                )
            row.extend([
                str(finding.rule_effective_date or ""),
                str(finding.technique_modified.date() if finding.technique_modified else ""),
                str(score.source_file.name),
            ])
            table.add_row(*row)

    console.print(table)
    return buf.getvalue()


def _render_html(report: StalenessReport, min_severity: str) -> str:
    """Render the report to a self-contained HTML string via Jinja2."""
    filtered = _filter_scores(report, min_severity)
    env = Environment(
        loader=PackageLoader("detect_forge.stale", "templates"),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(summary=filtered.summary, scores=filtered.scores)


def render(
    report: StalenessReport,
    output_format: str = "terminal",
    min_severity: str = "low",
) -> str:
    """Render a StalenessReport to the requested format.

    The three formats (terminal / json / html) each filter findings below
    `min_severity`. Returns a str; the caller decides where to write it.
    """
    if output_format == "terminal":
        return _render_terminal(report, min_severity)
    if output_format == "json":
        return _filter_scores(report, min_severity).model_dump_json(indent=2)
    if output_format == "html":
        return _render_html(report, min_severity)
    raise ValueError(f"unknown output_format: {output_format!r}")
