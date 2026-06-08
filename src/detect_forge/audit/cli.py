"""The audit subcommand — composes stale + coverage + backtest."""

from __future__ import annotations

import logging
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..config import load_audit_config_or_defaults
from ..console import err_console
from ..exit_codes import GATED, RESERVED
from ..settings import Settings

log = logging.getLogger(__name__)

_VALID_SUBCOMMANDS = {"stale", "coverage", "backtest"}
_DEFAULT_LLM_MODEL = "gpt-4o-mini"


@click.command(name="audit")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "html"]),
    default="terminal", show_default=True,
    help="Output format. Navigator is NOT supported in v0.1 — run "
         "coverage/backtest directly for those layers.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path), default=None,
    help="Write output to file instead of stdout",
)
@click.option(
    "--no-cache", is_flag=True, default=False,
    help="Bypass STIX + Mordor caches across all subcommands",
)
@click.option(
    "--domain",
    type=click.Choice(["enterprise-attack", "ics-attack", "mobile-attack"]),
    default=Settings().attack_domain, show_default=True,
    help="ATT&CK domain",
)
@click.option(
    "--no-gate", is_flag=True, default=False,
    help="Don't exit 2 even if the audit gate would have fired",
)
@click.option(
    "--skip",
    multiple=True,
    type=click.Choice(["stale", "coverage", "backtest"]),
    help="Skip a subcommand entirely. Repeatable.",
)
@click.option(
    "--priority-list",
    type=click.Path(exists=True, path_type=Path), default=None,
    help="Path to custom priority list JSON (shared by coverage + backtest)",
)
@click.option(
    "--with-llm-proposals", is_flag=True, default=False,
    help="Enable LLM diff proposals in stale (off by default — cost gate)",
)
@click.option(
    "--platform",
    type=click.Choice(["windows", "linux", "macos", "all"]),
    default="all", show_default=True,
    help="Backtest-only: limit Mordor datasets by platform",
)
@click.option(
    "--techniques", default=None,
    help="Backtest-only: comma-separated technique IDs to restrict scan",
)
@click.option(
    "--semantic-threshold",
    type=float, default=0.65, show_default=True,
    help="Stale: cosine similarity threshold for semantic drift",
)
@click.pass_context
def audit_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    no_cache: bool,
    domain: str,
    no_gate: bool,
    skip: tuple[str, ...],
    priority_list: Path | None,
    with_llm_proposals: bool,
    platform: str,
    techniques: str | None,
    semantic_threshold: float,
) -> None:
    """Run every check in one step — stale + coverage + backtest."""
    from . import reporter, scan_audit

    settings = Settings()
    audit_cfg = load_audit_config_or_defaults()
    effective_no_cache = no_cache or settings.no_cache

    # Compute enabled subcommands: config.subcommands MINUS CLI --skip.
    from typing import cast as _cast  # noqa: PLC0415

    from ..audit.models import SubcommandName  # noqa: PLC0415
    config_enabled: set[SubcommandName] = set(audit_cfg.subcommands)
    cli_skip: set[SubcommandName] = _cast(
        "set[SubcommandName]", set(skip)
    )
    enabled: set[SubcommandName] = config_enabled - cli_skip
    if not enabled:
        err_console.print(
            "[critical]No subcommands enabled "
            "(everything was either disabled in config or --skipped).[/critical]"
        )
        ctx.exit(RESERVED)
        return

    # Gate strategy: config drives ('all' default, 'never' kills); --no-gate forces never.
    effective_gate_strategy = audit_cfg.gate_strategy
    if no_gate:
        effective_gate_strategy = "never"

    # LLM: opt-in via CLI flag or config.
    effective_llm_model: str | None = None
    if with_llm_proposals or audit_cfg.include_llm_proposals:
        effective_llm_model = _DEFAULT_LLM_MODEL

    # Technique filter parse.
    technique_filter: set[str] | None = None
    if techniques:
        technique_filter = {t.strip() for t in techniques.split(",") if t.strip()}

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        prog_task = progress.add_task("Running audit...", total=None)
        report = scan_audit(
            rule_dir,
            enabled=enabled,
            gate_strategy=effective_gate_strategy,
            domain=domain,
            cache_dir=settings.cache_dir,
            cache_ttl_hours=settings.cache_ttl_hours,
            no_cache=effective_no_cache,
            priority_list=priority_list,
            platform=platform,
            technique_filter=technique_filter,
            semantic_threshold=semantic_threshold,
            llm_model=effective_llm_model,
        )
        progress.remove_task(prog_task)

    rendered = reporter.render(report, output_format=output_format)

    if output:
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[info]Report written to {output}[/info]")
    else:
        click.echo(rendered, nl=False, color=output_format == "terminal")

    # Exit code per spec §4:
    # 2 — audit gate fired (gate-fire wins over errored)
    # 1 — at least one subcommand errored AND gate didn't fire
    # 0 — clean
    if report.summary.audit_would_gate and not no_gate:
        ctx.exit(GATED)
    if report.summary.subcommands_errored > 0:
        ctx.exit(RESERVED)


def register(group: click.Group) -> None:
    group.add_command(audit_cmd)
