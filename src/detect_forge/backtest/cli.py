from __future__ import annotations

from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..config import load_backtest_config_or_defaults
from ..console import err_console
from ..exit_codes import GATED
from ..settings import Settings


@click.command(name="backtest")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "html", "navigator"]),
    default="terminal", show_default=True, help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path), default=None,
    help="Write output to file instead of stdout",
)
@click.option(
    "--no-cache", is_flag=True, default=False,
    help="Bypass STIX + Mordor caches; refetch",
)
@click.option(
    "--domain",
    type=click.Choice(["enterprise-attack", "ics-attack", "mobile-attack"]),
    default=Settings().attack_domain, show_default=True,
    help="ATT&CK domain to fetch",
)
@click.option(
    "--no-gate", is_flag=True, default=False,
    help="Don't exit 2 on either gate (informational only)",
)
@click.option(
    "--priority-list",
    type=click.Path(exists=True, path_type=Path), default=None,
    help="Path to custom priority list JSON",
)
@click.option(
    "--platform",
    type=click.Choice(["windows", "linux", "macos", "all"]),
    default="all", show_default=True,
    help="Limit Mordor datasets by platform",
)
@click.option(
    "--techniques", default=None,
    help="Comma-separated technique IDs to restrict the scan",
)
@click.option(
    "--mordor-source",
    type=click.Path(exists=True, path_type=Path), default=None,
    help="Local Security-Datasets checkout (skips network)",
)
@click.pass_context
def backtest_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    no_cache: bool,
    domain: str,
    no_gate: bool,
    priority_list: Path | None,
    platform: str,
    techniques: str | None,
    mordor_source: Path | None,
) -> None:
    """Replay adversary technique behavior against detection rules."""
    from . import reporter, scan_backtest

    settings = Settings()
    bt_cfg = load_backtest_config_or_defaults()
    effective_no_cache = no_cache or settings.no_cache

    # Gating precedence: --no-gate > config > default True.
    gate_priority = bt_cfg.gate_on_priority_silence
    gate_broken = bt_cfg.gate_on_broken_rules
    if no_gate:
        gate_priority = False
        gate_broken = False

    # Platform: CLI > config > default.
    effective_platform = platform if platform != "all" else bt_cfg.platform

    # Mordor source: CLI > config > fetch.
    effective_mordor: Path | None = mordor_source
    if effective_mordor is None and bt_cfg.mordor_source:
        effective_mordor = Path(bt_cfg.mordor_source)

    # Technique filter from CLI.
    technique_filter: set[str] | None = None
    if techniques:
        technique_filter = {t.strip() for t in techniques.split(",") if t.strip()}

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        prog_task = progress.add_task("Running backtest...", total=None)
        report = scan_backtest(
            rule_dir,
            domain=domain,
            cache_dir=settings.cache_dir,
            cache_ttl_hours=settings.cache_ttl_hours,
            no_cache=effective_no_cache,
            priority_list=priority_list,
            platform=effective_platform,
            technique_filter=technique_filter,
            mordor_source=effective_mordor,
        )
        progress.remove_task(prog_task)

    rendered = reporter.render(report, output_format=output_format)

    if output:
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[info]Report written to {output}[/info]")
    else:
        click.echo(rendered, nl=False, color=output_format == "terminal")

    gated = False
    if gate_priority and report.summary.priority_silent > 0:
        err_console.print(
            f"[critical]{report.summary.priority_silent} priority technique(s) "
            f"silent on Mordor datasets.[/critical]"
        )
        gated = True
    if gate_broken and report.summary.rules_silent_on_all > 0:
        err_console.print(
            f"[critical]{report.summary.rules_silent_on_all} rule(s) silent on all "
            f"tested datasets (likely broken).[/critical]"
        )
        gated = True
    if gated:
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    group.add_command(backtest_cmd)
