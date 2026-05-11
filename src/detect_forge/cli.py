from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from .console import err_console
from .exit_codes import GATED
from .settings import settings


@click.group()
@click.version_option(package_name="detect-forge")
def main() -> None:
    """Score your detection rules for ATT&CK technique staleness."""


@main.command()
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "html"]),
    default="terminal",
    show_default=True,
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    show_default=True,
    help="Only show rules at or above this severity",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass disk cache and fetch fresh ATT&CK bundle",
)
@click.option(
    "--domain",
    type=click.Choice(["enterprise-attack", "ics-attack", "mobile-attack"]),
    default=settings.attack_domain,
    show_default=True,
    help="ATT&CK domain to fetch",
)
def scan(
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    min_severity: str,
    no_cache: bool,
    domain: str,
) -> None:
    """Scan RULE_DIR for Sigma rules and score them for ATT&CK staleness."""
    from .stale import attack_client, reporter, rule_parser, scorer

    ttl = 0 if no_cache else settings.cache_ttl_hours

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        t1 = progress.add_task("Fetching ATT&CK bundle...", total=None)
        index = attack_client.build_index(
            domain=domain, cache_dir=settings.cache_dir, ttl_hours=ttl
        )
        progress.remove_task(t1)

        t2 = progress.add_task(f"Parsing rules in {rule_dir}...", total=None)
        rules = rule_parser.parse_rule_dir(rule_dir)
        progress.remove_task(t2)

        t3 = progress.add_task("Scoring...", total=None)
        report = scorer.score_rules(rules, index)
        progress.remove_task(t3)

    rendered = reporter.render(
        report,
        output_format=output_format,
        min_severity=min_severity,
    )

    if output:
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[info]Report written to {output}[/info]")
    else:
        click.echo(rendered, nl=False, color=output_format == "terminal")

    if report.has_severity("critical"):
        sys.exit(GATED)


if __name__ == "__main__":
    main()
