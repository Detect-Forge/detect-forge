# Detect-Forge Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the Python package `ttp-staleness` to `detect-forge`, restructure the CLI as a subcommand suite (`stale` real + `backtest`/`coverage`/`cti ingest`/`audit` stubs), migrate env vars from `TTP_` to `DETECT_FORGE_`, change the CI-gating exit code from `1` to `2`, and ship XDG-aware caching — all in one branch ahead of the May 23 2026 launch.

**Architecture:** One PyPI package `detect-forge` exposing the `detect-forge` console script. Python package `src/detect_forge/` with shared modules (`cli.py`, `settings.py`, `cache.py`, `console.py`, `common.py`, `exit_codes.py`, `_stubs.py`) at the top level and per-subcommand subpackages (`stale/`, `backtest/`, `coverage/`, `cti/`, `audit/`). Each subcommand subpackage exposes a `register(group)` function that the root CLI calls. `stale/` contains the entire existing staleness pipeline; the others are click stubs that print to stderr and exit `1`. The existing pipeline modules (`attack_client`, `rule_parser`, `scorer`, `reporter`, `models`, `templates/`) are moved via `git mv` to preserve history. Hard cut on the old name — no `ttp-staleness` alias, no `TTP_*` env var back-compat.

**Tech Stack:** Python 3.12+, click 8.2+, pydantic v2, pydantic-settings v2, rich 13+, mitreattack-python 3+, requests, pySigma, jinja2; hatchling build; pytest + pytest-mock + requests-mock, ruff, mypy --strict.

**Source spec:** [📐 Spec: Detect-Forge Rebrand](../specs/2026-05-11-detect-forge-rebrand-design.md)

---

## File Structure

After this plan, the source tree is:

```
detect-forge/
├── pyproject.toml                          # name=detect-forge, scripts entry updated
├── README.md                               # full rewrite — Detect-Forge brand, subcommand surface
├── LICENSE                                 # unchanged
├── src/
│   └── detect_forge/
│       ├── __init__.py                     # __version__ from "detect-forge" dist
│       ├── cli.py                          # click root group; calls register() per subcommand
│       ├── settings.py                     # DETECT_FORGE_* env prefix; cache_dir via factory
│       ├── console.py                      # unchanged after move (no internal references)
│       ├── cache.py                        # XDG-aware _default_cache_dir(); helpers unchanged
│       ├── common.py                       # NEW — @common_output_options decorator
│       ├── exit_codes.py                   # NEW — CLEAN=0, RESERVED=1, GATED=2
│       ├── _stubs.py                       # NEW — stub_command(name, message) helper
│       ├── stale/
│       │   ├── __init__.py                 # public API: scan(), build_index, parse_rule_dir, score_rules, render
│       │   ├── cli.py                      # NEW — stale_cmd click.command + register()
│       │   ├── attack_client.py            # moved (history preserved)
│       │   ├── rule_parser.py              # moved (preserves .toml-vs-.yml TODO)
│       │   ├── scorer.py                   # moved
│       │   ├── reporter.py                 # moved; PackageLoader + Panel title updated
│       │   ├── models.py                   # moved
│       │   └── templates/
│       │       └── report.html.j2          # moved; rebrand-string updates
│       ├── backtest/
│       │   ├── __init__.py
│       │   └── cli.py                      # stub via _stubs.stub_command
│       ├── coverage/
│       │   ├── __init__.py
│       │   └── cli.py                      # stub
│       ├── cti/
│       │   ├── __init__.py
│       │   └── cli.py                      # click.group "cti" + ingest stub
│       └── audit/
│           ├── __init__.py
│           └── cli.py                      # stub with reserved message
└── tests/
    ├── __init__.py                         # unchanged
    ├── conftest.py                         # fixture renamed; DETECT_FORGE_* clear; imports updated
    ├── fixtures/                           # unchanged
    ├── stubs/
    │   ├── __init__.py                     # NEW
    │   └── test_stub_subcommands.py        # NEW — exits, stderr messages
    ├── test_attack_client.py               # imports updated
    ├── test_cache.py                       # XDG behavior asserted; DEFAULT_CACHE_DIR removed
    ├── test_cache_xdg.py                   # NEW
    ├── test_cli.py                         # imports updated; exit code 2 expected; stale subcommand
    ├── test_common.py                      # NEW
    ├── test_console.py                     # imports updated
    ├── test_exit_codes.py                  # NEW
    ├── test_models.py                      # imports updated
    ├── test_reporter.py                    # imports updated; brand-string assertions updated
    ├── test_rule_parser.py                 # imports updated
    ├── test_scorer.py                      # imports updated
    ├── test_settings.py                    # DETECT_FORGE_* prefix; factory-aware cache_dir
    ├── test_stale_api.py                   # NEW — public scan() function
    └── test_version.py                     # import updated
```

**File responsibilities:**
- `src/detect_forge/__init__.py` — package version pulled from the `detect-forge` distribution; no other exports.
- `src/detect_forge/cli.py` — defines the root click group and calls each subpackage's `register(group)`. Holds nothing else.
- `src/detect_forge/settings.py` — pydantic-settings `Settings` with `DETECT_FORGE_` prefix and `cache_dir` via `default_factory` so env-time changes to `XDG_CACHE_HOME` are honored at instance creation.
- `src/detect_forge/cache.py` — XDG-aware factory plus the existing cache I/O helpers. No subcommand-specific knowledge.
- `src/detect_forge/common.py` — single `@common_output_options` decorator that adds `--format`, `--output`, `--min-severity` to any click command that composes it.
- `src/detect_forge/exit_codes.py` — `CLEAN`, `RESERVED`, `GATED` constants. Imported wherever a non-zero exit is decided.
- `src/detect_forge/_stubs.py` — `stub_command(name, message)` factory that returns a click command which prints to stderr and exits `RESERVED`. Used by every unbuilt subcommand.
- `src/detect_forge/stale/__init__.py` — re-exports the public API (`scan`, `build_index`, `parse_rule_dir`, `score_rules`, `render`, and the public model classes) so users can do `from detect_forge.stale import scan`.
- `src/detect_forge/stale/cli.py` — the click `stale_cmd` command (was previously `scan` in the root `cli.py`) plus the `register()` adapter. Wraps the public `scan()` function with output rendering and exit-code logic.
- Each stub subpackage's `cli.py` defines a `register(group)` function. `cti/cli.py` defines a click group and attaches a single `ingest` stub child.

---

## Prereqs / Working Conventions

- All work happens in the existing git worktree at `/Users/jbower/Documents/personal_projects/detect-forge/.claude/worktrees/quirky-newton-bab423` on branch `claude/quirky-newton-bab423`. Do not switch branches.
- Active venv: `source .venv/bin/activate` from the worktree root.
- Run all `git`, `pytest`, `pip`, `ruff`, `mypy` commands from the worktree root.
- After Task 1 the installed distribution is `detect-forge`. Reinstall is part of Task 1; subsequent tasks do not need to reinstall unless `pyproject.toml` changes.
- Use `git mv` (not `mv`) for every package-tree move to preserve history.
- Commit messages use Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `chore:`, `docs:`). NO `Co-Authored-By` lines (per user's global CLAUDE.md).
- Run `pytest -q` at the end of every task. A task is not done unless every existing test plus every new test passes.
- TDD applies to new behavior (Tasks 2+). Task 1 is a mechanical refactor that must leave the existing test suite green after rename-aware updates.

---

## Task 1: Mechanical package rename to `detect_forge`

**Goal:** Move `src/ttp_staleness/` to its new location under `src/detect_forge/` (with the existing staleness logic landing inside a `stale/` subpackage), update every import / env-prefix / brand-string reference, update `pyproject.toml`, reinstall, and verify all 38 existing tests still pass. No new behavior. No new files beyond empty `__init__.py`s for the new subpackages.

**Files:**
- Move (git mv): every `src/ttp_staleness/*.py` and `src/ttp_staleness/templates/`
- Create: `src/detect_forge/__init__.py` (then overwritten by the move), `src/detect_forge/stale/__init__.py`, `src/detect_forge/backtest/__init__.py`, `src/detect_forge/coverage/__init__.py`, `src/detect_forge/cti/__init__.py`, `src/detect_forge/audit/__init__.py`
- Modify: `pyproject.toml`, `src/detect_forge/__init__.py`, `src/detect_forge/cli.py`, `src/detect_forge/stale/reporter.py`, `src/detect_forge/stale/templates/report.html.j2`, every file in `tests/`

- [ ] **Step 1: Verify baseline — all 38 existing tests pass before any change**

Run:
```bash
pytest -q
```

Expected: 38 passed (or whatever the current count is — record the number; the same number must pass at end of this task).

If anything fails before changes, fix that first or stop and escalate; rename must start from green.

- [ ] **Step 2: Create the new top-level package directory**

Run:
```bash
mkdir -p src/detect_forge
```

- [ ] **Step 3: Move every existing source file into the new tree with `git mv`**

The strategy: move the whole old package directory to `src/detect_forge/stale/` first (so `git mv` records one rename per file with history), then promote the shared modules back up to `src/detect_forge/`.

Run, in this exact order:
```bash
git mv src/ttp_staleness src/detect_forge/stale
git mv src/detect_forge/stale/__init__.py src/detect_forge/__init__.py
git mv src/detect_forge/stale/cli.py      src/detect_forge/cli.py
git mv src/detect_forge/stale/settings.py src/detect_forge/settings.py
git mv src/detect_forge/stale/cache.py    src/detect_forge/cache.py
git mv src/detect_forge/stale/console.py  src/detect_forge/console.py
```

After this, `src/detect_forge/stale/` contains: `attack_client.py`, `rule_parser.py`, `scorer.py`, `reporter.py`, `models.py`, `templates/`, and no `__init__.py`. The shared modules are at `src/detect_forge/` with no `stale` subpackage `__init__.py`.

- [ ] **Step 4: Create empty `__init__.py` for the `stale` and stub subpackages**

Run:
```bash
touch src/detect_forge/stale/__init__.py
mkdir -p src/detect_forge/backtest src/detect_forge/coverage src/detect_forge/cti src/detect_forge/audit
touch src/detect_forge/backtest/__init__.py
touch src/detect_forge/coverage/__init__.py
touch src/detect_forge/cti/__init__.py
touch src/detect_forge/audit/__init__.py
```

These remain empty until later tasks. They exist now so Python recognizes the subpackages and `pyproject.toml`'s wheel build includes them.

- [ ] **Step 5: Update `src/detect_forge/__init__.py` to read the new distribution name**

Replace the file contents with:
```python
from importlib.metadata import version

__version__ = version("detect-forge")
```

- [ ] **Step 6: Update `src/detect_forge/cli.py` — version_option, lazy imports**

Replace the file contents with the verbatim block below. Two functional changes vs the current file: `package_name` is `"detect-forge"`, and the lazy import targets `.stale` instead of `.` so `attack_client.build_index`, etc. resolve in the new location. The exit-code-on-critical line is preserved as `sys.exit(1)` for now — Task 4 changes it to `GATED`.

```python
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from .console import err_console
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
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Update `src/detect_forge/stale/reporter.py` — PackageLoader argument and Panel title**

Find the two lines that need to change:

Old (line ~60):
```python
    console.print(Panel(summary_text, title="TTP-Staleness Report", expand=False))
```
New:
```python
    console.print(Panel(summary_text, title="Detect-Forge Stale Report", expand=False))
```

Old (line ~96):
```python
        loader=PackageLoader("ttp_staleness", "templates"),
```
New:
```python
        loader=PackageLoader("detect_forge.stale", "templates"),
```

Use Edit tool with `old_string`/`new_string` for both. No other changes in this file.

- [ ] **Step 8: Update `src/detect_forge/stale/templates/report.html.j2` — brand strings**

Find and replace the two `TTP Staleness Report` occurrences:

Old (line 5):
```html
<title>TTP Staleness Report — {{ summary.generated_at.date() }}</title>
```
New:
```html
<title>Detect-Forge Stale Report — {{ summary.generated_at.date() }}</title>
```

Old (line 34):
```html
<h1>TTP Staleness Report</h1>
```
New:
```html
<h1>Detect-Forge Stale Report</h1>
```

- [ ] **Step 9: Update `pyproject.toml` — package name, console script, build packages, include**

Use the Edit tool four times (each replacement is unique):

Old:
```toml
name = "ttp-staleness"
```
New:
```toml
name = "detect-forge"
```

Old:
```toml
[project.scripts]
ttp-staleness = "ttp_staleness.cli:main"
```
New:
```toml
[project.scripts]
detect-forge = "detect_forge.cli:main"
```

Old:
```toml
[tool.hatch.build.targets.wheel]
packages = ["src/ttp_staleness"]
include = ["src/ttp_staleness/templates/*"]
```
New:
```toml
[tool.hatch.build.targets.wheel]
packages = ["src/detect_forge"]
include = ["src/detect_forge/stale/templates/*"]
```

(The `[project.urls]` block already points at `Detect-Forge/detect-forge` from an earlier commit — do not touch it.)

- [ ] **Step 10: Update `tests/conftest.py`**

Replace the file contents with:
```python
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from detect_forge.stale.models import StalenessReport


@pytest.fixture(autouse=True)
def _clear_detect_forge_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip any ambient DETECT_FORGE_* env vars so tests get a clean Settings()."""
    for key in list(os.environ):
        if key.startswith("DETECT_FORGE_"):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    """An empty directory that satisfies click's exists=True, file_okay=False."""
    d = tmp_path / "rules"
    d.mkdir()
    return d


@pytest.fixture
def sample_report() -> StalenessReport:
    from datetime import UTC, date, datetime
    from pathlib import Path as _Path

    from detect_forge.stale.models import (
        ReportSummary,
        RuleScore,
        StalenessReport,
        TechniqueFinding,
    )

    def _rule(
        title: str,
        severity: str,
        kind: str,
        days_stale: int,
        tech: str,
        file: str,
    ) -> RuleScore:
        finding = TechniqueFinding(
            technique_id=tech,
            technique_name=f"{tech} name",
            technique_modified=datetime(2024, 10, 17, tzinfo=UTC),
            rule_effective_date=date(2024, 1, 1),
            days_stale=days_stale,
            severity=severity,  # type: ignore[arg-type]
            kind=kind,  # type: ignore[arg-type]
        )
        return RuleScore(
            rule_id=f"id-{tech}",
            title=title,
            source_file=_Path(f"/rules/{file}"),
            status="stable",
            findings=[finding],
            worst_severity=severity,  # type: ignore[arg-type]
            worst_days_stale=days_stale,
            has_attack_tags=True,
        )

    scores = [
        _rule("Critical Test Rule", "critical", "stale", 400, "T1059", "crit.yml"),
        _rule("High Test Rule", "high", "stale", 200, "T1003", "high.yml"),
        _rule("Medium Test Rule", "medium", "stale", 120, "T1005", "med.yml"),
        _rule("Low Test Rule", "low", "current", 0, "T1083", "low.yml"),
        RuleScore(
            rule_id=None,
            title="Bare Rule No Tags",
            source_file=_Path("/rules/bare.yml"),
            status="stable",
            findings=[],
            worst_severity="info",
            worst_days_stale=0,
            has_attack_tags=False,
        ),
    ]

    summary = ReportSummary(
        total_rules=5,
        rules_with_findings=4,
        critical=1,
        high=1,
        medium=1,
        low=1,
        no_attack_tags=1,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=datetime(2026, 4, 18, 12, 0, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime(2026, 4, 18, 10, 0, tzinfo=UTC),
    )
    return StalenessReport(summary=summary, scores=scores)
```

Three changes from the previous version: fixture is renamed from `_clear_ttp_env` to `_clear_detect_forge_env`, the prefix filter is `DETECT_FORGE_` instead of `TTP_`, and both model imports target `detect_forge.stale.models`.

- [ ] **Step 11: Update every test file — bulk import migration**

For each test file in the table below, apply the listed replacements via the Edit tool. All replacements are exact-string. Do **not** use a single `replace_all` across multiple semantically different patterns.

`tests/test_version.py` — replace twice (use replace_all=true since the strings are short and unique to this file's intent):

Old:
```python
import ttp_staleness
```
New:
```python
import detect_forge
```

Old (replace_all=true for the two occurrences):
```python
ttp_staleness.__version__
```
New:
```python
detect_forge.__version__
```

`tests/test_console.py`:

Old:
```python
from ttp_staleness.console import console, err_console, theme
```
New:
```python
from detect_forge.console import console, err_console, theme
```

`tests/test_models.py`:

Old:
```python
from ttp_staleness.models import (
```
New:
```python
from detect_forge.stale.models import (
```

`tests/test_scorer.py` (two import statements):

Old:
```python
from ttp_staleness.models import (
```
New:
```python
from detect_forge.stale.models import (
```

Old:
```python
from ttp_staleness.scorer import score_rule, score_rules
```
New:
```python
from detect_forge.stale.scorer import score_rule, score_rules
```

`tests/test_rule_parser.py` (one top-level import + multiple inline `_parse_sigma_date` imports — use replace_all=true on the inline pattern):

Old:
```python
from ttp_staleness.rule_parser import (
```
New:
```python
from detect_forge.stale.rule_parser import (
```

Old (replace_all=true):
```python
    from ttp_staleness.rule_parser import _parse_sigma_date
```
New:
```python
    from detect_forge.stale.rule_parser import _parse_sigma_date
```

`tests/test_attack_client.py` (four references):

Old:
```python
from ttp_staleness.attack_client import build_index
from ttp_staleness.models import AttackIndex
```
New:
```python
from detect_forge.stale.attack_client import build_index
from detect_forge.stale.models import AttackIndex
```

Old:
```python
    from ttp_staleness.attack_client import STIX_URLS
```
New:
```python
    from detect_forge.stale.attack_client import STIX_URLS
```

Old:
```python
    get_spy = mocker.patch("ttp_staleness.attack_client.requests.get")
```
New:
```python
    get_spy = mocker.patch("detect_forge.stale.attack_client.requests.get")
```

`tests/test_reporter.py` (one top-level import + three inline `_filter_scores` imports — use replace_all=true on the inline pattern):

Old:
```python
from ttp_staleness.reporter import render
```
New:
```python
from detect_forge.stale.reporter import render
```

Old (replace_all=true):
```python
    from ttp_staleness.reporter import _filter_scores
```
New:
```python
    from detect_forge.stale.reporter import _filter_scores
```

If any assertion in `tests/test_reporter.py` checks for the literal `TTP-Staleness Report` or `TTP Staleness Report`, update that assertion to `Detect-Forge Stale Report`. Use Edit with the exact old string from the file.

`tests/test_settings.py` (six references — three import-related, three env-var-related; assert-side cache_dir path):

Old:
```python
from ttp_staleness.settings import Settings
```
New:
```python
from detect_forge.settings import Settings
```

Old:
```python
    assert s.cache_dir == Path.home() / ".cache" / "ttp-staleness"
```
New:
```python
    assert s.cache_dir == Path.home() / ".cache" / "detect-forge"
```

Old:
```python
    monkeypatch.setenv("TTP_CACHE_DIR", str(tmp_path / "alt"))
```
New:
```python
    monkeypatch.setenv("DETECT_FORGE_CACHE_DIR", str(tmp_path / "alt"))
```

Old:
```python
    monkeypatch.setenv("TTP_NO_CACHE", "true")
```
New:
```python
    monkeypatch.setenv("DETECT_FORGE_NO_CACHE", "true")
```

Old:
```python
    monkeypatch.setenv("TTP_ATTACK_DOMAIN", "ics-attack")
```
New:
```python
    monkeypatch.setenv("DETECT_FORGE_ATTACK_DOMAIN", "ics-attack")
```

Old:
```python
    from ttp_staleness import settings as settings_mod
```
New:
```python
    from detect_forge import settings as settings_mod
```

`tests/test_cache.py` (two references):

Old:
```python
from ttp_staleness.cache import (
```
New:
```python
from detect_forge.cache import (
```

Old:
```python
    assert Path.home() / ".cache" / "ttp-staleness" == DEFAULT_CACHE_DIR
```
New:
```python
    assert Path.home() / ".cache" / "detect-forge" == DEFAULT_CACHE_DIR
```

(In Task 3 this assertion will be replaced wholesale by an XDG-aware test; for now it just has the path updated so Task 1 keeps the suite green.)

`tests/test_cli.py` (eight references):

Old:
```python
from ttp_staleness import __version__
from ttp_staleness.cli import main
from ttp_staleness.models import (
```
New:
```python
from detect_forge import __version__
from detect_forge.cli import main
from detect_forge.stale.models import (
```

Old (replace_all=true for these three mocker.patch targets in `patched_pipeline`):
```python
            "ttp_staleness.attack_client.build_index", return_value=_EMPTY_INDEX
```
New:
```python
            "detect_forge.stale.attack_client.build_index", return_value=_EMPTY_INDEX
```

Old:
```python
            "ttp_staleness.rule_parser.parse_rule_dir", return_value=[]
```
New:
```python
            "detect_forge.stale.rule_parser.parse_rule_dir", return_value=[]
```

Old:
```python
            "ttp_staleness.scorer.score_rules", return_value=_EMPTY_REPORT
```
New:
```python
            "detect_forge.stale.scorer.score_rules", return_value=_EMPTY_REPORT
```

Old:
```python
    assert "ttp-staleness" in result.stdout.lower()
```
New:
```python
    assert "detect-forge" in result.stdout.lower()
```

Old:
```python
    assert kwargs["cache_dir"] == Path.home() / ".cache" / "ttp-staleness"
```
New:
```python
    assert kwargs["cache_dir"] == Path.home() / ".cache" / "detect-forge"
```

Old (the test-function name itself contains the old brand — rename it):
```python
def test_scan_default_cache_dir_is_home_cache_ttp_staleness(
```
New:
```python
def test_scan_default_cache_dir_is_home_cache_detect_forge(
```

(If the actual function name in your file differs, grep for `ttp_staleness` in function names — any function whose identifier contains the old brand should be renamed to use `detect_forge`.)

Old (the critical-finding mock block — there are three `mocker.patch` calls in `test_scan_exits_1_when_critical_finding`; update each):
```python
        "ttp_staleness.attack_client.build_index", return_value=_EMPTY_INDEX
```
New:
```python
        "detect_forge.stale.attack_client.build_index", return_value=_EMPTY_INDEX
```

Old:
```python
    mocker.patch("ttp_staleness.rule_parser.parse_rule_dir", return_value=[])
```
New:
```python
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
```

Old:
```python
    mocker.patch("ttp_staleness.scorer.score_rules", return_value=critical_report)
```
New:
```python
    mocker.patch("detect_forge.stale.scorer.score_rules", return_value=critical_report)
```

Note: the same `"ttp_staleness.attack_client.build_index", return_value=_EMPTY_INDEX` string appears in both the `patched_pipeline` fixture and the critical-finding test. If you used `replace_all=true` earlier for the fixture-level patches, the second occurrence is already updated and the Edit call will fail with "old_string not found" — that's fine, skip it.

- [ ] **Step 12: Sweep for any remaining old-name reference**

Run:
```bash
grep -rn "ttp_staleness\|ttp-staleness\|TTP-Staleness\|TTP Staleness\|TTP_" src/ tests/ pyproject.toml 2>&1 | grep -v __pycache__
```

Expected: **no results.** If any line remains, open the file and replace it. The only legitimate remaining reference would be in `src/detect_forge/stale/rule_parser.py:99` — the TODO comment about `data/rules/*.toml`. That TODO is preserved verbatim per the spec; specifically the text `ttp-staleness scan data/rules` in that comment is the OLD command and is fine to leave because the carried-forward TODO is about the rules data, not the rebrand. **Update** the command in the comment to `detect-forge stale data/rules` to keep the comment accurate, then re-run the grep — that final occurrence should be gone too.

The exact Edit:

Old:
```python
# TODO(detect-forge): the bundled rules in data/rules/ are *.toml, but this
# default glob only matches *.yml — so `ttp-staleness scan data/rules` finds
# nothing out of the box. Either rename the fixtures, broaden the default
# glob, or auto-detect the rule format. See conversation 2026-05-11.
```
New:
```python
# TODO(detect-forge): the bundled rules in data/rules/ are *.toml, but this
# default glob only matches *.yml — so `detect-forge stale data/rules` finds
# nothing out of the box. Either rename the fixtures, broaden the default
# glob, or auto-detect the rule format. See conversation 2026-05-11.
```

Re-run the grep. Expected: no results.

- [ ] **Step 13: Reinstall the package under the new name**

Run:
```bash
pip uninstall -y ttp-staleness
pip install -e ".[dev]"
```

Expected: `pip uninstall` reports the old distribution removed (or "not installed" — that's OK if a previous task already removed it). `pip install -e` completes without error and `pip show detect-forge` reports version `0.1.0`.

- [ ] **Step 14: Run the full test suite**

Run:
```bash
pytest -q
```

Expected: same number of tests as baseline (Step 1) — all pass. If any fail with `ModuleNotFoundError` for `ttp_staleness`, Step 11 missed a reference; grep again and fix.

- [ ] **Step 15: Smoke-check the new console script**

Run:
```bash
detect-forge --version
detect-forge scan --help
```

Expected: `--version` prints `detect-forge, version 0.1.0` (or similar Click format with `detect-forge`). `scan --help` prints the existing flag surface. (The CLI restructure to `stale` happens in Task 5; for now `scan` is still the command name.)

- [ ] **Step 16: Commit**

Run:
```bash
git add -A
git status
```

Expected `git status` output: all `src/ttp_staleness/*` listed as deletions, corresponding `src/detect_forge/...` paths as additions/renames, `pyproject.toml` and tests modified.

```bash
git commit -m "refactor: rename ttp-staleness package to detect-forge with stale submodule

Move src/ttp_staleness/ to src/detect_forge/ with the staleness pipeline
(attack_client, rule_parser, scorer, reporter, models, templates) under
src/detect_forge/stale/. Shared modules (cli, settings, cache, console)
sit at the top level. Console script renamed to 'detect-forge'. All
existing tests migrated and passing under the new module paths."
```

---

## Task 2: Add `exit_codes` module + flip `stale` to exit `2` on critical (TDD)

**Goal:** Introduce named exit-code constants and change the CI-gating exit from `1` to `2` per OS §8. Stubs (added later) will use `RESERVED=1`; `stale` uses `GATED=2`. This is the only behavioral break in the rebrand.

**Files:**
- Create: `src/detect_forge/exit_codes.py`
- Create: `tests/test_exit_codes.py`
- Modify: `src/detect_forge/cli.py` (one line)
- Modify: `tests/test_cli.py` (update the critical-exit assertion from `== 1` to `== 2`)

- [ ] **Step 1: Write failing test for the constants**

Create `tests/test_exit_codes.py`:
```python
from detect_forge.exit_codes import CLEAN, GATED, RESERVED


def test_clean_is_zero() -> None:
    assert CLEAN == 0


def test_reserved_is_one() -> None:
    assert RESERVED == 1


def test_gated_is_two() -> None:
    assert GATED == 2
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_exit_codes.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'detect_forge.exit_codes'`.

- [ ] **Step 3: Implement `src/detect_forge/exit_codes.py`**

```python
"""Detect-Forge exit-code constants.

Per Company OS §8:
- 0 (CLEAN): scan completed, no gating findings
- 1 (RESERVED): tool error, stub, or unimplemented command
- 2 (GATED): CI-gating condition met (e.g. critical finding)
"""

CLEAN = 0
RESERVED = 1
GATED = 2
```

- [ ] **Step 4: Run constants tests, confirm pass**

Run:
```bash
pytest tests/test_exit_codes.py -q
```

Expected: PASS (3 passed).

- [ ] **Step 5: Find and update the existing critical-exit test**

In `tests/test_cli.py`, find the test `test_scan_exits_1_when_critical_finding` (or whatever the existing critical-finding test is named). Its assertion currently reads:

```python
    assert result.exit_code == 1
```

Replace with:
```python
    assert result.exit_code == 2
```

Also rename the test function:

Old:
```python
def test_scan_exits_1_when_critical_finding(
```
New:
```python
def test_scan_exits_2_when_critical_finding(
```

- [ ] **Step 6: Run the critical-finding test, confirm failure**

Run:
```bash
pytest tests/test_cli.py -k "exits_2_when_critical" -q
```

Expected: FAIL — `assert 1 == 2` (current code still exits 1).

- [ ] **Step 7: Update `src/detect_forge/cli.py` to use `GATED`**

Add the import near the top:

Old:
```python
from .console import err_console
from .settings import settings
```
New:
```python
from .console import err_console
from .exit_codes import GATED
from .settings import settings
```

Update the exit line at the bottom of `scan`:

Old:
```python
    if report.has_severity("critical"):
        sys.exit(1)
```
New:
```python
    if report.has_severity("critical"):
        sys.exit(GATED)
```

- [ ] **Step 8: Run full test suite, confirm everything passes**

Run:
```bash
pytest -q
```

Expected: PASS (baseline tests + 3 new exit-code tests).

- [ ] **Step 9: Commit**

```bash
git add src/detect_forge/exit_codes.py src/detect_forge/cli.py tests/test_exit_codes.py tests/test_cli.py
git commit -m "feat: add exit_codes module; gate critical findings with exit 2 (was 1)"
```

---

## Task 3: XDG-aware cache directory (TDD)

**Goal:** Replace the hard-coded `~/.cache/detect-forge/` default with a factory that respects `XDG_CACHE_HOME`. Wire it into both `cache.py` and `Settings.cache_dir`.

**Files:**
- Create: `tests/test_cache_xdg.py`
- Modify: `src/detect_forge/cache.py`
- Modify: `src/detect_forge/settings.py`
- Modify: `tests/test_cache.py` (the old `DEFAULT_CACHE_DIR ==` assertion is replaced; the module-level constant is removed in Step 4)
- Modify: `tests/test_settings.py` (one assertion newly checks XDG handling)

- [ ] **Step 1: Write failing tests**

Create `tests/test_cache_xdg.py`:
```python
from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.cache import _default_cache_dir


def test_default_cache_dir_without_xdg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    assert _default_cache_dir() == Path.home() / ".cache" / "detect-forge"


def test_default_cache_dir_honors_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert _default_cache_dir() == tmp_path / "detect-forge"


def test_default_cache_dir_ignores_empty_xdg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    assert _default_cache_dir() == Path.home() / ".cache" / "detect-forge"
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_cache_xdg.py -q
```

Expected: FAIL — `ImportError: cannot import name '_default_cache_dir' from 'detect_forge.cache'`.

- [ ] **Step 3: Implement the factory in `src/detect_forge/cache.py`**

Replace the file contents with:
```python
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def _default_cache_dir() -> Path:
    """Return the default cache directory honoring XDG_CACHE_HOME.

    Falls back to ``~/.cache/detect-forge`` when ``XDG_CACHE_HOME`` is unset
    or empty.
    """
    xdg = os.environ.get("XDG_CACHE_HOME") or ""
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "detect-forge"


DEFAULT_TTL_HOURS = 24


def cache_path(domain: str, cache_dir: Path | None = None) -> Path:
    """Return the filesystem path for a given ATT&CK domain's cached STIX bundle.

    Ensures the cache directory exists.
    """
    resolved = cache_dir if cache_dir is not None else _default_cache_dir()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved / f"{domain}.json"


def is_cache_valid(path: Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> bool:
    """Return True iff the file exists and is younger than ttl_hours.

    `ttl_hours=0` always returns False (cache bypass).
    """
    if ttl_hours <= 0 or not path.exists():
        return False
    age = datetime.now(UTC) - datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    return age < timedelta(hours=ttl_hours)


def read_cache(path: Path) -> dict[str, Any]:
    """Read and parse a cached JSON file."""
    return dict(json.loads(path.read_text(encoding="utf-8")))


def write_cache(path: Path, data: dict[str, Any]) -> None:
    """Write a dict to disk as JSON atomically (write tmp + rename)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)
```

Two changes from the previous version: (a) the module-level `DEFAULT_CACHE_DIR` constant is gone, replaced by `_default_cache_dir()`; (b) `cache_path` accepts `cache_dir: Path | None = None` and falls back to the factory.

- [ ] **Step 4: Remove the broken `DEFAULT_CACHE_DIR` references from `tests/test_cache.py`**

In `tests/test_cache.py`, find:

Old:
```python
from detect_forge.cache import (
```

Look at the import block — it likely lists `DEFAULT_CACHE_DIR` as one of the names. Remove `DEFAULT_CACHE_DIR` from that import (preserve every other name). The import block should still include `cache_path`, `is_cache_valid`, `read_cache`, `write_cache`.

Find the test that previously asserted `DEFAULT_CACHE_DIR`:

Old:
```python
    assert Path.home() / ".cache" / "detect-forge" == DEFAULT_CACHE_DIR
```

Replace the entire test function. The simplest approach: change the test name and body to call the factory directly. Use Edit to find the surrounding `def test_...` block and replace it with:

```python
def test_cache_path_uses_factory_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    path = cache_path("enterprise-attack")
    assert path == tmp_path / "detect-forge" / "enterprise-attack.json"
```

If `pytest` isn't already imported at the top of `tests/test_cache.py`, add `import pytest` to the imports.

- [ ] **Step 5: Wire the factory into `src/detect_forge/settings.py`**

Replace the file contents with:
```python
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache import _default_cache_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DETECT_FORGE_", env_file=".env", extra="ignore"
    )

    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False


settings = Settings()
```

Two changes from the previous version: the `env_prefix` flips to `DETECT_FORGE_`, and `cache_dir` uses `Field(default_factory=_default_cache_dir)`. The previously-pending TODO comment about `no_cache` is dropped — Task 4 wires the value through. The previously-hard-coded `cache_dir = Path.home() / ".cache" / "ttp-staleness"` is gone.

(Note: the env prefix change is a Task 4 concern; Steps 5 here both lines change at once because the file is rewritten. Step 6 of Task 3 confirms cache-related tests pass; the env-prefix tests will pass after Task 4 updates `tests/test_settings.py`.)

**Wait** — to keep this task focused on cache-dir only, do NOT change the env_prefix here. Keep `env_prefix="TTP_"` in this file and only update the `cache_dir` default. Then Task 4 flips the env_prefix in a dedicated commit. Adjust the replacement above accordingly:

```python
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache import _default_cache_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TTP_", env_file=".env", extra="ignore")

    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    # TODO(detect-forge): `no_cache` is unused — cli.py reads only the
    # --no-cache flag, so the documented TTP_NO_CACHE env var has no effect.
    # Wire it through cli.scan (e.g. ttl = 0 if no_cache or settings.no_cache).
    no_cache: bool = False


settings = Settings()
```

Use this version. The TODO and env_prefix stay as-is for now.

- [ ] **Step 6: Update `tests/test_settings.py` — the cache_dir default assertion**

Find:

Old:
```python
    assert s.cache_dir == Path.home() / ".cache" / "detect-forge"
```

This assertion is currently right *only* when `XDG_CACHE_HOME` is unset. Replace it with an XDG-aware version using `monkeypatch`:

Old (the whole test function — locate `def test_defaults_match_spec` or similar):
```python
def test_defaults_match_spec() -> None:
    s = Settings()
    assert s.cache_dir == Path.home() / ".cache" / "detect-forge"
    assert s.cache_ttl_hours == 24
    assert s.attack_domain == "enterprise-attack"
    assert s.no_cache is False
```

New:
```python
def test_defaults_match_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    s = Settings()
    assert s.cache_dir == Path.home() / ".cache" / "detect-forge"
    assert s.cache_ttl_hours == 24
    assert s.attack_domain == "enterprise-attack"
    assert s.no_cache is False
```

(The other test that already uses `TTP_CACHE_DIR` should still pass — the env var still overrides cache_dir via pydantic-settings regardless of the factory.)

- [ ] **Step 7: Run the full test suite**

Run:
```bash
pytest -q
```

Expected: PASS. The 3 new XDG tests plus the updated cache and settings tests should all be green.

- [ ] **Step 8: Update `tests/test_cli.py`'s cache_dir assertion to be XDG-aware**

`tests/test_cli.py` has an assertion that reads `kwargs["cache_dir"] == Path.home() / ".cache" / "detect-forge"`. That assertion is correct only when `XDG_CACHE_HOME` is unset. Wrap the test with a `monkeypatch.delenv` guard.

Find the test function (likely named `test_scan_default_cache_dir` or similar — find the line `assert kwargs["cache_dir"] == Path.home() / ".cache" / "detect-forge"` and inspect the surrounding `def test_...`).

Old (signature only — keep the body, add the monkeypatch parameter and delenv call):
```python
def test_scan_default_cache_dir_is_home_cache_ttp_staleness(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
```

New:
```python
def test_scan_default_cache_dir_is_home_cache_detect_forge(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
```

The body of the test is unchanged. If the test was named differently in the actual file, just rename to match the new path semantics (`detect_forge` instead of `ttp_staleness`).

If `pytest` isn't already imported at the top of `tests/test_cli.py`, add `import pytest`.

- [ ] **Step 9: Run full test suite again**

Run:
```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/detect_forge/cache.py src/detect_forge/settings.py tests/test_cache.py tests/test_cache_xdg.py tests/test_settings.py tests/test_cli.py
git commit -m "feat: XDG-aware default cache dir via _default_cache_dir factory"
```

---

## Task 4: Flip env prefix `TTP_` → `DETECT_FORGE_` and wire `no_cache` through (TDD)

**Goal:** Change the pydantic-settings env prefix, resolve the `no_cache` TODO by reading `DETECT_FORGE_NO_CACHE` into the runtime ttl logic, and update tests accordingly. Hard cut — no `TTP_*` is read.

**Files:**
- Modify: `src/detect_forge/settings.py` (env_prefix + remove TODO)
- Modify: `src/detect_forge/cli.py` (ttl now also considers `settings.no_cache`)
- Modify: `tests/test_settings.py` (already partially DETECT_FORGE_-prefixed from Task 1)
- Add new test: `tests/test_cli.py::test_scan_honors_settings_no_cache`

- [ ] **Step 1: Write failing test — settings.no_cache forces ttl=0**

Append to `tests/test_cli.py`:
```python
def test_scan_honors_settings_no_cache(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DETECT_FORGE_NO_CACHE=true must force ttl=0 even without the --no-cache flag."""
    monkeypatch.setenv("DETECT_FORGE_NO_CACHE", "true")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["ttl_hours"] == 0
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_cli.py::test_scan_honors_settings_no_cache -q
```

Expected: FAIL — `assert 24 == 0` (the env var is read, but `cli.scan` only checks the `--no-cache` flag).

- [ ] **Step 3: Update `src/detect_forge/cli.py` — combine flag with settings**

Old:
```python
    ttl = 0 if no_cache else settings.cache_ttl_hours
```
New:
```python
    ttl = 0 if (no_cache or settings.no_cache) else settings.cache_ttl_hours
```

- [ ] **Step 4: Update `src/detect_forge/settings.py` — env_prefix + drop TODO**

Replace the file contents with:
```python
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache import _default_cache_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DETECT_FORGE_", env_file=".env", extra="ignore"
    )

    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False


settings = Settings()
```

The TODO comment is dropped — Step 3 wired `no_cache` through, so it's now actually used.

- [ ] **Step 5: Run the test suite**

Run:
```bash
pytest -q
```

Expected: PASS. The new `test_scan_honors_settings_no_cache` is green. The previously-updated `test_settings.py` (Task 1) tests already use `DETECT_FORGE_*` so they should pass cleanly with the new prefix.

- [ ] **Step 6: Sweep for any lingering `TTP_` reference**

Run:
```bash
grep -rn "TTP_\|env_prefix=\"TTP_\"" src/ tests/ 2>&1 | grep -v __pycache__
```

Expected: no results. If anything remains in tests, replace `TTP_` with `DETECT_FORGE_`.

- [ ] **Step 7: Commit**

```bash
git add src/detect_forge/settings.py src/detect_forge/cli.py tests/test_cli.py
git commit -m "feat: switch env prefix to DETECT_FORGE_; wire no_cache through to scan"
```

---

## Task 5: Split `cli.py` into root group + `stale.cli` subcommand (TDD)

**Goal:** Restructure `src/detect_forge/cli.py` so it only declares the root `main` click group and calls each subpackage's `register(group)`. Move the existing `scan` command body verbatim into a new `src/detect_forge/stale/cli.py` as `stale_cmd`, rename to `stale`, and expose `register()`. No behavior change.

**Files:**
- Create: `src/detect_forge/stale/cli.py`
- Modify: `src/detect_forge/cli.py` (becomes thin root)
- Modify: `tests/test_cli.py` (the existing `scan` tests now invoke `stale`)

- [ ] **Step 1: Write failing test — the command is now `stale`**

In `tests/test_cli.py`, find every occurrence of the string `["scan",` and `["scan"` in `runner.invoke(main, [...])` calls. Plan to replace `"scan"` with `"stale"` in the invocation. Do not change the rest of the test bodies. Use replace_all=true for the literal strings if they are unique to this pattern.

Pre-emptive Edit (apply now):

Old (replace_all=true):
```python
runner.invoke(main, ["scan",
```
New:
```python
runner.invoke(main, ["stale",
```

Also handle the help-test invocation:

Old:
```python
    result = runner.invoke(main, ["scan", "--help"])
```
New:
```python
    result = runner.invoke(main, ["stale", "--help"])
```

(If `replace_all=true` for `["scan",` already caught this, the Edit will fail — skip it.)

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_cli.py -q
```

Expected: most `stale`-invoking tests FAIL because the `main` group has no `stale` command yet.

- [ ] **Step 3: Create `src/detect_forge/stale/cli.py`**

```python
from __future__ import annotations

from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..console import err_console
from ..exit_codes import GATED
from ..settings import settings


@click.command(name="stale")
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
@click.pass_context
def stale_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    min_severity: str,
    no_cache: bool,
    domain: str,
) -> None:
    """Score detection rules for ATT&CK technique staleness."""
    from . import attack_client, reporter, rule_parser, scorer

    ttl = 0 if (no_cache or settings.no_cache) else settings.cache_ttl_hours

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
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    """Attach the `stale` command to a parent click group."""
    group.add_command(stale_cmd)
```

Two behavior-irrelevant differences from the old `scan`: (a) lazy imports become relative-to-stale (`from . import attack_client, ...`), and (b) `sys.exit(GATED)` is replaced by `ctx.exit(GATED)` — Click's idiomatic pattern within a `@click.pass_context` command.

- [ ] **Step 4: Replace `src/detect_forge/cli.py` with the thin root group**

```python
from __future__ import annotations

import click

from .stale import cli as stale_cli


@click.group()
@click.version_option(package_name="detect-forge")
def main() -> None:
    """Detection engineering toolkit. One install, one config, one CI step."""


stale_cli.register(main)


if __name__ == "__main__":
    main()
```

The `scan` command body and all its decorators are gone — `stale/cli.py` owns them now. The root file becomes a registry.

- [ ] **Step 5: Run the test suite**

Run:
```bash
pytest -q
```

Expected: PASS. The mocker.patch targets in `tests/test_cli.py` still point at `detect_forge.stale.attack_client.*` (Task 1 updated them), and those are the symbols the new `stale_cmd` lazily imports.

- [ ] **Step 6: Smoke-check**

Run:
```bash
detect-forge --version
detect-forge --help
detect-forge stale --help
```

Expected:
- `--version` prints `detect-forge, version 0.1.0`
- `detect-forge --help` lists `stale` as a subcommand
- `detect-forge stale --help` shows the existing flag surface

- [ ] **Step 7: Commit**

```bash
git add src/detect_forge/cli.py src/detect_forge/stale/cli.py tests/test_cli.py
git commit -m "refactor: split cli.py into root group + stale.cli subcommand"
```

---

## Task 6: Shared output options decorator (`common.py`) (TDD)

**Goal:** Factor the three reusable click options (`--format`, `--output`, `--min-severity`) into a `@common_output_options` decorator so future subcommands compose them in one line. Refactor `stale.cli` to use the decorator without changing its surface.

**Files:**
- Create: `src/detect_forge/common.py`
- Create: `tests/test_common.py`
- Modify: `src/detect_forge/stale/cli.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_common.py`:
```python
from __future__ import annotations

import click
from click.testing import CliRunner

from detect_forge.common import common_output_options


def test_common_output_options_adds_three_flags() -> None:
    @click.command()
    @common_output_options
    def cmd(output_format: str, output: str | None, min_severity: str) -> None:
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(cmd, ["--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--output" in result.output
    assert "-o" in result.output
    assert "--min-severity" in result.output


def test_common_output_options_defaults() -> None:
    @click.command()
    @common_output_options
    def cmd(output_format: str, output: str | None, min_severity: str) -> None:
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(cmd, [])
    assert result.exit_code == 0
    assert result.output.strip() == "terminal|None|low"


def test_common_output_options_accepts_values(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "out.json"

    @click.command()
    @common_output_options
    def cmd(output_format: str, output, min_severity: str) -> None:  # type: ignore[no-untyped-def]
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(
        cmd,
        ["--format", "json", "-o", str(target), "--min-severity", "high"],
    )
    assert result.exit_code == 0
    assert f"json|{target}|high" in result.output
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_common.py -q
```

Expected: FAIL — `ModuleNotFoundError: No module named 'detect_forge.common'`.

- [ ] **Step 3: Implement `src/detect_forge/common.py`**

```python
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, TypeVar

import click

F = TypeVar("F", bound=Callable[..., Any])


def common_output_options(func: F) -> F:
    """Add `--format`, `--output`, and `--min-severity` to a click command.

    Three options are added in this order (Click applies decorators bottom-up,
    so the resulting --help order is format → output → min-severity):

    - ``--format / -f`` (choice: terminal | json | html, default terminal)
    - ``--output / -o`` (Path, default None)
    - ``--min-severity`` (choice: low | medium | high | critical, default low)
    """
    func = click.option(
        "--min-severity",
        type=click.Choice(["low", "medium", "high", "critical"]),
        default="low",
        show_default=True,
        help="Only show rules at or above this severity",
    )(func)
    func = click.option(
        "--output",
        "-o",
        type=click.Path(path_type=Path),
        default=None,
        help="Write output to file instead of stdout",
    )(func)
    func = click.option(
        "--format",
        "output_format",
        type=click.Choice(["terminal", "json", "html"]),
        default="terminal",
        show_default=True,
        help="Output format",
    )(func)
    return func
```

- [ ] **Step 4: Run the common-options tests, confirm pass**

Run:
```bash
pytest tests/test_common.py -q
```

Expected: PASS (3 passed).

- [ ] **Step 5: Refactor `src/detect_forge/stale/cli.py` to use the decorator**

Replace the three top decorators (`--format`, `--output`, `--min-severity`) with a single `@common_output_options`. The final file:

```python
from __future__ import annotations

from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..common import common_output_options
from ..console import err_console
from ..exit_codes import GATED
from ..settings import settings


@click.command(name="stale")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@common_output_options
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
@click.pass_context
def stale_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    min_severity: str,
    no_cache: bool,
    domain: str,
) -> None:
    """Score detection rules for ATT&CK technique staleness."""
    from . import attack_client, reporter, rule_parser, scorer

    ttl = 0 if (no_cache or settings.no_cache) else settings.cache_ttl_hours

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
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    """Attach the `stale` command to a parent click group."""
    group.add_command(stale_cmd)
```

- [ ] **Step 6: Run the full test suite, confirm all `stale`-CLI tests still pass**

Run:
```bash
pytest -q
```

Expected: PASS. The shared decorator preserves option names and defaults so the existing stale tests are unaffected.

- [ ] **Step 7: Commit**

```bash
git add src/detect_forge/common.py src/detect_forge/stale/cli.py tests/test_common.py
git commit -m "feat: add @common_output_options decorator; reuse in stale.cli"
```

---

## Task 7: Public `stale.scan()` Python API (TDD)

**Goal:** Extract the orchestration logic (build_index → parse_rule_dir → score_rules) from `stale.cli` into a public Python function `detect_forge.stale.scan()`, so consumers can call it programmatically per the OS-documented API. The click command becomes a thin wrapper around it.

**Files:**
- Modify: `src/detect_forge/stale/__init__.py` (re-exports + scan() function)
- Modify: `src/detect_forge/stale/cli.py` (calls scan() instead of orchestrating inline)
- Create: `tests/test_stale_api.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_stale_api.py`:
```python
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pytest_mock import MockerFixture

from detect_forge.stale import scan
from detect_forge.stale.models import AttackIndex, StalenessReport


def _empty_index() -> AttackIndex:
    return AttackIndex(fetched_at=datetime.now(UTC))


def test_scan_returns_staleness_report(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    report = scan(empty_rule_dir)
    assert isinstance(report, StalenessReport)


def test_scan_passes_domain_and_ttl(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    bi = mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    scan(empty_rule_dir, domain="ics-attack", cache_ttl_hours=12)
    assert bi.call_args.kwargs["domain"] == "ics-attack"
    assert bi.call_args.kwargs["ttl_hours"] == 12


def test_scan_no_cache_forces_ttl_zero(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    bi = mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    scan(empty_rule_dir, no_cache=True, cache_ttl_hours=999)
    assert bi.call_args.kwargs["ttl_hours"] == 0
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/test_stale_api.py -q
```

Expected: FAIL — `ImportError: cannot import name 'scan' from 'detect_forge.stale'`.

- [ ] **Step 3: Implement `src/detect_forge/stale/__init__.py`**

```python
from __future__ import annotations

from pathlib import Path

from ..cache import _default_cache_dir
from .attack_client import build_index
from .models import (
    AttackIndex,
    AttackTechnique,
    ReportSummary,
    RuleScore,
    SeverityLevel,
    SigmaRule,
    StalenessReport,
    TechniqueFinding,
)
from .reporter import render
from .rule_parser import parse_rule_dir
from .scorer import score_rule, score_rules

__all__ = [
    "AttackIndex",
    "AttackTechnique",
    "ReportSummary",
    "RuleScore",
    "SeverityLevel",
    "SigmaRule",
    "StalenessReport",
    "TechniqueFinding",
    "build_index",
    "parse_rule_dir",
    "render",
    "scan",
    "score_rule",
    "score_rules",
]


def scan(
    rule_dir: Path,
    *,
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    cache_ttl_hours: int = 24,
    no_cache: bool = False,
) -> StalenessReport:
    """Run a stale scan and return the structured StalenessReport.

    Public Python API for the `stale` capability. The CLI subcommand
    (`detect-forge stale`) wraps this with output rendering and exit-code
    logic; programmatic callers can use the returned ``StalenessReport``
    directly.

    Args:
        rule_dir: Directory containing Sigma rules to scan.
        domain: ATT&CK domain identifier ("enterprise-attack", "ics-attack",
            or "mobile-attack"). Defaults to enterprise.
        cache_dir: Where to read/write the cached STIX bundle. Defaults to
            ``_default_cache_dir()`` (XDG-aware).
        cache_ttl_hours: Cache TTL in hours. Ignored if ``no_cache`` is True.
        no_cache: If True, bypass the cache and refetch.

    Returns:
        A ``StalenessReport`` aggregating per-rule findings.
    """
    ttl = 0 if no_cache else cache_ttl_hours
    resolved_cache_dir = cache_dir if cache_dir is not None else _default_cache_dir()
    index = build_index(domain=domain, cache_dir=resolved_cache_dir, ttl_hours=ttl)
    rules = parse_rule_dir(rule_dir)
    return score_rules(rules, index)
```

- [ ] **Step 4: Run API tests, confirm pass**

Run:
```bash
pytest tests/test_stale_api.py -q
```

Expected: PASS (3 passed).

- [ ] **Step 5: Refactor `stale.cli.stale_cmd` to delegate to `scan()`**

Replace the body of `stale_cmd` so the orchestration calls `scan()`. Final file:

```python
from __future__ import annotations

from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..common import common_output_options
from ..console import err_console
from ..exit_codes import GATED
from ..settings import settings


@click.command(name="stale")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@common_output_options
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
@click.pass_context
def stale_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    min_severity: str,
    no_cache: bool,
    domain: str,
) -> None:
    """Score detection rules for ATT&CK technique staleness."""
    from . import reporter, scan

    effective_no_cache = no_cache or settings.no_cache

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        t = progress.add_task("Scoring rules against ATT&CK...", total=None)
        report = scan(
            rule_dir,
            domain=domain,
            cache_dir=settings.cache_dir,
            cache_ttl_hours=settings.cache_ttl_hours,
            no_cache=effective_no_cache,
        )
        progress.remove_task(t)

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
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    """Attach the `stale` command to a parent click group."""
    group.add_command(stale_cmd)
```

The three-spinner progress is collapsed into a single task because `scan()` is now opaque from the CLI's perspective. If the per-stage spinner detail matters, the implementer can split `scan()` into named steps later; for now, one spinner is fine.

- [ ] **Step 6: Run the full test suite**

Run:
```bash
pytest -q
```

Expected: PASS. The existing CLI tests mock `attack_client.build_index`, `rule_parser.parse_rule_dir`, and `scorer.score_rules` directly via their module paths — those are still the symbols `scan()` calls internally, so the mocks intercept correctly.

- [ ] **Step 7: Commit**

```bash
git add src/detect_forge/stale/__init__.py src/detect_forge/stale/cli.py tests/test_stale_api.py
git commit -m "feat: add public detect_forge.stale.scan() API; cli delegates to it"
```

---

## Task 8: Stub subcommands (`backtest`, `coverage`, `cti`, `audit`) (TDD)

**Goal:** Add four subcommand stubs to the root group. Each prints a not-implemented stderr message and exits `1` (`RESERVED`). `cti` is a click group with one registered child (`ingest`). The audit stub uses a "reserved" message wording.

**Files:**
- Create: `src/detect_forge/_stubs.py`
- Create: `src/detect_forge/backtest/cli.py`
- Create: `src/detect_forge/coverage/cli.py`
- Create: `src/detect_forge/cti/cli.py`
- Create: `src/detect_forge/audit/cli.py`
- Create: `tests/stubs/__init__.py`
- Create: `tests/stubs/test_stub_subcommands.py`
- Modify: `src/detect_forge/cli.py` (register all stubs)

- [ ] **Step 1: Write failing tests**

Create `tests/stubs/__init__.py` empty.

Create `tests/stubs/test_stub_subcommands.py`:
```python
from __future__ import annotations

from click.testing import CliRunner

from detect_forge.cli import main
from detect_forge.exit_codes import RESERVED


def _invoke(args: list[str]) -> tuple[int, str, str]:
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(main, args)
    return result.exit_code, result.stdout, result.stderr


def test_backtest_stub_message_and_exit() -> None:
    code, stdout, stderr = _invoke(["backtest"])
    assert code == RESERVED
    assert "'backtest' is not yet implemented" in stderr
    assert "Jun 28, 2026" in stderr
    assert "github.com/Detect-Forge/detect-forge" in stderr
    assert stdout == ""


def test_coverage_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["coverage"])
    assert code == RESERVED
    assert "'coverage' is not yet implemented" in stderr
    assert "Q3 2026" in stderr


def test_cti_group_help_shows_ingest() -> None:
    code, stdout, _stderr = _invoke(["cti", "--help"])
    assert code == 0
    assert "ingest" in stdout


def test_cti_ingest_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["cti", "ingest", "/tmp/anything.pdf"])
    assert code == RESERVED
    assert "'cti ingest' is not yet implemented" in stderr
    assert "Q3" in stderr  # matches "Q3" or "Q3–Q4 2026"


def test_audit_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["audit"])
    assert code == RESERVED
    assert "Reserved" in stderr
    assert "runs every check" in stderr


def test_main_help_lists_all_subcommands() -> None:
    code, stdout, _stderr = _invoke(["--help"])
    assert code == 0
    for cmd in ("stale", "backtest", "coverage", "cti", "audit"):
        assert cmd in stdout
```

- [ ] **Step 2: Run, confirm failure**

Run:
```bash
pytest tests/stubs/ -q
```

Expected: FAIL — `No such command 'backtest'` (or similar). The root cli only registers `stale` so far.

- [ ] **Step 3: Implement `src/detect_forge/_stubs.py`**

```python
from __future__ import annotations

import click

from .console import err_console
from .exit_codes import RESERVED


def stub_command(name: str, message: str, *, help_text: str | None = None) -> click.Command:
    """Return a click command that prints `message` to stderr and exits RESERVED.

    Used by every subcommand that is registered for discoverability but has
    not yet been implemented.

    Args:
        name: The command name as it appears on the CLI.
        message: Multi-line stderr message printed before exit.
        help_text: Optional one-line summary shown in the parent group's
            `--help` listing. Defaults to the first line of ``message``.
    """
    summary = help_text if help_text is not None else message.split("\n", 1)[0]

    @click.command(name=name, help=summary)
    @click.argument("args", nargs=-1, type=click.UNPROCESSED)
    @click.pass_context
    def _stub(ctx: click.Context, args: tuple[str, ...]) -> None:
        _ = args  # accept and ignore any positional args so users hit the stub
        err_console.print(message)
        ctx.exit(RESERVED)

    return _stub
```

The `args` parameter with `click.UNPROCESSED` lets stubs accept and ignore positional args (so `detect-forge backtest ./rules` still hits the stub instead of failing argument parsing).

- [ ] **Step 4: Implement `src/detect_forge/backtest/cli.py`**

```python
from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'backtest' is not yet implemented.\n"
    "Ship target: Jun 28, 2026.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

backtest_cmd = stub_command(
    "backtest",
    _MESSAGE,
    help_text="Adversarial replay (not yet implemented).",
)


def register(group: click.Group) -> None:
    group.add_command(backtest_cmd)
```

- [ ] **Step 5: Implement `src/detect_forge/coverage/cli.py`**

```python
from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'coverage' is not yet implemented.\n"
    "Ship target: Q3 2026.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

coverage_cmd = stub_command(
    "coverage",
    _MESSAGE,
    help_text="Coverage gap mapping (not yet implemented).",
)


def register(group: click.Group) -> None:
    group.add_command(coverage_cmd)
```

- [ ] **Step 6: Implement `src/detect_forge/cti/cli.py`**

```python
from __future__ import annotations

import click

from .._stubs import stub_command

_INGEST_MESSAGE = (
    "detect-forge: 'cti ingest' is not yet implemented.\n"
    "Ship target: Q3–Q4 2026.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)


@click.group(name="cti")
def cti_group() -> None:
    """CTI-to-detection generation (not yet implemented)."""


cti_ingest_cmd = stub_command(
    "ingest",
    _INGEST_MESSAGE,
    help_text="Generate detections from a CTI report (not yet implemented).",
)
cti_group.add_command(cti_ingest_cmd)


def register(group: click.Group) -> None:
    group.add_command(cti_group)
```

- [ ] **Step 7: Implement `src/detect_forge/audit/cli.py`**

```python
from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'audit' is Reserved — runs every check once 2+ subcommands ship.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

audit_cmd = stub_command(
    "audit",
    _MESSAGE,
    help_text="Reserved — runs every check once 2+ subcommands ship.",
)


def register(group: click.Group) -> None:
    group.add_command(audit_cmd)
```

- [ ] **Step 8: Update `src/detect_forge/cli.py` to register all five subcommands**

Replace the file contents with:
```python
from __future__ import annotations

import click

from .audit import cli as audit_cli
from .backtest import cli as backtest_cli
from .coverage import cli as coverage_cli
from .cti import cli as cti_cli
from .stale import cli as stale_cli


@click.group()
@click.version_option(package_name="detect-forge")
def main() -> None:
    """Detection engineering toolkit. One install, one config, one CI step."""


stale_cli.register(main)
backtest_cli.register(main)
coverage_cli.register(main)
cti_cli.register(main)
audit_cli.register(main)


if __name__ == "__main__":
    main()
```

- [ ] **Step 9: Run the full test suite**

Run:
```bash
pytest -q
```

Expected: PASS. All 6 new stub tests plus every existing test.

- [ ] **Step 10: Smoke-check the suite**

Run:
```bash
detect-forge --help
detect-forge backtest ./anything
echo "exit: $?"
detect-forge cti --help
detect-forge cti ingest /tmp/x.pdf
echo "exit: $?"
detect-forge audit
echo "exit: $?"
```

Expected:
- `--help` lists all five subcommands.
- `backtest`, `cti ingest`, `audit` each print their stderr message and exit `1`.
- `cti --help` lists `ingest`.

- [ ] **Step 11: Commit**

```bash
git add src/detect_forge/_stubs.py src/detect_forge/backtest src/detect_forge/coverage src/detect_forge/cti src/detect_forge/audit src/detect_forge/cli.py tests/stubs
git commit -m "feat: add backtest/coverage/cti/audit subcommand stubs (exit 1)"
```

---

## Task 9: Rewrite the README for the rebrand

**Goal:** Replace `README.md` contents to reflect the new name, subcommand surface, env vars, and exit codes. No code changes.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `README.md` contents**

Use the Write tool to overwrite the file with:

````markdown
# Detect-Forge

Detection engineering toolkit. One install, one config, one CI step.

## Overview

Detect-Forge is a composable CLI for detection engineers. Each capability is a subcommand; they share configuration, output formatting, caching, and a single CI gate. No platform, no sign-up.

The first shipping capability is `stale` — it scores your Sigma detection rules for ATT&CK technique staleness along three dimensions:

1. **Timestamp drift** — compares ATT&CK STIX `modified` timestamps to rule modification dates (deterministic).
2. **Semantic drift** *(in progress)* — embeddings-based cosine similarity between rule detection logic and current ATT&CK technique description.
3. **LLM diff proposals** *(planned)* — opt-in, BYOLLM (OpenAI primary, Claude secondary); proposes updated rules for flagged stale entries.

Designed to run in GitHub Actions as a CI gate. No data leaves your environment.

## Status

🔨 Building toward May 23, 2026 launch — `stale` semantic drift layer in progress (Phase 3). LLM diff proposal layer planned (Phase 4). Other subcommands (`backtest`, `coverage`, `cti ingest`, `audit`) are registered as stubs and will ship in subsequent releases.

## Requirements

- Python **3.12** or newer

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
detect-forge --help
detect-forge --version
detect-forge stale path/to/rules
```

### Subcommands

| Command | Status | Description |
|---|---|---|
| `stale` | ✅ Available | Score detection rules for ATT&CK technique staleness. |
| `backtest` | 📅 Jun 28, 2026 | Adversarial replay (Types 3 + 4). |
| `coverage` | 📝 Q3 2026 | Coverage gap mapping (Type 6a expansion). |
| `cti ingest` | 📝 Q3–Q4 2026 | CTI-to-detection generation. |
| `audit` | 📝 Reserved | Runs every check once 2+ subcommands ship. |

### `stale` options

| Option | Default | Description |
|---|---|---|
| `RULE_DIR` (positional) | — | Directory of Sigma rules to scan. Must exist. |
| `--format {terminal,json,html}` | `terminal` | Output format. |
| `-o, --output PATH` | _stdout_ | Write output to a file instead of stdout. |
| `--min-severity {low,medium,high,critical}` | `low` | Only show rules at or above this severity. |
| `--no-cache` | off | Bypass the disk cache and fetch a fresh ATT&CK bundle. |
| `--domain {enterprise-attack,ics-attack,mobile-attack}` | `enterprise-attack` | ATT&CK domain to fetch. |

Progress spinners go to **stderr**; the report goes to **stdout** so JSON output can be piped safely:

```bash
detect-forge stale path/to/rules --format json | jq '.scores'
detect-forge stale path/to/rules --format json -o report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no gating findings (CI passes). |
| `1` | Tool error, stub command, or unimplemented capability. |
| `2` | CI-gating condition met (e.g. `stale` found a critical finding). |

Use `exit-code 2` to fail your CI pipeline:

```bash
detect-forge stale path/to/rules || [ $? -ne 2 ] && exit $?
```

### Environment variables

All settings can be overridden via `DETECT_FORGE_`-prefixed env vars (or a `.env` file in the working directory):

| Variable | Default | Purpose |
|---|---|---|
| `DETECT_FORGE_CACHE_DIR` | `$XDG_CACHE_HOME/detect-forge` (or `~/.cache/detect-forge`) | Where the ATT&CK bundle is cached. |
| `DETECT_FORGE_CACHE_TTL_HOURS` | `24` | Cache lifetime in hours. |
| `DETECT_FORGE_ATTACK_DOMAIN` | `enterprise-attack` | Default `--domain` value. |
| `DETECT_FORGE_NO_CACHE` | `false` | If truthy, always bypass the cache. |

## Python API

Each subcommand exposes a programmatic API for power users:

```python
from pathlib import Path
from detect_forge.stale import scan

report = scan(Path("./rules"), domain="enterprise-attack")
for score in report.scores:
    if score.worst_severity == "critical":
        print(f"{score.title}: {score.worst_days_stale} days stale")
```

## Development

```bash
pytest -q                     # run the test suite
ruff check src/ tests/        # lint
mypy src/                     # type-check (strict)
```

The package layout:

```
src/detect_forge/
├── cli.py              # click root group; registers all subcommands
├── settings.py         # DETECT_FORGE_* pydantic-settings config
├── console.py          # rich stdout + stderr consoles
├── cache.py            # XDG-aware cache (DEFAULT_CACHE_DIR via _default_cache_dir())
├── common.py           # @common_output_options decorator
├── exit_codes.py       # CLEAN=0, RESERVED=1, GATED=2
├── _stubs.py           # stub_command() helper
├── stale/              # the staleness pipeline (real subcommand)
├── backtest/           # stub
├── coverage/           # stub
├── cti/                # group + ingest stub
└── audit/              # stub
```

## License

MIT
````

- [ ] **Step 2: Verify no remaining `ttp-staleness` references**

Run:
```bash
grep -n "ttp.staleness\|TTP.Staleness\|TTP_" README.md
```

Expected: no results.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for detect-forge rebrand"
```

---

## Task 10: Definition-of-Done verification

**Goal:** Run lint, types, the full test suite, and a manual end-to-end smoke against `data/rules` (which still contains `.toml` fixtures — those won't be picked up by the `.yml` glob, that's the preserved TODO). Capture any issues as bug-fix commits before declaring done.

**Files:** none new — verification only.

- [ ] **Step 1: Lint**

Run:
```bash
ruff check src/ tests/
```

Expected: `All checks passed!` If any issues, fix the specific finding (do not add blanket ignores) and re-run.

- [ ] **Step 2: Type check**

Run:
```bash
mypy src/
```

Expected: `Success: no issues found in N source files`. If new mypy errors surface in `_stubs.py` or stub `cli.py` files (e.g. unused-arg warnings, untyped decorators), fix narrowly.

- [ ] **Step 3: Full test suite**

Run:
```bash
pytest -q
```

Expected: every test passes — original 38 plus new ones from Tasks 2-8 (3 + 3 + 1 + 3 + 3 + 6 = 19 new tests; final count ≈ 57). Record the count.

- [ ] **Step 4: Acceptance criteria from the spec**

Run each command and verify:

```bash
# Acceptance: detect-forge installs with the right name
pip show detect-forge | head -3
# Expected: Name: detect-forge

# Acceptance: --help lists all five subcommands
detect-forge --help
# Expected output contains: stale, backtest, coverage, cti, audit

# Acceptance: stale runs on an empty dir and exits cleanly
mkdir -p /tmp/empty-rules
detect-forge stale /tmp/empty-rules --format json
echo "exit: $?"
# Expected: valid JSON to stdout, exit: 0

# Acceptance: stubs exit 1 with stderr message
detect-forge backtest /tmp/empty-rules 2>/tmp/err.log; echo "exit: $?"
cat /tmp/err.log
# Expected: exit: 1, message contains "not yet implemented" and "Jun 28, 2026"

detect-forge coverage /tmp/empty-rules 2>/tmp/err.log; echo "exit: $?"
detect-forge cti ingest /tmp/x.pdf 2>/tmp/err.log; echo "exit: $?"
detect-forge audit /tmp/empty-rules 2>/tmp/err.log; echo "exit: $?"
# All expected: exit: 1

# Acceptance: DETECT_FORGE_CACHE_DIR is honored
DETECT_FORGE_CACHE_DIR=/tmp/dfcache detect-forge stale /tmp/empty-rules --format json > /dev/null
ls /tmp/dfcache
# Expected: directory exists; contains enterprise-attack.json after first run

# Acceptance: XDG_CACHE_HOME is honored when DETECT_FORGE_CACHE_DIR is unset
unset DETECT_FORGE_CACHE_DIR
XDG_CACHE_HOME=/tmp/xdg detect-forge stale /tmp/empty-rules --format json > /dev/null
ls /tmp/xdg/detect-forge
# Expected: enterprise-attack.json present
```

If any acceptance check fails, open a focused commit to fix the underlying issue, then re-run that step.

- [ ] **Step 5: Verify no `ttp_staleness` / `TTP_` / `ttp-staleness` references anywhere**

Run:
```bash
grep -rn "ttp_staleness\|ttp-staleness\|TTP-Staleness\|TTP_" src/ tests/ pyproject.toml README.md 2>&1 | grep -v __pycache__
```

Expected: no results.

- [ ] **Step 6: Verify the .toml-vs-.yml TODO is preserved**

Run:
```bash
grep -n "TODO(detect-forge)" src/detect_forge/stale/rule_parser.py
```

Expected: one TODO referencing the `.toml`/`.yml` mismatch — confirms Step 12 of Task 1 didn't accidentally remove it.

- [ ] **Step 7: Final commit (only if any fixes from Steps 1-6 were needed)**

If everything passed cleanly, no commit needed. If fixes happened, commit them with focused messages and a short note in the body.

---

## Definition of Done (from spec — final check)

- [ ] `pip install -e ".[dev]"` installs the package as `detect-forge`.
- [ ] `detect-forge --help` lists all five subcommands (`stale`, `backtest`, `coverage`, `cti`, `audit`).
- [ ] `detect-forge stale ./rules` produces the same structural output as the old `ttp-staleness scan ./rules` (modulo exit code).
- [ ] `detect-forge stale ./rules` exits `2` (not `1`) when a critical finding is present.
- [ ] `detect-forge backtest`, `coverage`, `cti ingest`, `audit` each print the stub stderr message and exit `1`.
- [ ] `DETECT_FORGE_CACHE_DIR=/tmp/x` redirects the cache; `XDG_CACHE_HOME` fallback works when the env var is unset.
- [ ] `ruff check src/ tests/`, `mypy src/`, `pytest -q` all pass.
- [ ] No file under `src/` or `tests/` references `ttp_staleness`, `TTP_`, or `TTP-Staleness` (the preserved `data/rules` TODO comment uses `detect-forge stale` in its example, not the old name).
- [ ] `README.md` contains no `ttp-staleness` references.
- [ ] `from detect_forge.stale import scan` is callable; returns a `StalenessReport`.

## Out of Scope (per spec — confirm not done)

- `.detect-forge.toml` config file loading — deferred.
- Real implementations of `backtest`, `coverage`, `cti ingest`, `audit` — they remain stubs.
- Migration of `data/rules/*.toml` fixtures to `.yml` — TODO preserved.
- `AttackIndex.attack_version` population — TODO preserved.
- Any `ttp-staleness` alias / `TTP_*` env-var back-compat — hard cut, none added.
