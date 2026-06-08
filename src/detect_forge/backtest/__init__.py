"""Adversarial replay subcommand.

Public entry point: ``scan_backtest(rule_dir, *, domain, ..., mordor_source)``.

Returns a fully-resolved ``BacktestReport``. ``report.summary.priority_silent``
and ``report.summary.rules_silent_on_all`` drive the two CI gates.
"""

from __future__ import annotations

from pathlib import Path

from ..coverage.priority import resolve_priority_techniques
from ..stale.attack_client import build_index
from ..stale.rule_parser import parse_rule_dir
from .corpus import MordorCorpus
from .models import (
    BacktestReport,
    BacktestSummary,
    FireRecord,
    FireStatus,
    RuleResult,
    RuleStatus,
    TechniqueResult,
    TechniqueRollup,
    TechniqueStatus,
)
from .orchestrator import run_backtest

__all__ = [
    "BacktestReport",
    "BacktestSummary",
    "FireRecord",
    "FireStatus",
    "RuleResult",
    "RuleStatus",
    "TechniqueResult",
    "TechniqueRollup",
    "TechniqueStatus",
    "scan_backtest",
]

_VALID_PLATFORMS = frozenset({"windows", "linux", "macos", "all"})


def scan_backtest(
    rule_dir: Path,
    *,
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    cache_ttl_hours: int = 24,
    no_cache: bool = False,
    priority_list: Path | None = None,
    platform: str = "all",
    technique_filter: set[str] | None = None,
    mordor_source: Path | None = None,
) -> BacktestReport:
    """Run a backtest: parse rules, fetch ATT&CK, build corpus, evaluate.

    Args:
        rule_dir: Directory containing detection rules (Sigma .yml and/or
            Elastic .toml). Walked recursively.
        domain: ATT&CK domain.
        cache_dir: Override for the cache directory.
        cache_ttl_hours: STIX bundle cache lifetime.
        no_cache: Bypass STIX + Mordor caches when True.
        priority_list: Path to custom priority list JSON.
        platform: Mordor dataset platform filter. One of "windows", "linux",
            "macos", "all".
        technique_filter: Restrict the scan to these technique IDs.
        mordor_source: Local Security-Datasets checkout path.
    """
    if platform not in _VALID_PLATFORMS:
        raise ValueError(
            f"platform must be one of {sorted(_VALID_PLATFORMS)}, got {platform!r}"
        )
    rules = parse_rule_dir(rule_dir)
    index = build_index(
        domain=domain,
        cache_dir=cache_dir,
        ttl_hours=0 if no_cache else cache_ttl_hours,
    )
    priority_ids = resolve_priority_techniques(cli_path=priority_list)

    platform_filter: set[str] | None
    platform_filter = None if platform == "all" else {platform}

    effective_cache_dir = cache_dir if cache_dir is not None else _default_cache_dir()

    corpus = MordorCorpus(
        cache_dir=effective_cache_dir,
        platform_filter=platform_filter,
        technique_filter=technique_filter,
        source_override=mordor_source,
        no_cache=no_cache,
    )

    return run_backtest(rules, index, corpus, priority_ids)


def _default_cache_dir() -> Path:
    from ..cache import default_cache_dir
    return default_cache_dir()
