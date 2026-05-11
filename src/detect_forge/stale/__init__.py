from __future__ import annotations

from pathlib import Path

from ..cache import default_cache_dir
from . import attack_client, rule_parser, scorer
from .attack_client import build_index
from .models import (
    AttackIndex,
    AttackTechnique,
    DetectionRule,
    DiffProposal,
    FindingKind,
    ReportSummary,
    RuleScore,
    SeverityLevel,
    StalenessReport,
    TechniqueFinding,
)
from .reporter import render
from .rule_parser import parse_rule_dir
from .scorer import score_rule, score_rules

__all__ = [
    "AttackIndex",
    "AttackTechnique",
    "DetectionRule",
    "DiffProposal",
    "FindingKind",
    "ReportSummary",
    "RuleScore",
    "SeverityLevel",
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
    semantic_threshold: float = 0.65,
    llm_model: str | None = None,
    max_proposals: int = 5,
) -> StalenessReport:
    """Run a stale scan and return the structured StalenessReport.

    Public Python API for the `stale` capability. The CLI subcommand
    (`detect-forge stale`) wraps this with output rendering and exit-code
    logic; programmatic callers can use the returned ``StalenessReport``
    directly.

    Args:
        rule_dir: Directory containing detection rules to scan. Recursively
            picks up Sigma (`.yml`/`.yaml`) and Elastic Detection Rules
            (`.toml`, covering EQL/KQL/ESQL).
        domain: ATT&CK domain identifier ("enterprise-attack", "ics-attack",
            or "mobile-attack"). Defaults to enterprise.
        cache_dir: Where to read/write the cached STIX bundle. Defaults to
            ``default_cache_dir()`` (XDG-aware).
        cache_ttl_hours: Cache TTL in hours. Ignored if ``no_cache`` is True.
        no_cache: If True, bypass the cache and refetch.
        semantic_threshold: Cosine similarity threshold; rule × technique pairs
            below this value emit a ``semantic_drift`` finding. Default ``0.65``.
        llm_model: If set (e.g. ``"gpt-4o-mini"``) AND ``OPENAI_API_KEY`` is
            present in the environment, the scorer will request an LLM-generated
            diff proposal for every rule with a ``semantic_drift`` finding, up
            to ``max_proposals`` total per scan. Defaults to ``None`` (off).
        max_proposals: Hard ceiling on proposal attempts per scan. Every attempt
            (success, refusal, or post-receive validation rejection) consumes
            one slot. Defaults to ``5``.

    Returns:
        A ``StalenessReport`` aggregating per-rule findings.
    """
    ttl = 0 if no_cache else cache_ttl_hours
    resolved_cache_dir = cache_dir if cache_dir is not None else default_cache_dir()
    index = attack_client.build_index(
        domain=domain, cache_dir=resolved_cache_dir, ttl_hours=ttl
    )
    rules = rule_parser.parse_rule_dir(rule_dir)
    return scorer.score_rules(
        rules,
        index,
        cache_dir=resolved_cache_dir,
        semantic_threshold=semantic_threshold,
        llm_model=llm_model,
        max_proposals=max_proposals,
    )
