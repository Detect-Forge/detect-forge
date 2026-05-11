"""Semantic-drift scoring.

Given a rule, an ATT&CK index, and pre-computed embeddings (one vector for the
rule, one vector per technique in the index), produce zero-or-more
``TechniqueFinding`` entries of kind ``semantic_drift`` for technique pairs whose
cosine similarity falls below the threshold.

Callers (``scorer.score_rules``) batch all embedding work into two big
fastembed calls (one for techniques, one for rules) and inject the resulting
dicts here. This module knows nothing about fastembed or the cache layer.
"""

from __future__ import annotations

from .embeddings import cosine_similarity
from .models import (
    AttackIndex,
    AttackTechnique,
    DetectionRule,
    SeverityLevel,
    TechniqueFinding,
)

SEMANTIC_THRESHOLD_DEFAULT = 0.65
"""Cosine similarity at or above which a rule × technique pair is considered aligned."""

SEMANTIC_SEVERITY: SeverityLevel = "medium"
"""Severity bucket for all semantic_drift findings in v0.1 (single bucket per spec)."""


def _rule_text(rule: DetectionRule) -> str | None:
    """Return the natural-language text we embed for a rule, or None if empty."""
    parts = [rule.title]
    if rule.description:
        parts.append(rule.description)
    text = "\n".join(parts).strip()
    return text or None


def _technique_text(tech: AttackTechnique) -> str | None:
    """Return the natural-language text we embed for a technique, or None."""
    parts = [tech.name]
    if tech.description:
        parts.append(tech.description)
    text = "\n".join(parts).strip()
    return text or None


def score_rule_semantic(
    rule: DetectionRule,
    index: AttackIndex,
    rule_embedding: list[float] | None,
    technique_embeddings: dict[str, list[float]],
    threshold: float = SEMANTIC_THRESHOLD_DEFAULT,
) -> list[TechniqueFinding]:
    """Return zero-or-more semantic_drift findings for ``rule``.

    No-ops gracefully if the rule has no embedable text or if none of the
    rule's techniques have embedable descriptions in the index. The timestamp
    scorer already emits ``unknown_technique`` for techniques not in the
    index, so this function skips them silently.
    """
    if rule_embedding is None:
        return []

    findings: list[TechniqueFinding] = []
    for tech_id in rule.technique_ids:
        tech = index.techniques.get(tech_id)
        if tech is None:
            continue  # unknown_technique handled by timestamp scorer
        tech_emb = technique_embeddings.get(tech_id)
        if tech_emb is None:
            continue  # technique has no description text — skip silently
        sim = cosine_similarity(rule_embedding, tech_emb)
        if sim < threshold:
            findings.append(
                TechniqueFinding(
                    technique_id=tech_id,
                    technique_name=tech.name,
                    technique_modified=tech.modified,
                    rule_effective_date=rule.modified_date or rule.rule_date,
                    days_stale=0,
                    severity=SEMANTIC_SEVERITY,
                    kind="semantic_drift",
                    similarity_score=round(sim, 4),
                )
            )
    return findings
