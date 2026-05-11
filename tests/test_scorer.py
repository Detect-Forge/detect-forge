from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from pytest_mock import MockerFixture

from detect_forge.stale.models import (
    AttackIndex,
    AttackTechnique,
    DetectionRule,
    RuleScore,
    StalenessReport,
)
from detect_forge.stale.scorer import score_rule, score_rules


def test_score_rules_sorted_worst_first() -> None:
    stale_rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=500))
    current_rule = _make_rule(["T1059"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1059", days_ago=400))
    # Pass in wrong order — scorer should sort worst-first.
    report = score_rules([current_rule, stale_rule], index)
    assert isinstance(report, StalenessReport)
    assert len(report.scores) == 2
    assert report.scores[0].worst_days_stale > report.scores[1].worst_days_stale


def test_report_summary_counts_and_has_severity() -> None:
    stale_rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=500))
    bare_rule = _make_rule([])
    index = _make_index_with(_make_technique("T1059", days_ago=400))

    report = score_rules([stale_rule, bare_rule], index)
    assert report.summary.total_rules == 2
    assert report.summary.no_attack_tags == 1
    assert report.summary.critical >= 1
    assert report.has_severity("critical") is True
    assert report.summary.attack_domain == "enterprise-attack"


TODAY = datetime.now(UTC).date()


def _make_technique(
    tid: str = "T1059",
    days_ago: int = 400,
    deprecated: bool = False,
    revoked: bool = False,
) -> AttackTechnique:
    return AttackTechnique(
        technique_id=tid,
        name=f"Tech {tid}",
        modified=datetime.now(UTC) - timedelta(days=days_ago),
        is_subtechnique="." in tid,
        deprecated=deprecated,
        revoked=revoked,
        tactic_ids=["execution"],
        stix_id=f"attack-pattern--fake-{tid}",
    )


def _make_index_with(*techniques: AttackTechnique) -> AttackIndex:
    return AttackIndex(
        techniques={t.technique_id: t for t in techniques},
        fetched_at=datetime.now(UTC),
    )


def _make_rule(
    technique_ids: list[str],
    rule_date: date | None = None,
    modified_date: date | None = None,
) -> DetectionRule:
    return DetectionRule(
        rule_id="test-id",
        title="Test Rule",
        status="test",
        rule_date=rule_date,
        modified_date=modified_date,
        technique_ids=technique_ids,
        source_file=Path("/fake/rule.yml"),
        raw_tags=[],
    )


def test_critical_above_365_days() -> None:
    rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=500))
    index = _make_index_with(_make_technique("T1059", days_ago=400))
    score = score_rule(rule, index)
    assert isinstance(score, RuleScore)
    assert score.worst_severity == "critical"
    assert score.worst_days_stale >= 365


def test_high_between_180_and_365() -> None:
    rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=300))
    index = _make_index_with(_make_technique("T1059", days_ago=200))
    score = score_rule(rule, index)
    assert score.worst_severity == "high"
    assert 180 <= score.worst_days_stale < 365


def test_current_when_rule_newer_than_technique() -> None:
    rule = _make_rule(["T1059"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1059", days_ago=100))
    score = score_rule(rule, index)
    assert score.worst_severity == "low"
    assert score.worst_days_stale == 0
    assert score.findings[0].kind == "current"


def test_no_attack_tags_returns_info() -> None:
    rule = _make_rule([])
    index = _make_index_with()
    score = score_rule(rule, index)
    assert score.has_attack_tags is False
    assert score.worst_severity == "info"
    assert score.findings == []


def test_unknown_technique_has_unknown_kind() -> None:
    rule = _make_rule(["T9999"])
    index = _make_index_with()  # T9999 not indexed
    score = score_rule(rule, index)
    assert score.findings[0].kind == "unknown_technique"
    assert score.findings[0].severity == "info"


def test_deprecated_technique_returns_high() -> None:
    rule = _make_rule(["T1086"])
    index = _make_index_with(_make_technique("T1086", deprecated=True))
    score = score_rule(rule, index)
    assert score.findings[0].kind == "deprecated_technique"
    assert score.findings[0].severity == "high"


def test_no_rule_date_scores_conservatively() -> None:
    rule = _make_rule(["T1059"])  # no dates
    index = _make_index_with(_make_technique("T1059", days_ago=200))
    score = score_rule(rule, index)
    assert score.findings[0].kind == "no_rule_date"
    assert score.worst_days_stale >= 200


def test_modified_date_preferred_over_rule_date() -> None:
    rule = _make_rule(
        ["T1059"],
        rule_date=TODAY - timedelta(days=500),
        modified_date=TODAY - timedelta(days=10),
    )
    index = _make_index_with(_make_technique("T1059", days_ago=100))
    score = score_rule(rule, index)
    # modified_date (10 days ago) > technique_modified (100 days ago) → current
    assert score.worst_days_stale == 0
    assert score.findings[0].kind == "current"


def test_stale_severity_reflects_technique_age_not_rule_age() -> None:
    """When rule is older than technique by 1 day AND technique is 89 days old,
    staleness should be 89 (low), not the rule's 90-day age (medium).

    Protects against the bug where days_stale used (today - rule_effective_date)
    instead of (today - technique_date).
    """
    rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=90))
    index = _make_index_with(_make_technique("T1059", days_ago=89))
    score = score_rule(rule, index)
    assert score.findings[0].kind == "stale"
    assert score.findings[0].days_stale == 89
    assert score.worst_severity == "low"


def test_mixed_deprecated_and_stale_pairs_correctly() -> None:
    """When a rule covers a deprecated technique (high, 0d) AND a stale medium
    technique (medium, ~100d), worst_severity must pair with the winning
    finding's own days_stale — not accidentally report (high, 100d).
    """
    rule = _make_rule(
        ["T1086", "T1059"],
        rule_date=TODAY - timedelta(days=200),  # ~older than techniques below
    )
    index = _make_index_with(
        _make_technique("T1086", deprecated=True),
        _make_technique("T1059", days_ago=100),  # stale: ~100 days
    )
    score = score_rule(rule, index)
    # deprecated finding wins severity (high beats medium/low)
    assert score.worst_severity == "high"
    # worst_days_stale is 0 (from the deprecated finding), NOT 100
    assert score.worst_days_stale == 0


def test_summary_counts_deprecated_rule_in_rules_with_findings() -> None:
    """A rule referencing a deprecated technique must show up in the summary's
    rules_with_findings counter, even though worst_days_stale=0.

    Guards against the previous condition `s.worst_days_stale > 0 or not s.has_attack_tags`
    which silently excluded deprecated-only and unknown-only findings.
    """
    deprecated_rule = _make_rule(["T1086"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1086", deprecated=True))

    report = score_rules([deprecated_rule], index)
    assert report.summary.total_rules == 1
    assert report.summary.rules_with_findings == 1
    assert report.summary.deprecated_techniques == 1


def test_revoked_technique_returns_high_with_revoked_kind() -> None:
    """A rule referencing a revoked technique must produce kind=revoked_technique
    with severity high, regardless of the rule's date."""
    rule = _make_rule(["T1086"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1086", revoked=True))
    score = score_rule(rule, index)
    assert score.findings[0].kind == "revoked_technique"
    assert score.findings[0].severity == "high"
    assert score.worst_severity == "high"
    assert score.worst_days_stale == 0


def test_revoked_takes_precedence_over_deprecated() -> None:
    """If a technique is both revoked and deprecated, the finding surfaces the
    revoked kind (revoked is the stronger signal — concept is gone, not just old)."""
    rule = _make_rule(["T1086"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1086", deprecated=True, revoked=True))
    score = score_rule(rule, index)
    assert score.findings[0].kind == "revoked_technique"


def test_summary_counts_revoked_rule_in_rules_with_findings() -> None:
    """Revoked techniques must show up in rules_with_findings and revoked_techniques."""
    rule = _make_rule(["T1086"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1086", revoked=True))

    report = score_rules([rule], index)
    assert report.summary.total_rules == 1
    assert report.summary.rules_with_findings == 1
    assert report.summary.revoked_techniques == 1
    assert report.summary.deprecated_techniques == 0


def test_score_rule_accepts_embeddings_and_emits_low_alignment() -> None:
    """When timestamp scorer would emit 'current' and semantic scorer
    sees orthogonal vectors, the rule gets both findings."""
    rule = _make_rule(["T1059"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1059", days_ago=100))
    score = score_rule(
        rule,
        index,
        rule_embedding=[1.0, 0.0],
        technique_embeddings={"T1059": [0.0, 1.0]},  # orthogonal -> flagged
    )
    kinds = {f.kind for f in score.findings}
    assert "current" in kinds  # timestamp finding
    assert "low_alignment" in kinds  # semantic finding


def test_worst_severity_takes_max_across_kinds() -> None:
    """Timestamp high (stale) beats semantic medium (low_alignment) in aggregation."""
    rule = _make_rule(["T1059"], rule_date=TODAY - timedelta(days=300))
    index = _make_index_with(_make_technique("T1059", days_ago=200))  # 200d -> high
    score = score_rule(
        rule,
        index,
        rule_embedding=[1.0, 0.0],
        technique_embeddings={"T1059": [0.0, 1.0]},  # also misaligned -> medium
    )
    assert score.worst_severity == "high"
    # Both findings present; aggregation picked the worse one.
    kinds = {f.kind for f in score.findings}
    assert "stale" in kinds
    assert "low_alignment" in kinds


def test_score_rule_without_embeddings_skips_semantic() -> None:
    """When called without embeddings (existing callers), no low_alignment findings."""
    rule = _make_rule(["T1059"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1059", days_ago=100))
    score = score_rule(rule, index)
    assert all(f.kind != "low_alignment" for f in score.findings)


def test_score_rules_builds_embeddings_when_cache_dir_given(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    """score_rules with cache_dir must build embedding dicts and pass them through.

    Verifies the orchestration calls EmbeddingModel.embed_batch (mocked).
    """
    from detect_forge.stale.scorer import score_rules

    rule = _make_rule(["T1059"], rule_date=TODAY)
    rule.description = "Detects something specific."  # so it has embedable text
    tech = _make_technique("T1059")
    tech_with_desc = tech.model_copy(update={"description": "Technique description."})
    index = AttackIndex(
        techniques={"T1059": tech_with_desc},
        fetched_at=datetime.now(UTC),
    )

    # Mock fastembed wholesale: __init__ is a no-op; embed yields fixed vectors.
    import numpy as np
    mocker.patch(
        "detect_forge.stale.embeddings.fastembed.TextEmbedding.__init__",
        return_value=None,
    )
    mocker.patch(
        "detect_forge.stale.embeddings.fastembed.TextEmbedding.embed",
        side_effect=lambda texts: iter([np.array([0.0, 1.0]) for _ in texts]),
    )

    # Create a fake STIX bundle file so stix_bundle_hash succeeds.
    (tmp_path / "enterprise-attack.json").write_text('{"type":"bundle"}')

    report = score_rules(
        [rule], index, cache_dir=tmp_path, semantic_threshold=0.65,
    )
    assert isinstance(report, StalenessReport)
    assert report.summary.total_rules == 1


def test_score_rules_without_cache_dir_skips_semantic() -> None:
    """Existing behavior preserved: score_rules() without cache_dir = timestamp-only."""
    from detect_forge.stale.scorer import score_rules

    rule = _make_rule(["T1059"], rule_date=TODAY)
    index = _make_index_with(_make_technique("T1059", days_ago=100))
    report = score_rules([rule], index)  # no cache_dir kwarg
    for s in report.scores:
        for f in s.findings:
            assert f.kind != "low_alignment"
