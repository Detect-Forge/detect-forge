from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from detect_forge.stale._semantic import (
    SEMANTIC_SEVERITY,
    SEMANTIC_THRESHOLD_DEFAULT,
    _rule_text,
    _technique_text,
    score_rule_semantic,
)
from detect_forge.stale.models import (
    AttackIndex,
    AttackTechnique,
    DetectionRule,
)


def _make_technique(
    tid: str = "T1059",
    description: str | None = "A technique description.",
) -> AttackTechnique:
    return AttackTechnique(
        technique_id=tid,
        name="Tech Name",
        description=description,
        modified=datetime(2025, 1, 1, tzinfo=UTC),
        is_subtechnique="." in tid,
        stix_id=f"attack-pattern--fake-{tid}",
    )


def _make_index(*techs: AttackTechnique) -> AttackIndex:
    return AttackIndex(
        techniques={t.technique_id: t for t in techs},
        fetched_at=datetime.now(UTC),
    )


def _make_rule(
    technique_ids: list[str],
    description: str | None = "Rule description",
    title: str = "Test Rule",
) -> DetectionRule:
    return DetectionRule(
        rule_id="test-id",
        title=title,
        description=description,
        technique_ids=technique_ids,
        source_file=Path("/fake/rule.yml"),
    )


def test_thresholds_constants_match_spec() -> None:
    assert SEMANTIC_THRESHOLD_DEFAULT == 0.65
    assert SEMANTIC_SEVERITY == "medium"


def test_rule_text_combines_title_and_description() -> None:
    rule = _make_rule(["T1059"], title="Title Here", description="Description here")
    assert _rule_text(rule) == "Title Here\nDescription here"


def test_rule_text_title_only_when_no_description() -> None:
    rule = _make_rule(["T1059"], description=None)
    assert _rule_text(rule) == "Test Rule"


def test_rule_text_returns_none_when_empty() -> None:
    rule = DetectionRule(title="", source_file=Path("/r"))
    assert _rule_text(rule) is None


def test_technique_text_combines_name_and_description() -> None:
    tech = _make_technique(description="Tech description")
    assert _technique_text(tech) == "Tech Name\nTech description"


def test_aligned_pair_yields_no_finding() -> None:
    """High cosine similarity (vector A vs vector A) → no finding."""
    rule = _make_rule(["T1059"])
    index = _make_index(_make_technique("T1059"))
    rule_vec = [1.0, 0.0, 0.0]
    tech_vecs = {"T1059": [1.0, 0.0, 0.0]}  # identical → sim 1.0
    findings = score_rule_semantic(rule, index, rule_vec, tech_vecs)
    assert findings == []


def test_misaligned_pair_yields_low_alignment_finding() -> None:
    """Orthogonal vectors → sim 0 → below 0.65 threshold → one finding."""
    rule = _make_rule(["T1059"])
    index = _make_index(_make_technique("T1059"))
    rule_vec = [1.0, 0.0]
    tech_vecs = {"T1059": [0.0, 1.0]}  # orthogonal → sim 0.0
    findings = score_rule_semantic(rule, index, rule_vec, tech_vecs)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "low_alignment"
    assert f.severity == "medium"
    assert f.technique_id == "T1059"
    assert f.similarity_score == 0.0
    assert f.days_stale == 0


def test_threshold_boundary_exact_match_is_not_flagged() -> None:
    """sim == threshold → no finding (we flag strictly below)."""
    rule = _make_rule(["T1059"])
    index = _make_index(_make_technique("T1059"))
    # Cosine of these vectors is exactly 0.65 (constructed so cos(θ) = 0.65).
    rule_vec = [1.0, 0.0]
    tech_vecs = {"T1059": [0.65, 0.7599342076785331]}  # cos == 0.65
    findings = score_rule_semantic(
        rule, index, rule_vec, tech_vecs, threshold=0.65
    )
    assert findings == []


def test_threshold_boundary_just_below_is_flagged() -> None:
    rule = _make_rule(["T1059"])
    index = _make_index(_make_technique("T1059"))
    rule_vec = [1.0, 0.0]
    # cos == 0.64 (just below the default 0.65)
    tech_vecs = {"T1059": [0.64, 0.7683749084618852]}
    findings = score_rule_semantic(
        rule, index, rule_vec, tech_vecs, threshold=0.65
    )
    assert len(findings) == 1
    assert findings[0].similarity_score == 0.64


def test_rule_without_embedding_returns_empty() -> None:
    rule = _make_rule(["T1059"])
    index = _make_index(_make_technique("T1059"))
    findings = score_rule_semantic(rule, index, None, {"T1059": [1.0, 0.0]})
    assert findings == []


def test_technique_without_embedding_is_skipped() -> None:
    """If a technique has no embedding (no description), skip silently."""
    rule = _make_rule(["T1059", "T1003"])
    index = _make_index(_make_technique("T1059"), _make_technique("T1003"))
    rule_vec = [1.0, 0.0]
    # Only T1059 has an embedding; T1003 is missing.
    tech_vecs = {"T1059": [0.0, 1.0]}  # T1059 misaligned
    findings = score_rule_semantic(rule, index, rule_vec, tech_vecs)
    # Exactly one finding: T1059's misalignment. T1003 silently skipped.
    assert len(findings) == 1
    assert findings[0].technique_id == "T1059"


def test_unknown_technique_is_skipped() -> None:
    """The timestamp scorer emits 'unknown_technique'; semantic scorer skips it."""
    rule = _make_rule(["T9999"])  # not in index
    index = _make_index(_make_technique("T1059"))
    findings = score_rule_semantic(rule, index, [1.0, 0.0], {"T1059": [0.0, 1.0]})
    assert findings == []


def test_multiple_techniques_can_produce_multiple_findings() -> None:
    rule = _make_rule(["T1059", "T1003"])
    index = _make_index(_make_technique("T1059"), _make_technique("T1003"))
    rule_vec = [1.0, 0.0]
    tech_vecs = {"T1059": [0.0, 1.0], "T1003": [-1.0, 0.0]}  # both misaligned
    findings = score_rule_semantic(rule, index, rule_vec, tech_vecs)
    assert len(findings) == 2
    assert {f.technique_id for f in findings} == {"T1059", "T1003"}
