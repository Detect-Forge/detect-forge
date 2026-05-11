from __future__ import annotations

from pathlib import Path

from detect_forge.stale.rule_parser import parse_rule_dir, parse_rule_file

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma"
ELASTIC_FIXTURES = Path(__file__).parent / "fixtures" / "elastic"


def test_dispatch_yml_goes_to_sigma() -> None:
    rule = parse_rule_file(SIGMA_FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    # Sigma parser populates raw_tags; Elastic parser leaves it empty.
    assert rule.raw_tags != []


def test_dispatch_toml_goes_to_elastic() -> None:
    rule = parse_rule_file(ELASTIC_FIXTURES / "minimal_eql.toml")
    assert rule is not None
    # Elastic parser leaves raw_tags empty; Sigma parser would populate it.
    assert rule.raw_tags == []
    assert rule.technique_ids == ["T1059"]


def test_dispatch_unknown_extension_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "rule.json"
    p.write_text("{}")
    assert parse_rule_file(p) is None


def test_dispatch_yaml_extension_also_goes_to_sigma(tmp_path: Path) -> None:
    """Sigma rules ending in .yaml should also be picked up."""
    p = tmp_path / "rule.yaml"
    p.write_text(
        "title: Test Rule\n"
        "id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
        "tags:\n"
        "  - attack.t1059\n"
    )
    rule = parse_rule_file(p)
    assert rule is not None
    assert rule.title == "Test Rule"
    assert rule.technique_ids == ["T1059"]


def test_parse_rule_dir_mixed_format_directory(tmp_path: Path) -> None:
    """A directory containing both Sigma .yml and Elastic .toml files yields
    rules from both parsers in a single result list."""
    sigma_path = tmp_path / "sigma_rule.yml"
    sigma_path.write_text(
        "title: Mixed Sigma\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "tags:\n"
        "  - attack.t1059\n"
    )
    elastic_path = tmp_path / "elastic_rule.toml"
    elastic_path.write_text(
        '[metadata]\n'
        'creation_date = "2024/01/01"\n'
        '[rule]\n'
        'name = "Mixed Elastic"\n'
        'rule_id = "22222222-2222-2222-2222-222222222222"\n'
        '[[rule.threat]]\n'
        '[[rule.threat.technique]]\n'
        'id = "T1003"\n'
    )

    rules = parse_rule_dir(tmp_path)
    titles = {r.title for r in rules}
    assert titles == {"Mixed Sigma", "Mixed Elastic"}


def test_parse_rule_dir_recurses_into_subdirectories(tmp_path: Path) -> None:
    sigma_dir = tmp_path / "Sigma"
    elastic_dir = tmp_path / "Elastic"
    sigma_dir.mkdir()
    elastic_dir.mkdir()
    (sigma_dir / "a.yml").write_text(
        "title: Sigma A\nid: 11111111-1111-1111-1111-111111111111\ntags: [attack.t1059]\n"
    )
    (elastic_dir / "b.toml").write_text(
        '[metadata]\n'
        '[rule]\n'
        'name = "Elastic B"\n'
        'rule_id = "22222222-2222-2222-2222-222222222222"\n'
        '[[rule.threat]]\n'
        '[[rule.threat.technique]]\n'
        'id = "T1003"\n'
    )
    rules = parse_rule_dir(tmp_path)
    titles = {r.title for r in rules}
    assert titles == {"Sigma A", "Elastic B"}


def test_parse_rule_dir_skips_unknown_extensions(tmp_path: Path) -> None:
    (tmp_path / "rule.yml").write_text(
        "title: Kept\nid: 33333333-3333-3333-3333-333333333333\ntags: [attack.t1059]\n"
    )
    (tmp_path / "rule.json").write_text("{}")
    (tmp_path / "README.md").write_text("# not a rule")
    rules = parse_rule_dir(tmp_path)
    assert {r.title for r in rules} == {"Kept"}


def test_parse_rule_dir_empty_dir(tmp_path: Path) -> None:
    assert parse_rule_dir(tmp_path) == []
