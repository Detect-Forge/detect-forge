from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.config import (
    StaleConfig,
    find_config_file,
    load_stale_config,
    load_stale_config_or_defaults,
)


def test_stale_config_defaults() -> None:
    cfg = StaleConfig()
    assert cfg.semantic_threshold == 0.65
    assert cfg.llm_model == "gpt-4o-mini"
    assert cfg.max_proposals == 5


def test_stale_config_accepts_values() -> None:
    cfg = StaleConfig(semantic_threshold=0.50, llm_model="gpt-4o", max_proposals=10)
    assert cfg.semantic_threshold == 0.50
    assert cfg.llm_model == "gpt-4o"
    assert cfg.max_proposals == 10


def test_stale_config_rejects_negative_threshold() -> None:
    """Validation: cosine similarity is in [-1, 1]; reject out-of-range."""
    with pytest.raises(ValueError):
        StaleConfig(semantic_threshold=-2.0)


def test_stale_config_rejects_threshold_above_one() -> None:
    with pytest.raises(ValueError):
        StaleConfig(semantic_threshold=1.5)


def test_stale_config_rejects_negative_max_proposals() -> None:
    with pytest.raises(ValueError):
        StaleConfig(max_proposals=-1)


def test_find_config_file_returns_none_when_absent(tmp_path: Path) -> None:
    """No .detect-forge.toml anywhere upward → None."""
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert find_config_file(nested) is None


def test_find_config_file_finds_in_starting_dir(tmp_path: Path) -> None:
    cfg = tmp_path / ".detect-forge.toml"
    cfg.write_text("[stale]\nsemantic_threshold = 0.5\n")
    found = find_config_file(tmp_path)
    assert found == cfg


def test_find_config_file_walks_upward(tmp_path: Path) -> None:
    """Discover walks parents until first .detect-forge.toml is found."""
    cfg = tmp_path / ".detect-forge.toml"
    cfg.write_text("[stale]\n")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    found = find_config_file(deep)
    assert found == cfg


def test_find_config_file_stops_at_git_root(tmp_path: Path) -> None:
    """Walk halts at a `.git` directory even if a config exists above it."""
    # Above .git: a config the discoverer must NOT find.
    above = tmp_path
    above_cfg = above / ".detect-forge.toml"
    above_cfg.write_text("[stale]\n")
    # The git root.
    repo = above / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    deep = repo / "src" / "deep"
    deep.mkdir(parents=True)
    found = find_config_file(deep)
    # Walk halts at repo (.git marker); cfg above is invisible.
    assert found is None


def test_load_stale_config_from_minimal_file() -> None:
    p = Path(__file__).parent / "fixtures" / "config" / "minimal.toml"
    cfg = load_stale_config(p)
    assert cfg.semantic_threshold == 0.65  # absent → default
    assert cfg.llm_model == "gpt-4o-mini"
    assert cfg.max_proposals == 5


def test_load_stale_config_from_full_file() -> None:
    p = Path(__file__).parent / "fixtures" / "config" / "full.toml"
    cfg = load_stale_config(p)
    assert cfg.semantic_threshold == 0.50
    assert cfg.llm_model == "gpt-4o"
    assert cfg.max_proposals == 10


def test_load_stale_config_invalid_threshold_raises() -> None:
    p = Path(__file__).parent / "fixtures" / "config" / "invalid_threshold.toml"
    with pytest.raises(ValueError):
        load_stale_config(p)


def test_load_stale_config_missing_stale_section() -> None:
    """A .detect-forge.toml without [stale] uses defaults."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write("[some_other_section]\nfoo = 1\n")
        path = Path(f.name)
    try:
        cfg = load_stale_config(path)
        assert cfg.semantic_threshold == 0.65
        assert cfg.llm_model == "gpt-4o-mini"
        assert cfg.max_proposals == 5
    finally:
        path.unlink()


def test_load_or_defaults_uses_defaults_when_no_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """No .detect-forge.toml upward → returns default StaleConfig."""
    nested = tmp_path / "x"
    nested.mkdir()
    monkeypatch.chdir(nested)
    cfg = load_stale_config_or_defaults()
    assert cfg.semantic_threshold == 0.65


def test_load_or_defaults_reads_discovered_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    cfg_file = tmp_path / ".detect-forge.toml"
    cfg_file.write_text("[stale]\nsemantic_threshold = 0.42\n")
    nested = tmp_path / "x" / "y"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    cfg = load_stale_config_or_defaults()
    assert cfg.semantic_threshold == 0.42
