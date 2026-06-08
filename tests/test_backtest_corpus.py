from __future__ import annotations

import json
import shutil
from pathlib import Path

import requests_mock as rm_lib

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "backtest"


def _load_synthetic_zip_bytes() -> bytes:
    return (FIXTURE_DIR / "synthetic_dataset.zip").read_bytes()


def test_corpus_loads_builtin_index() -> None:
    from detect_forge.backtest.corpus import load_builtin_index

    idx = load_builtin_index()
    assert "datasets" in idx
    assert isinstance(idx["datasets"], dict)


def test_corpus_datasets_for_returns_empty_for_unknown_technique(
    tmp_path: Path,
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
    )
    assert corpus.datasets_for("T9999") == []


def test_corpus_platform_filter(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        platform_filter={"linux"},
    )
    # T1059.001 is windows-only; filtered out.
    assert corpus.datasets_for("T1059.001") == []


def test_corpus_technique_filter(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        technique_filter={"T1078"},
    )
    # Even though T1059.001 has datasets, the filter excludes it.
    assert corpus.datasets_for("T1059.001") == []


def test_corpus_fetches_and_caches(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    datasets = corpus.datasets_for("T1059.001")
    assert len(datasets) == 1
    assert datasets[0].dataset_id == "synthetic_ps"
    assert len(datasets[0].events) == 3
    # File now in cache.
    cached = tmp_path / "security-datasets" / "datasets" / "T1059.001" / "synthetic_ps.json"
    assert cached.is_file()


def test_corpus_uses_cache_on_second_call(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    fetch_count_before = requests_mock.call_count

    corpus2 = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus2.datasets_for("T1059.001")
    # Second call should not fetch (cache hit).
    assert requests_mock.call_count == fetch_count_before


def test_corpus_no_cache_refetches(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    fetch_count_before = requests_mock.call_count

    corpus_nc = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx, no_cache=True)
    corpus_nc.datasets_for("T1059.001")
    assert requests_mock.call_count == fetch_count_before + 1


def test_corpus_source_override_skips_fetch(tmp_path: Path) -> None:
    """When source_override is set, datasets are loaded from the local path."""
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    # Lay down a fake local checkout layout.
    src = tmp_path / "checkout"
    (src / "datasets" / "atomic" / "windows" / "execution" / "host").mkdir(parents=True)
    shutil.copy(
        FIXTURE_DIR / "synthetic_dataset.zip",
        src / "datasets" / "atomic" / "windows" / "execution" / "host" / "synthetic_ps.zip",
    )
    (src / "index.json").write_text(json.dumps(fixture_idx))

    corpus = MordorCorpus(cache_dir=tmp_path, source_override=src)
    datasets = corpus.datasets_for("T1059.001")
    assert len(datasets) == 1


def test_corpus_datasets_consulted_count(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    assert corpus.datasets_consulted() == 1


def test_corpus_returns_empty_for_filtered_technique(tmp_path: Path) -> None:
    """technique_filter narrows the universe before fetch."""
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        technique_filter={"T9999"},
    )
    assert corpus.datasets_for("T1059.001") == []
    assert corpus.datasets_consulted() == 0
