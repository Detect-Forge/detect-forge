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
