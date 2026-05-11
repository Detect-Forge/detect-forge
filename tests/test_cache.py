from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from detect_forge.cache import (
    cache_path,
    is_cache_valid,
    read_cache,
    write_cache,
)


def test_cache_path_uses_factory_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    path = cache_path("enterprise-attack")
    assert path == tmp_path / "detect-forge" / "enterprise-attack.json"


def test_cache_path_creates_directory_and_returns_filename(tmp_path: Path) -> None:
    nested = tmp_path / "subdir" / "deeper"
    p = cache_path("enterprise-attack", nested)
    assert nested.exists()
    assert p == nested / "enterprise-attack.json"


def test_is_cache_valid_false_when_missing(tmp_path: Path) -> None:
    assert is_cache_valid(tmp_path / "nope.json", ttl_hours=24) is False


def test_is_cache_valid_true_for_fresh_file(tmp_path: Path) -> None:
    p = tmp_path / "fresh.json"
    p.write_text("{}", encoding="utf-8")
    assert is_cache_valid(p, ttl_hours=24) is True


def test_is_cache_valid_false_when_ttl_zero(tmp_path: Path) -> None:
    p = tmp_path / "fresh.json"
    p.write_text("{}", encoding="utf-8")
    assert is_cache_valid(p, ttl_hours=0) is False


def test_is_cache_valid_false_when_file_older_than_ttl(tmp_path: Path) -> None:
    p = tmp_path / "old.json"
    p.write_text("{}", encoding="utf-8")
    two_hours_ago = time.time() - 2 * 3600
    os.utime(p, (two_hours_ago, two_hours_ago))
    assert is_cache_valid(p, ttl_hours=1) is False


def test_write_cache_and_read_cache_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    payload = {"hello": "world", "nested": {"n": 1}}
    write_cache(p, payload)
    assert p.exists()
    assert read_cache(p) == payload
    assert json.loads(p.read_text(encoding="utf-8")) == payload
