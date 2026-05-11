from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    """Return the default cache directory honoring XDG_CACHE_HOME.

    Falls back to ``~/.cache/detect-forge`` when ``XDG_CACHE_HOME`` is unset
    or empty.
    """
    xdg = os.environ.get("XDG_CACHE_HOME") or ""
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "detect-forge"


DEFAULT_TTL_HOURS = 24


def cache_path(domain: str, cache_dir: Path | None = None) -> Path:
    """Return the filesystem path for a given ATT&CK domain's cached STIX bundle.

    Ensures the cache directory exists.
    """
    resolved = cache_dir if cache_dir is not None else default_cache_dir()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved / f"{domain}.json"


def is_cache_valid(path: Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> bool:
    """Return True iff the file exists and is younger than ttl_hours.

    `ttl_hours=0` always returns False (cache bypass).
    """
    if ttl_hours <= 0 or not path.exists():
        return False
    age = datetime.now(UTC) - datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    return age < timedelta(hours=ttl_hours)


def read_cache(path: Path) -> dict[str, Any]:
    """Read and parse a cached JSON file."""
    return dict(json.loads(path.read_text(encoding="utf-8")))


def write_cache(path: Path, data: dict[str, Any]) -> None:
    """Write a dict to disk as JSON atomically (write tmp + rename).

    `Path.replace` is atomic on POSIX when tmp and path are on the same filesystem.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)
