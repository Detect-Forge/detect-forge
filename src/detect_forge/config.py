"""Config file loading for ``.detect-forge.toml``.

Walks upward from the working directory until it finds a ``.detect-forge.toml``
or hits a git-repo boundary (``.git`` marker), then loads the ``[stale]``
section into a pydantic ``StaleConfig`` model.

Per-subcommand config sections (``[backtest]``, ``[coverage]``, etc.) will be
added in this module as those subcommands ship.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

CONFIG_FILENAME = ".detect-forge.toml"


class StaleConfig(BaseModel):
    """Settings for the ``stale`` subcommand sourced from ``[stale]`` in the config file."""

    semantic_threshold: float = Field(default=0.65)
    llm_model: str = Field(default="gpt-4o-mini")
    max_proposals: int = Field(default=5, ge=0)

    @field_validator("semantic_threshold")
    @classmethod
    def _threshold_in_range(cls, v: float) -> float:
        if not -1.0 <= v <= 1.0:
            raise ValueError(
                f"semantic_threshold must be in [-1, 1] (cosine range); got {v}"
            )
        return v


def find_config_file(start: Path | None = None) -> Path | None:
    """Walk upward from ``start`` (default: CWD) until a ``.detect-forge.toml``
    is found, or a ``.git`` directory boundary is reached, or the filesystem root.

    Returns the discovered file path, or None if no file is found before the
    walk halts.
    """
    current = (start if start is not None else Path.cwd()).resolve()
    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        # Stop at git-root boundary so a parent-directory config doesn't
        # accidentally leak into an unrelated repo.
        if (current / ".git").exists():
            return None
        parent = current.parent
        if parent == current:
            return None  # reached filesystem root
        current = parent


def load_stale_config(path: Path) -> StaleConfig:
    """Parse a ``.detect-forge.toml`` file and return the validated StaleConfig.

    Missing ``[stale]`` section is fine — returns defaults. Invalid field
    values raise ``pydantic.ValidationError`` (subclass of ``ValueError``).
    """
    raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    stale_section = raw.get("stale", {})
    if not isinstance(stale_section, dict):
        stale_section = {}
    return StaleConfig(**stale_section)


def load_stale_config_or_defaults(start: Path | None = None) -> StaleConfig:
    """Discover a ``.detect-forge.toml`` upward from ``start`` and load it.

    If no config is found, returns a default ``StaleConfig``.
    """
    path = find_config_file(start)
    if path is None:
        return StaleConfig()
    return load_stale_config(path)
