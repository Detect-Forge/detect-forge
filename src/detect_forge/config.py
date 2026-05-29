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
from typing import Any, Literal

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


class CoverageConfig(BaseModel):
    """Settings for the ``coverage`` subcommand sourced from ``[coverage]`` in the config file."""

    priority_list: str = ""
    """Path to a custom priority list JSON. Empty string means "use the built-in CTID default"."""
    gate_on_priority_gaps: bool = True
    """When True, exit code 2 fires if any priority-list technique has gap state."""


class BacktestConfig(BaseModel):
    """Settings for the ``backtest`` subcommand sourced from ``[backtest]`` in the config file."""

    gate_on_priority_silence: bool = True
    """When True, exit 2 if any priority-list technique has zero firing rules."""
    gate_on_broken_rules: bool = True
    """When True, exit 2 if any rule is silent on every tested dataset."""
    mordor_source: str = ""
    """Path to a local Security-Datasets checkout. Empty string means fetch on demand."""
    platform: Literal["windows", "linux", "macos", "all"] = "all"
    """Filter Mordor datasets by platform."""


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


def load_coverage_config(path: Path) -> CoverageConfig:
    """Parse a ``.detect-forge.toml`` file and return the validated CoverageConfig.

    Missing ``[coverage]`` section is fine — returns defaults. Invalid values
    raise ``pydantic.ValidationError`` (subclass of ``ValueError``).
    """
    raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    coverage_section = raw.get("coverage", {})
    if not isinstance(coverage_section, dict):
        coverage_section = {}
    return CoverageConfig(**coverage_section)


def load_coverage_config_or_defaults(start: Path | None = None) -> CoverageConfig:
    """Discover a ``.detect-forge.toml`` upward from ``start`` and load it.

    If no config is found, returns a default ``CoverageConfig``.
    """
    path = find_config_file(start)
    if path is None:
        return CoverageConfig()
    return load_coverage_config(path)


def load_backtest_config(path: Path) -> BacktestConfig:
    """Parse a ``.detect-forge.toml`` file and return the validated BacktestConfig.

    Missing ``[backtest]`` section is fine — returns defaults. Invalid values
    raise ``pydantic.ValidationError`` (subclass of ``ValueError``).
    """
    raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    backtest_section = raw.get("backtest", {})
    if not isinstance(backtest_section, dict):
        backtest_section = {}
    return BacktestConfig(**backtest_section)


def load_backtest_config_or_defaults(start: Path | None = None) -> BacktestConfig:
    """Discover a ``.detect-forge.toml`` upward from ``start`` and load the [backtest] section.

    Returns a default ``BacktestConfig`` when no file is found.
    """
    path = find_config_file(start)
    if path is None:
        return BacktestConfig()
    return load_backtest_config(path)
