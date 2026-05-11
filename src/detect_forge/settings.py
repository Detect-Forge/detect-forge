from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache import default_cache_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DETECT_FORGE_", env_file=".env", extra="ignore")

    cache_dir: Path = Field(default_factory=default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False
    semantic_threshold: float | None = None
