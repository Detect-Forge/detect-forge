from __future__ import annotations

from pathlib import Path

import pytest


def test_audit_config_defaults() -> None:
    """Default AuditConfig: all 3 subcommands enabled, strict-AND gate, no LLM."""
    from detect_forge.config import AuditConfig

    cfg = AuditConfig()
    assert cfg.gate_strategy == "all"
    assert cfg.subcommands == ["stale", "coverage", "backtest"]
    assert cfg.include_llm_proposals is False


def test_audit_config_rejects_invalid_gate_strategy() -> None:
    """gate_strategy is a Literal["all", "never"]."""
    from pydantic import ValidationError

    from detect_forge.config import AuditConfig

    with pytest.raises(ValidationError):
        AuditConfig(gate_strategy="any")  # type: ignore[arg-type]


def test_audit_config_rejects_unknown_subcommand_name() -> None:
    """Subcommands list must only contain known subcommand names."""
    from pydantic import ValidationError

    from detect_forge.config import AuditConfig

    with pytest.raises(ValidationError):
        AuditConfig(subcommands=["stale", "magic"])


def test_load_audit_config_or_defaults_when_no_file(tmp_path: Path) -> None:
    """No .detect-forge.toml in scope → returns defaults."""
    from detect_forge.config import AuditConfig, load_audit_config_or_defaults

    cfg = load_audit_config_or_defaults(start=tmp_path)
    assert cfg == AuditConfig()


def test_load_audit_config_reads_partial_section(tmp_path: Path) -> None:
    """[audit] with subset of keys: unspecified keys use defaults."""
    from detect_forge.config import load_audit_config_or_defaults

    cfg_file = tmp_path / ".detect-forge.toml"
    cfg_file.write_text(
        '[audit]\n'
        'gate_strategy = "never"\n'
        'include_llm_proposals = true\n',
        encoding="utf-8",
    )
    cfg = load_audit_config_or_defaults(start=tmp_path)
    assert cfg.gate_strategy == "never"
    assert cfg.include_llm_proposals is True
    assert cfg.subcommands == ["stale", "coverage", "backtest"]  # default
