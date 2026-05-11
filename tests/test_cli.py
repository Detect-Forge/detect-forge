from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from pytest_mock import MockerFixture

from detect_forge import __version__
from detect_forge.cli import main
from detect_forge.exit_codes import GATED
from detect_forge.stale.models import (
    AttackIndex,
    ReportSummary,
    RuleScore,
    StalenessReport,
)

_EMPTY_INDEX = AttackIndex(fetched_at=datetime(2026, 1, 1, tzinfo=UTC))


def _empty_report() -> StalenessReport:
    summary = ReportSummary(
        total_rules=0,
        rules_with_findings=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        no_attack_tags=0,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return StalenessReport(summary=summary, scores=[])


_EMPTY_REPORT = _empty_report()


def test_main_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Detection engineering toolkit" in result.output


def test_main_version_prints_package_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.fixture
def patched_pipeline(mocker: MockerFixture) -> dict[str, MagicMock]:
    """Replace scan's lazy-imported functions with mocks returning empty data."""
    return {
        "build_index": mocker.patch(
            "detect_forge.stale.attack_client.build_index", return_value=_EMPTY_INDEX
        ),
        "parse_rule_dir": mocker.patch(
            "detect_forge.stale.rule_parser.parse_rule_dir", return_value=[]
        ),
        "score_rules": mocker.patch(
            "detect_forge.stale.scorer.score_rules", return_value=_EMPTY_REPORT
        ),
    }


def test_scan_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["stale", "--help"])
    assert result.exit_code == 0
    assert "RULE_DIR" in result.output
    assert "--min-severity" in result.output
    assert "--no-cache" in result.output


def test_scan_happy_path_terminal(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
    assert "detect-forge" in result.stdout.lower()
    patched_pipeline["build_index"].assert_called_once()
    patched_pipeline["parse_rule_dir"].assert_called_once()
    patched_pipeline["score_rules"].assert_called_once()


def test_scan_json_output_to_stdout(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scores"] == []
    assert payload["summary"]["total_rules"] == 0


def test_scan_no_cache_sets_ttl_zero(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir), "--no-cache"])
    assert result.exit_code == 0
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["ttl_hours"] == 0
    assert kwargs["cache_dir"] == Path.home() / ".cache" / "detect-forge"


def test_scan_honors_settings_no_cache(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DETECT_FORGE_NO_CACHE=true must force ttl=0 even without the --no-cache flag."""
    monkeypatch.setenv("DETECT_FORGE_NO_CACHE", "true")
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["ttl_hours"] == 0


def test_scan_domain_option_flows_through(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["stale", str(empty_rule_dir), "--domain", "ics-attack"]
    )
    assert result.exit_code == 0
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["domain"] == "ics-attack"


def test_scan_writes_file_when_output_given(
    tmp_path: Path, empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["stale", str(empty_rule_dir), "--format", "json", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["scores"] == []
    assert result.stdout == ""


def test_scan_exits_2_when_critical_finding(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    critical_score = RuleScore(
        rule_id="r1",
        title="t1",
        source_file=Path("/fake/r1.yml"),
        status="stable",
        findings=[],
        worst_severity="critical",
        worst_days_stale=400,
        has_attack_tags=True,
    )
    summary = ReportSummary(
        total_rules=1,
        rules_with_findings=1,
        critical=1,
        high=0,
        medium=0,
        low=0,
        no_attack_tags=0,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    critical_report = StalenessReport(summary=summary, scores=[critical_score])

    mocker.patch(
        "detect_forge.stale.attack_client.build_index", return_value=_EMPTY_INDEX
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    mocker.patch("detect_forge.stale.scorer.score_rules", return_value=critical_report)

    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir)])
    assert result.exit_code == GATED


def test_scan_rejects_nonexistent_rule_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(tmp_path / "does-not-exist")])
    assert result.exit_code != 0


def test_stale_accepts_semantic_threshold_flag(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The --semantic-threshold flag must be accepted and pass through to scan()."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    runner = CliRunner()
    result = runner.invoke(
        main, ["stale", str(empty_rule_dir), "--semantic-threshold", "0.50"]
    )
    assert result.exit_code == 0, result.stderr
    # Verify the value flowed through to the underlying score_rules call.
    kwargs = patched_pipeline["score_rules"].call_args.kwargs
    assert kwargs.get("semantic_threshold") == 0.50


def test_stale_default_semantic_threshold_is_065(
    empty_rule_dir: Path,
    patched_pipeline: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["stale", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
    kwargs = patched_pipeline["score_rules"].call_args.kwargs
    assert kwargs.get("semantic_threshold") == 0.65
