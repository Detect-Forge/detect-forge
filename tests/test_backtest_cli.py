from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from pytest_mock import MockerFixture

from detect_forge.cli import main


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    return d


def _fake_report(*, priority_silent: int = 0, rules_silent_on_all: int = 0):
    from detect_forge.backtest.models import BacktestReport, BacktestSummary
    now = datetime.now(UTC)
    s = BacktestSummary(
        rules_parsed=0, rules_fires=0, rules_partial=0,
        rules_silent_on_all=rules_silent_on_all,
        rules_untested=0, rules_unsupported=0,
        techniques_in_scope=0, techniques_verified=0,
        techniques_silent=0, techniques_untested=0,
        priority_total=0, priority_verified=0,
        priority_silent=priority_silent, priority_untested=0,
        datasets_consulted=0, mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=now, generated_at=now,
    )
    return BacktestReport(summary=s)


def test_cli_exits_zero_when_neither_gate_fires(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.backtest.scan_backtest", return_value=_fake_report())
    runner = CliRunner()
    result = runner.invoke(main, ["backtest", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr


def test_cli_exits_two_on_priority_silence(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.backtest.scan_backtest",
        return_value=_fake_report(priority_silent=3),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["backtest", str(empty_rule_dir)])
    assert result.exit_code == 2, result.stderr
    assert "3" in result.stderr


def test_cli_exits_two_on_broken_rules(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.backtest.scan_backtest",
        return_value=_fake_report(rules_silent_on_all=2),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["backtest", str(empty_rule_dir)])
    assert result.exit_code == 2, result.stderr
    assert "2" in result.stderr


def test_cli_no_gate_suppresses_both(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.backtest.scan_backtest",
        return_value=_fake_report(priority_silent=5, rules_silent_on_all=2),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["backtest", str(empty_rule_dir), "--no-gate"])
    assert result.exit_code == 0, result.stderr


def test_cli_writes_output_file(
    empty_rule_dir: Path, mocker: MockerFixture, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.backtest.scan_backtest", return_value=_fake_report())
    out_file = tmp_path / "bt.json"
    runner = CliRunner()
    result = runner.invoke(
        main, ["backtest", str(empty_rule_dir), "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    assert "summary" in out_file.read_text()


def test_cli_passes_platform_flag(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    scan_mock = mocker.patch(
        "detect_forge.backtest.scan_backtest", return_value=_fake_report(),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["backtest", str(empty_rule_dir), "--platform", "windows"],
    )
    assert result.exit_code == 0
    assert scan_mock.call_args.kwargs["platform"] == "windows"


def test_cli_passes_techniques_filter(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    scan_mock = mocker.patch(
        "detect_forge.backtest.scan_backtest", return_value=_fake_report(),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["backtest", str(empty_rule_dir), "--techniques", "T1059.001,T1078"],
    )
    assert result.exit_code == 0
    assert scan_mock.call_args.kwargs["technique_filter"] == {"T1059.001", "T1078"}


def test_cli_config_file_disables_priority_gate(
    empty_rule_dir: Path, mocker: MockerFixture, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    cfg = tmp_path / ".detect-forge.toml"
    cfg.write_text("[backtest]\ngate_on_priority_silence = false\n")
    monkeypatch.chdir(tmp_path)
    mocker.patch(
        "detect_forge.backtest.scan_backtest",
        return_value=_fake_report(priority_silent=3),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["backtest", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
