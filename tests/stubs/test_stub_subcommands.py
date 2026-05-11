from __future__ import annotations

from click.testing import CliRunner

from detect_forge.cli import main
from detect_forge.exit_codes import RESERVED


def _invoke(args: list[str]) -> tuple[int, str, str]:
    runner = CliRunner()
    result = runner.invoke(main, args)
    return result.exit_code, result.stdout, result.stderr


def test_backtest_stub_message_and_exit() -> None:
    code, stdout, stderr = _invoke(["backtest"])
    assert code == RESERVED
    assert "'backtest' is not yet implemented" in stderr
    assert "Jun 28, 2026" in stderr
    assert "github.com/Detect-Forge/detect-forge" in stderr
    assert stdout == ""


def test_coverage_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["coverage"])
    assert code == RESERVED
    assert "'coverage' is not yet implemented" in stderr
    assert "Q3 2026" in stderr


def test_cti_group_help_shows_ingest() -> None:
    code, stdout, _stderr = _invoke(["cti", "--help"])
    assert code == 0
    assert "ingest" in stdout


def test_cti_ingest_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["cti", "ingest", "/tmp/anything.pdf"])
    assert code == RESERVED
    assert "'cti ingest' is not yet implemented" in stderr
    assert "Q3" in stderr  # matches "Q3" or "Q3-Q4 2026"


def test_audit_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["audit"])
    assert code == RESERVED
    assert "Reserved" in stderr
    assert "runs every check" in stderr


def test_main_help_lists_all_subcommands() -> None:
    code, stdout, _stderr = _invoke(["--help"])
    assert code == 0
    for cmd in ("stale", "backtest", "coverage", "cti", "audit"):
        assert cmd in stdout
