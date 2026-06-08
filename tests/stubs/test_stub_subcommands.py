from __future__ import annotations

from click.testing import CliRunner

from detect_forge.cli import main
from detect_forge.exit_codes import RESERVED


def _invoke(args: list[str]) -> tuple[int, str, str]:
    runner = CliRunner()
    result = runner.invoke(main, args)
    return result.exit_code, result.stdout, result.stderr


def test_cti_group_help_shows_ingest() -> None:
    code, stdout, _stderr = _invoke(["cti", "--help"])
    assert code == 0
    assert "ingest" in stdout


def test_cti_ingest_stub_message_and_exit() -> None:
    code, _stdout, stderr = _invoke(["cti", "ingest", "/tmp/anything.pdf"])
    assert code == RESERVED
    assert "'cti ingest' is not yet implemented" in stderr
    assert "Q3" in stderr  # matches "Q3" or "Q3-Q4 2026"


def test_main_help_lists_all_subcommands() -> None:
    code, stdout, _stderr = _invoke(["--help"])
    assert code == 0
    for cmd in ("stale", "backtest", "coverage", "cti", "audit"):
        assert cmd in stdout
