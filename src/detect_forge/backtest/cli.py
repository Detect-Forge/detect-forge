from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'backtest' is not yet implemented.\n"
    "Ship target: Jun 28, 2026.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

backtest_cmd = stub_command(
    "backtest",
    _MESSAGE,
    help_text="Adversarial replay (not yet implemented).",
)


def register(group: click.Group) -> None:
    group.add_command(backtest_cmd)
