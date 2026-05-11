from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'coverage' is not yet implemented.\n"
    "Ship target: Q3 2026.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

coverage_cmd = stub_command(
    "coverage",
    _MESSAGE,
    help_text="Coverage gap mapping (not yet implemented).",
)


def register(group: click.Group) -> None:
    group.add_command(coverage_cmd)
