from __future__ import annotations

import click

from .._stubs import stub_command

_MESSAGE = (
    "detect-forge: 'audit' is Reserved - runs every check once 2+ subcommands ship.\n"
    "Track at https://github.com/Detect-Forge/detect-forge/issues"
)

audit_cmd = stub_command(
    "audit",
    _MESSAGE,
    help_text="Reserved - runs every check once 2+ subcommands ship.",
)


def register(group: click.Group) -> None:
    group.add_command(audit_cmd)
