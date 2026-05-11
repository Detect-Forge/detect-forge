from __future__ import annotations

import click

from .console import err_console
from .exit_codes import RESERVED


def stub_command(name: str, message: str, *, help_text: str | None = None) -> click.Command:
    """Return a click command that prints `message` to stderr and exits RESERVED.

    Used by every subcommand that is registered for discoverability but has
    not yet been implemented.

    Args:
        name: The command name as it appears on the CLI.
        message: Multi-line stderr message printed before exit.
        help_text: Optional one-line summary shown in the parent group's
            `--help` listing. Defaults to the first line of ``message``.
    """
    summary = help_text if help_text is not None else message.split("\n", 1)[0]

    @click.command(name=name, help=summary)
    @click.argument("args", nargs=-1, type=click.UNPROCESSED)
    @click.pass_context
    def _stub(ctx: click.Context, args: tuple[str, ...]) -> None:
        _ = args  # accept and ignore any positional args so users hit the stub
        err_console.print(message)
        ctx.exit(RESERVED)

    return _stub
