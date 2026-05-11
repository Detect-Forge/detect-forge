from __future__ import annotations

import click

from .audit import cli as audit_cli
from .backtest import cli as backtest_cli
from .coverage import cli as coverage_cli
from .cti import cli as cti_cli
from .stale import cli as stale_cli


@click.group()
@click.version_option(package_name="detect-forge")
def main() -> None:
    """Detection engineering toolkit. One install, one config, one CI step."""


stale_cli.register(main)
backtest_cli.register(main)
coverage_cli.register(main)
cti_cli.register(main)
audit_cli.register(main)


if __name__ == "__main__":
    main()
