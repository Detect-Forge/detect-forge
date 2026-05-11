from __future__ import annotations

import click

from .stale import cli as stale_cli


@click.group()
@click.version_option(package_name="detect-forge")
def main() -> None:
    """Detection engineering toolkit. One install, one config, one CI step."""


stale_cli.register(main)


if __name__ == "__main__":
    main()
