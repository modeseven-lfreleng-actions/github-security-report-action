# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Command-line entry point.

The full CLI is assembled in later commits; this provides the Typer app and
the entry point referenced by ``[project.scripts]`` so the package is
installable and ``--version`` works from the outset.
"""

from __future__ import annotations

import typer

from github_security_report import __version__

app = typer.Typer(
    name="github-security-report",
    help="Security and quality reporting across GitHub organisations.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"github-security-report {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Security and quality reporting across GitHub organisations."""


if __name__ == "__main__":  # pragma: no cover
    app()
