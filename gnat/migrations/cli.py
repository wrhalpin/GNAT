"""
gnat.migrations.cli
====================

CLI commands for database migrations (``gnat db`` subcommand group).

Available commands::

    gnat db upgrade [revision]     — apply migrations (default: head)
    gnat db downgrade [revision]   — roll back migrations (default: -1)
    gnat db revision -m "message"  — create a new migration file
    gnat db current                — show current revision
    gnat db history                — show revision history
    gnat db check                  — verify DB matches current models

Usage via CLI::

    gnat db upgrade head
    gnat db downgrade -1
    gnat db revision --autogenerate -m "add analyst_id column"

Usage from Python::

    from gnat.migrations.cli import run_db_command
    run_db_command(["upgrade", "head"])
"""

from __future__ import annotations

import os
import sys
import logging
from typing import Sequence

logger = logging.getLogger(__name__)

# Default alembic.ini path — resolved relative to the package root
_DEFAULT_ALEMBIC_INI = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "alembic.ini",
)


def run_db_command(args: Sequence[str], alembic_ini: str | None = None) -> int:
    """
    Run an Alembic CLI command programmatically.

    Parameters
    ----------
    args : sequence of str
        Alembic subcommand + arguments, e.g. ``["upgrade", "head"]``.
    alembic_ini : str, optional
        Path to ``alembic.ini``.  Defaults to the repo root ``alembic.ini``.

    Returns
    -------
    int
        Exit code (0 = success).
    """
    try:
        from alembic.config import Config
        from alembic import command as alembic_cmd
    except ImportError as exc:
        logger.error("Alembic is required: pip install 'gnat[migrations]'")
        raise ImportError("alembic not installed") from exc

    ini_path = alembic_ini or os.environ.get("ALEMBIC_INI") or _DEFAULT_ALEMBIC_INI

    if not os.path.isfile(ini_path):
        # Fallback: look for alembic.ini in CWD
        cwd_ini = os.path.join(os.getcwd(), "alembic.ini")
        if os.path.isfile(cwd_ini):
            ini_path = cwd_ini
        else:
            raise FileNotFoundError(
                f"alembic.ini not found at {ini_path!r}. "
                "Run from the GNAT repository root or set ALEMBIC_INI."
            )

    alembic_cfg = Config(ini_path)

    cmd = args[0] if args else "current"
    rest = list(args[1:]) if len(args) > 1 else []

    dispatch: dict = {
        "upgrade":    lambda: alembic_cmd.upgrade(alembic_cfg, rest[0] if rest else "head"),
        "downgrade":  lambda: alembic_cmd.downgrade(alembic_cfg, rest[0] if rest else "-1"),
        "current":    lambda: alembic_cmd.current(alembic_cfg),
        "history":    lambda: alembic_cmd.history(alembic_cfg),
        "check":      lambda: alembic_cmd.check(alembic_cfg),
        "revision":   lambda: _run_revision(alembic_cfg, rest),
        "stamp":      lambda: alembic_cmd.stamp(alembic_cfg, rest[0] if rest else "head"),
    }

    handler = dispatch.get(cmd)
    if handler is None:
        raise ValueError(f"Unknown db command: {cmd!r}. Valid: {list(dispatch)}")

    try:
        handler()
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        logger.error("Migration command failed: %s", exc)
        raise


def _run_revision(cfg, rest: list[str]) -> None:
    from alembic import command as alembic_cmd
    autogenerate = "--autogenerate" in rest or "-a" in rest
    message = None
    for i, arg in enumerate(rest):
        if arg in ("-m", "--message") and i + 1 < len(rest):
            message = rest[i + 1]
    alembic_cmd.revision(cfg, message=message, autogenerate=autogenerate)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``gnat db`` CLI subcommand."""
    args = argv if argv is not None else sys.argv[1:]
    try:
        code = run_db_command(args)
        sys.exit(code)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
