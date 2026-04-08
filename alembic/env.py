"""
Alembic migration environment for GNAT.

Imports all SQLAlchemy ``_Base`` registries so that ``alembic revision
--autogenerate`` picks up all table definitions automatically.

Database URL resolution order
------------------------------
1. ``GNAT_DB_URL`` environment variable
2. ``GNAT_CONFIG`` → read ``[database] url`` from the INI config
3. ``alembic.ini`` ``sqlalchemy.url`` key

Usage
-----
::

    # Apply all pending migrations
    alembic upgrade head

    # Roll back one migration
    alembic downgrade -1

    # Auto-generate a new migration from model changes
    alembic revision --autogenerate -m "add lineage events"

    # Show current revision
    alembic current
"""

from __future__ import annotations

import os
import logging
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Logging — configured by alembic.ini
# ---------------------------------------------------------------------------

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import all SQLAlchemy bases so Alembic sees all table metadata
# ---------------------------------------------------------------------------

# Guard: only import if SQLAlchemy is installed
try:
    from gnat.migrations import get_combined_metadata
    target_metadata = get_combined_metadata()
except ImportError:
    logger.warning("gnat.migrations unavailable — running offline migration mode.")
    target_metadata = None


# ---------------------------------------------------------------------------
# Database URL resolution
# ---------------------------------------------------------------------------

def _resolve_db_url() -> str:
    """Return the database URL from env var, GNAT config, or alembic.ini."""
    # 1. Explicit env var
    env_url = os.environ.get("GNAT_DB_URL")
    if env_url:
        return env_url

    # 2. GNAT config file
    config_path = os.environ.get("GNAT_CONFIG")
    if config_path and os.path.isfile(config_path):
        try:
            import configparser
            cfg = configparser.ConfigParser()
            cfg.read(config_path)
            if cfg.has_option("database", "url"):
                return cfg.get("database", "url")
        except Exception as exc:
            logger.warning("Could not read GNAT_CONFIG for DB URL: %s", exc)

    # 3. Fall through to alembic.ini sqlalchemy.url
    return config.get_main_option("sqlalchemy.url", "sqlite:///gnat.db")


# ---------------------------------------------------------------------------
# Offline migrations (generate SQL without connecting)
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    url = _resolve_db_url()
    context.configure(
        url               = url,
        target_metadata   = target_metadata,
        literal_binds     = True,
        dialect_opts      = {"paramstyle": "named"},
        compare_type      = True,
        include_schemas   = False,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (run against live DB)
# ---------------------------------------------------------------------------

def run_migrations_online() -> None:
    url = _resolve_db_url()
    # Override alembic.ini URL with resolved value
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix     = "sqlalchemy.",
        poolclass  = pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection      = connection,
            target_metadata = target_metadata,
            compare_type    = True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
