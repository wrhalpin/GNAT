"""
gnat.migrations
================

Helpers for Alembic database migrations.

:func:`get_combined_metadata` collects all SQLAlchemy ``MetaData`` objects
from GNAT's storage modules into a single combined :class:`sqlalchemy.MetaData`
so that Alembic's autogenerate can see every table in one pass.

Usage in ``alembic/env.py``::

    from gnat.migrations import get_combined_metadata
    target_metadata = get_combined_metadata()
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def get_combined_metadata():
    """
    Return a :class:`sqlalchemy.MetaData` that contains all GNAT tables.

    Imports each storage module's ``_Base`` and merges their metadata.
    Modules are imported lazily so that optional dependencies (SQLAlchemy)
    don't need to be present at package import time.
    """
    try:
        from sqlalchemy import MetaData
    except ImportError as exc:
        raise ImportError(
            "SQLAlchemy is required for migrations. "
            "Install it with: pip install 'gnat[persist]'"
        ) from exc

    combined = MetaData()
    _bases = _collect_bases()

    for base in _bases:
        try:
            for table in base.metadata.tables.values():
                table.tometadata(combined)
        except Exception as exc:
            logger.warning("Could not merge metadata from %r: %s", base, exc)

    return combined


def _collect_bases() -> list:
    """Collect all SQLAlchemy _Base objects from GNAT storage modules."""
    bases = []

    # Investigations
    try:
        from gnat.analysis.investigations import storage as inv_storage
        if hasattr(inv_storage, "_Base"):
            bases.append(inv_storage._Base)
    except Exception as exc:
        logger.debug("Could not import investigations storage: %s", exc)

    # Reports
    try:
        from gnat.reporting import storage as rep_storage
        if hasattr(rep_storage, "_Base"):
            bases.append(rep_storage._Base)
    except Exception as exc:
        logger.debug("Could not import reporting storage: %s", exc)

    # Context / workspace
    try:
        from gnat.context import store as ctx_store
        if hasattr(ctx_store, "_Base"):
            bases.append(ctx_store._Base)
    except Exception as exc:
        logger.debug("Could not import context store: %s", exc)

    # Lineage (added in Phase 3C — gracefully absent if not yet installed)
    try:
        from gnat.lineage import store as lin_store
        if hasattr(lin_store, "_Base"):
            bases.append(lin_store._Base)
    except Exception as exc:
        logger.debug("Could not import lineage store: %s", exc)

    return bases
