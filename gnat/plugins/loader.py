"""
gnat.plugins.loader
====================

Convenience functions for loading all configured plugins at startup.

Usage::

    from gnat.plugins.loader import load_plugins

    # Auto-discover and load all plugins
    load_plugins()

    # Or with explicit config
    load_plugins(
        entry_points=True,
        directories=["./custom_plugins"],
    )
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def load_plugins(
    entry_points: bool = True,
    directories:  list[str] | None = None,
    config:       Any | None = None,
) -> int:
    """
    Discover and load all GNAT plugins.

    Parameters
    ----------
    entry_points : bool
        Load plugins from setuptools ``gnat.plugins`` entry points (default True).
    directories : list of str, optional
        Additional directories to scan for ``*.py`` plugin files.
    config : ConfigParser, optional
        GNAT INI config.  If provided, reads ``[plugins]`` section for:
        - ``enabled = true/false``
        - ``directories = /path/one,/path/two``

    Returns
    -------
    int
        Total number of plugins successfully loaded.
    """
    from gnat.plugins.registry import PluginRegistry
    registry = PluginRegistry.instance()

    # Read config overrides
    dirs: list[str] = list(directories or [])
    _ep = entry_points

    if config is not None:
        try:
            if config.has_section("plugins"):
                if config.has_option("plugins", "enabled"):
                    if not config.getboolean("plugins", "enabled"):
                        logger.info("PluginRegistry: plugins disabled via config.")
                        return 0
                if config.has_option("plugins", "directories"):
                    raw = config.get("plugins", "directories")
                    dirs.extend(p.strip() for p in raw.split(",") if p.strip())
        except Exception as exc:
            logger.warning("load_plugins: error reading [plugins] config: %s", exc)

    # Also check env var for extra directories
    env_dirs = os.environ.get("GNAT_PLUGIN_DIRS", "")
    if env_dirs:
        dirs.extend(p.strip() for p in env_dirs.split(":") if p.strip())

    total = 0

    if _ep:
        total += registry.load_entry_points()

    for d in dirs:
        total += registry.load_directory(d)

    if total:
        logger.info("load_plugins: loaded %d plugin(s) total.", total)

    return total
