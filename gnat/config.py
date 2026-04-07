# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.config
==============

INI-file based configuration management for GNAT.

Configuration files use standard INI format with one section per target::

    [DEFAULT]
    timeout = 30
    verify_ssl = true

    [threatq]
    host = https://threatq.example.com
    client_id = my-client-id
    client_secret = s3cr3t
    auth_type = oauth2

    [crowdstrike]
    host = https://api.crowdstrike.com
    client_id = my-cid
    client_secret = my-secret
    auth_type = oauth2

Default config file search order:
    1. Path passed explicitly to ``GNATConfig``
    2. ``GNAT_CONFIG`` environment variable
    3. ``~/.gnat/config.ini``
    4. ``./gnat.ini``
"""

import configparser
import os
from pathlib import Path
from typing import Optional

_DEFAULT_SEARCH_PATHS = [
    Path.home() / ".gnat" / "config.ini",
    Path("gnat.ini"),
]


class GNATConfig:
    """
    Loads and exposes per-target configuration from INI files.

    Parameters
    ----------
    config_path : str or Path, optional
        Explicit path to an INI configuration file.  If omitted the class
        searches the default locations listed in the module docstring.

    Raises
    ------
    FileNotFoundError
        If no configuration file can be located.

    Examples
    --------
    >>> cfg = GNATConfig()
    >>> threatq_cfg = cfg.get("threatq")
    >>> print(threatq_cfg["host"])
    """

    def __init__(self, config_path: Optional[str] = None):
        self._parser = configparser.ConfigParser()
        resolved = self._resolve_path(config_path)
        if resolved is None:
            raise FileNotFoundError(
                "No GNAT configuration file found. "
                "Create ~/.gnat/config.ini or pass config_path= explicitly."
            )
        self._path = resolved
        self._parser.read(resolved)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, target: str) -> dict:
        """
        Return all configuration keys for *target* as a plain dict.

        Falls back to ``[DEFAULT]`` values for missing keys.

        Parameters
        ----------
        target : str
            Section name matching the target system (e.g. ``"threatq"``).

        Returns
        -------
        dict
            Merged DEFAULT + target section key/value pairs.

        Raises
        ------
        KeyError
            If *target* section does not exist in the config file.
        """
        if not self._parser.has_section(target):
            raise KeyError(
                f"No [{target}] section found in {self._path}. Available sections: {self.sections}"
            )
        return dict(self._parser[target])

    @property
    def sections(self) -> list:
        """List of non-DEFAULT section names present in the config file."""
        return self._parser.sections()

    @property
    def config_path(self) -> Path:
        """Resolved path to the active configuration file."""
        return self._path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, explicit: Optional[str]) -> Optional[Path]:
        if explicit:
            p = Path(explicit)
            if p.exists():
                return p
            raise FileNotFoundError(f"Config file not found: {explicit}")

        env = os.environ.get("GNAT_CONFIG")
        if env:
            p = Path(env)
            if p.exists():
                return p

        for candidate in _DEFAULT_SEARCH_PATHS:
            if candidate.exists():
                return candidate

        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"GNATConfig(path={self._path!r}, sections={self.sections})"
