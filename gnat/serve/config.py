# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.config
=================
Configuration dataclass for the GNAT web dashboard.

Reads from the ``[webui]`` section of the GNAT INI file::

    [webui]
    enabled     = true
    bind        = 127.0.0.1
    port        = 8088
    api_key     = <32-char hex secret>
    reports_dir = /var/gnat/reports
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass


@dataclass
class WebUIConfig:
    """Runtime configuration for the GNAT web dashboard.

    Parameters
    ----------
    enabled : bool
        Whether the web UI is enabled.  Default ``True``.
    bind : str
        Host to bind to.  Default ``"127.0.0.1"`` (localhost only).
    port : int
        TCP port.  Default ``8088``.
    api_key : str
        ``X-Api-Key`` value required on every API request.
    reports_dir : str, optional
        Directory to scan for generated report files.
    """

    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 8088
    api_key: str = ""
    reports_dir: str | None = None

    @classmethod
    def from_ini(cls, path: str) -> WebUIConfig:
        """Read ``[webui]`` section from an INI config file.

        Parameters
        ----------
        path : str
            Path to ``gnat.ini`` / ``config.ini``.

        Returns
        -------
        WebUIConfig
            Populated instance; defaults used for any missing keys.
        """
        cp = configparser.ConfigParser()
        cp.read(path)
        if "webui" not in cp:
            return cls()
        sec = cp["webui"]
        return cls(
            enabled=sec.getboolean("enabled", fallback=True),
            bind=sec.get("bind", fallback="127.0.0.1"),
            port=sec.getint("port", fallback=8088),
            api_key=sec.get("api_key", fallback=""),
            reports_dir=sec.get("reports_dir", fallback=None) or None,
        )
