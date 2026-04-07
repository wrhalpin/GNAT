# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.qradar.config
===================================
Configuration schema for the QRadar connector.

INI example
-----------
[qradar]
host              = qradar.corp.example.com
token             = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
verify_ssl        = true
api_version       = 20.0
scheme            = https
timeout           = 30
max_results       = 50
offense_status    = OPEN

Notes
-----
- ``token`` is the Authorized Service token from:
  QRadar Admin → User Management → Authorized Services
  It is a UUID-format string sent as the ``SEC`` header.
- ``api_version`` controls the ``Version`` header sent on every request.
  QRadar uses this for backward-compatible API evolution.
  20.0 is current stable; earlier versions (17–19) supported for CE users.
- ``max_results`` is the default page size used in Range header requests.
  QRadar imposes a server-side cap (typically 500 for most endpoints;
  50 is a safe default that avoids timeout on heavy offense queries).
- ``offense_status`` is the default filter applied when listing offenses.
  Values: 'OPEN', 'HIDDEN', 'CLOSED', or '' for all.
"""

import configparser
from dataclasses import dataclass, field

from .exceptions import QRadarConfigError

_REQUIRED = {"host", "token"}

_DEFAULTS: dict = {
    "host": "",
    "token": "",
    "verify_ssl": "true",
    "api_version": "20.0",
    "scheme": "https",
    "timeout": "30",
    "max_results": "50",
    "offense_status": "OPEN",
}


@dataclass
class QRadarConfig:
    """
    Validated configuration for the QRadar connector.

    Attributes
    ----------
    host : str
        QRadar console hostname or IP.
    token : str
        Authorized Service token (UUID string).
    verify_ssl : bool
        Whether to verify TLS certificates.
    api_version : str
        QRadar REST API version (e.g. '20.0').
    scheme : str
        'https' or 'http'.
    timeout : int
        HTTP request timeout in seconds.
    max_results : int
        Default page size for Range-based pagination.
    offense_status : str
        Default offense status filter ('OPEN', 'HIDDEN', 'CLOSED', or '').
    base_url : str
        Computed API base URL.
    """

    host: str
    token: str
    verify_ssl: bool = True
    api_version: str = "20.0"
    scheme: str = "https"
    timeout: int = 30
    max_results: int = 50
    offense_status: str = "OPEN"
    base_url: str = field(init=False)

    def __post_init__(self) -> None:
        self.base_url = f"{self.scheme}://{self.host}/api"
        self._validate()

    def _validate(self) -> None:
        if not self.host:
            raise QRadarConfigError("'host' is required in [qradar] config.")
        if not self.token:
            raise QRadarConfigError("'token' is required in [qradar] config.")
        if self.scheme not in ("http", "https"):
            raise QRadarConfigError(f"Invalid scheme '{self.scheme}'. Must be 'http' or 'https'.")
        if self.timeout <= 0:
            raise QRadarConfigError("'timeout' must be a positive integer.")
        if self.max_results <= 0:
            raise QRadarConfigError("'max_results' must be a positive integer.")

    def endpoint(self, path: str) -> str:
        """Build a full QRadar API URL."""
        return f"{self.base_url}/{path.lstrip('/')}"

    @property
    def base_headers(self) -> dict[str, str]:
        """
        Return the standard headers required on every QRadar API request.

        QRadar requires:
          SEC      — the Authorized Service token
          Version  — the API version string
          Accept   — application/json
        """
        return {
            "SEC": self.token,
            "Version": self.api_version,
            "Accept": "application/json",
        }

    @property
    def json_headers(self) -> dict[str, str]:
        """Return base headers plus Content-Type for requests with a JSON body."""
        return {
            **self.base_headers,
            "Content-Type": "application/json",
        }


def load_qradar_config(
    config: configparser.ConfigParser,
    section: str = "qradar",
) -> "QRadarConfig":
    """
    Parse [qradar] section from a gnat.ini ConfigParser instance.

    Parameters
    ----------
    config : configparser.ConfigParser
        Already-loaded ConfigParser.
    section : str
        INI section name. Defaults to 'qradar'.

    Returns
    -------
    QRadarConfig

    Raises
    ------
    QRadarConfigError
    """
    if not config.has_section(section):
        raise QRadarConfigError(f"Configuration section '[{section}]' not found in gnat.ini.")

    raw = dict(_DEFAULTS)
    raw.update(dict(config.items(section)))

    missing = {k for k in _REQUIRED if not raw.get(k, "").strip()}
    if missing:
        raise QRadarConfigError(
            f"Missing required [qradar] config keys: {', '.join(sorted(missing))}"
        )

    def _bool(v: str) -> bool:
        return v.strip().lower() in ("true", "1", "yes")

    return QRadarConfig(
        host=raw["host"].strip(),
        token=raw["token"].strip(),
        verify_ssl=_bool(raw["verify_ssl"]),
        api_version=raw["api_version"].strip(),
        scheme=raw["scheme"].strip().lower(),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
        offense_status=raw["offense_status"].strip().upper(),
    )
