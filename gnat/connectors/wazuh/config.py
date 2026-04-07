# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.wazuh.config

Configuration schema for the Wazuh connector.

## INI example

[wazuh]
host              = wazuh.corp.example.com
port              = 55000
scheme            = https
username          = wazuh-svc
password          = s3cr3t
verify_ssl        = false         ; Wazuh default uses self-signed certs
timeout           = 30
max_results       = 500
token_expiry_secs = 900           ; mirror your wazuh server auth_token_exp_timeout
indexer_enabled   = false
indexer_host      = wazuh.corp.example.com
indexer_port      = 9200
indexer_username  = admin
indexer_password  =

## Notes

- `verify_ssl = false` is typical for dev/lab Wazuh installs that use
  the default self-signed certificate. Set to true in production.
- `token_expiry_secs` should match the `auth_token_exp_timeout` setting
  in /var/ossec/api/configuration/api.yaml on the Wazuh server.
  The default is 900 seconds (15 minutes). WazuhAuthManager uses this value
  to proactively renew before actual expiry.
- `max_results` caps are applied to list operations that use Wazuh's
  `limit` parameter. Wazuh hard-caps at 500 per request; for larger
  result sets use the paginate helpers which handle offset iteration.
"""

import configparser
from dataclasses import dataclass, field

from .exceptions import WazuhConfigError

_REQUIRED = {"host", "username", "password"}

_DEFAULTS: dict = {
    "port": "55000",
    "scheme": "https",
    "verify_ssl": "false",
    "timeout": "30",
    "max_results": "500",
    "token_expiry_secs": "900",
    "indexer_enabled": "false",
    "indexer_host": "",
    "indexer_port": "9200",
    "indexer_username": "admin",
    "indexer_password": "",
}

# Wazuh hard-caps list results at 500 per request

WAZUH_MAX_LIMIT = 500


@dataclass
class WazuhConfig:
    """
    Validated configuration for the Wazuh connector.

    Attributes
    ----------
    host : str
        Hostname or IP of the Wazuh manager.
    port : int
        Manager API port (default 55000).
    scheme : str
        'https' (strongly recommended) or 'http'.
    username : str
        Wazuh API username (default: 'wazuh').
    password : str
        Wazuh API password.
    verify_ssl : bool
        Whether to verify the server's TLS certificate.
        False is typical for self-signed lab certs.
    timeout : int
        HTTP request timeout in seconds.
    max_results : int
        Default result count cap. Capped at WAZUH_MAX_LIMIT (500).
    token_expiry_secs : int
        Mirror of wazuh server auth_token_exp_timeout. Used to schedule
        proactive token renewal (renew at 80% of this value).
    indexer_enabled : bool
        True to enable Wazuh Indexer (OpenSearch) queries.
    indexer_host : str
        Hostname of the Wazuh Indexer. Defaults to same host as manager.
    indexer_port : int
        Indexer port (default 9200).
    indexer_username : str
        Indexer admin username.
    indexer_password : str
        Indexer admin password.
    base_url : str
        Computed base URL for the Manager API.
    indexer_url : str
        Computed base URL for the Indexer API.
    """

    host: str
    username: str
    password: str
    port: int = 55000
    scheme: str = "https"
    verify_ssl: bool = False
    timeout: int = 30
    max_results: int = 500
    token_expiry_secs: int = 900
    indexer_enabled: bool = False
    indexer_host: str = ""
    indexer_port: int = 9200
    indexer_username: str = "admin"
    indexer_password: str = ""
    base_url: str = field(init=False)
    indexer_url: str = field(init=False)

    def __post_init__(self) -> None:
        """Post-init setup for WazuhConfig."""
        self.base_url = f"{self.scheme}://{self.host}:{self.port}"
        _idx_host = self.indexer_host or self.host
        self.indexer_url = f"{self.scheme}://{_idx_host}:{self.indexer_port}"
        # Cap max_results at Wazuh's hard limit
        self.max_results = min(self.max_results, WAZUH_MAX_LIMIT)
        self._validate()

    def _validate(self) -> None:
        """Internal helper for validate."""
        if not self.host:
            raise WazuhConfigError("'host' is required in [wazuh] config.")
        if not self.username:
            raise WazuhConfigError("'username' is required in [wazuh] config.")
        if not self.password:
            raise WazuhConfigError("'password' is required in [wazuh] config.")
        if self.scheme not in ("http", "https"):
            raise WazuhConfigError(f"Invalid scheme '{self.scheme}'. Must be 'http' or 'https'.")
        if not 1 <= self.port <= 65535:
            raise WazuhConfigError(f"Invalid port {self.port}.")
        if self.timeout <= 0:
            raise WazuhConfigError("'timeout' must be a positive integer.")
        if self.token_expiry_secs <= 0:
            raise WazuhConfigError("'token_expiry_secs' must be a positive integer.")
        if self.indexer_enabled and not (self.indexer_host or self.host):
            raise WazuhConfigError("'indexer_host' is required when 'indexer_enabled = true'.")

    def endpoint(self, path: str) -> str:
        """Build a full Manager API URL."""
        return f"{self.base_url}/{path.lstrip('/')}"

    def indexer_endpoint(self, path: str) -> str:
        """Build a full Indexer API URL."""
        return f"{self.indexer_url}/{path.lstrip('/')}"

    @property
    def token_renewal_threshold(self) -> float:
        """
        Seconds before expiry at which the token should be renewed.
        Set to 20% of the configured expiry window (minimum 60 seconds).
        """
        return max(self.token_expiry_secs * 0.20, 60.0)


def load_wazuh_config(
    config: configparser.ConfigParser,
    section: str = "wazuh",
) -> WazuhConfig:
    """
    Parse [wazuh] section from a gnat.ini ConfigParser instance.

    Parameters
    ----------
    config : configparser.ConfigParser
        Already-loaded ConfigParser.
    section : str
        INI section name. Defaults to 'wazuh'.

    Returns
    -------
    WazuhConfig

    Raises
    ------
    WazuhConfigError
        If the section is missing or required keys are absent.
    """
    if not config.has_section(section):
        raise WazuhConfigError(f"Configuration section '[{section}]' not found in gnat.ini.")

    raw = dict(_DEFAULTS)
    raw.update(dict(config.items(section)))

    missing = {k for k in _REQUIRED if not raw.get(k, "").strip()}
    if missing:
        raise WazuhConfigError(
            f"Missing required [wazuh] config keys: {', '.join(sorted(missing))}"
        )

    def _bool(val: str) -> bool:
        """Internal helper for bool."""
        return val.strip().lower() in ("true", "1", "yes")

    return WazuhConfig(
        host=raw["host"].strip(),
        port=int(raw["port"]),
        scheme=raw["scheme"].strip().lower(),
        username=raw["username"].strip(),
        password=raw["password"].strip(),
        verify_ssl=_bool(raw["verify_ssl"]),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
        token_expiry_secs=int(raw["token_expiry_secs"]),
        indexer_enabled=_bool(raw["indexer_enabled"]),
        indexer_host=raw["indexer_host"].strip(),
        indexer_port=int(raw["indexer_port"]),
        indexer_username=raw["indexer_username"].strip(),
        indexer_password=raw["indexer_password"].strip(),
    )
