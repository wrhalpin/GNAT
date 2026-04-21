# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dynatrace.config
=====================================
Configuration schema for the Dynatrace connector.

INI example
-----------
[dynatrace]
host      = https://YOUR_ENV_ID.live.dynatrace.com
api_token = dt0c01.YOUR_API_TOKEN
; --- Grail / Platform Storage API (optional)
; oauth_client_id     = dt0s01.YOUR_OAUTH2_CLIENT_ID
; oauth_client_secret = dt0s01.YOUR_OAUTH2_CLIENT_SECRET
; oauth_token_url     = https://sso.dynatrace.com/sso/oauth2/token
verify_ssl = true
timeout    = 30

Dual-auth model
---------------
Environment API v2 uses a static Api-Token header.
Grail / Platform Storage API (/platform/storage/...) requires
OAuth2 client credentials with a separate token URL and 1 hour TTL.
"""

import configparser
import urllib.parse
from dataclasses import dataclass, field

from .exceptions import DynatraceConfigError

_REQUIRED = {"host", "api_token"}

_DEFAULTS: dict = {
    "host": "",
    "api_token": "",
    "oauth_client_id": "",
    "oauth_client_secret": "",
    "oauth_token_url": "",
    "verify_ssl": "true",
    "timeout": "30",
    "grail_scan_limit_gb": "500",
    "grail_max_records": "1000",
    "grail_poll_interval_secs": "2.0",
    "grail_max_wait_secs": "120.0",
}

# OAuth2 scopes required for Grail platform storage APIs
_GRAIL_SCOPES = (
    "storage:logs:read "
    "storage:events:read "
    "storage:query:execute "
    "storage:bizevents:read "
    "storage:bizevents:write"
)


@dataclass
class DynatraceConfig:
    """Validated configuration for the Dynatrace connector."""

    host: str
    api_token: str
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_token_url: str = ""
    verify_ssl: bool = True
    timeout: float = 30.0
    grail_scan_limit_gb: int = 500
    grail_max_records: int = 1000
    grail_poll_interval_secs: float = 2.0
    grail_max_wait_secs: float = 120.0
    # Computed in __post_init__
    _oauth_token_url_resolved: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Post-init setup for DynatraceConfig."""
        self.host = self.host.rstrip("/")
        # Resolve OAuth2 token URL if not explicitly set
        if self.oauth_token_url:
            self._oauth_token_url_resolved = self.oauth_token_url
        elif ".apps.dynatrace.com" in self.host:
            self._oauth_token_url_resolved = f"{self.host}/sso/oauth2/token"
        else:
            self._oauth_token_url_resolved = "https://sso.dynatrace.com/sso/oauth2/token"
        self._validate()

    def _validate(self) -> None:
        """Internal helper for validate."""
        missing = {k for k in _REQUIRED if not getattr(self, k, "").strip()}
        if missing:
            raise DynatraceConfigError(
                f"Missing required [dynatrace] config keys: {', '.join(sorted(missing))}"
            )

    def api_url(self, path: str) -> str:
        """Build a full Dynatrace Environment API URL."""
        return urllib.parse.urljoin(self.host + "/", path.lstrip("/"))

    @property
    def token_renewal_threshold(self) -> float:
        """Renew OAuth2 token at 80% of expiry window (720 seconds early)."""
        return 720.0

    @property
    def token_request_body(self) -> bytes:
        """Return URL-encoded body for the Grail OAuth2 token request."""
        params = {
            "grant_type": "client_credentials",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
            "scope": _GRAIL_SCOPES,
        }
        return urllib.parse.urlencode(params).encode("utf-8")

    @property
    def resolved_oauth_token_url(self) -> str:
        """Return the resolved OAuth2 token URL (auto-detected or explicit)."""
        return self._oauth_token_url_resolved


def load_dynatrace_config(
    config: configparser.ConfigParser,
    section: str = "dynatrace",
) -> DynatraceConfig:
    """Parse [dynatrace] section from gnat.ini."""
    if not config.has_section(section):
        raise DynatraceConfigError(f"Configuration section '[{section}]' not found in gnat.ini.")
    raw = dict(_DEFAULTS)
    raw.update(dict(config.items(section)))

    def _bool(v: str) -> bool:
        return v.strip().lower() in ("true", "1", "yes")

    return DynatraceConfig(
        host=raw["host"].strip(),
        api_token=raw["api_token"].strip(),
        oauth_client_id=raw["oauth_client_id"].strip(),
        oauth_client_secret=raw["oauth_client_secret"].strip(),
        oauth_token_url=raw["oauth_token_url"].strip(),
        verify_ssl=_bool(raw["verify_ssl"]),
        timeout=float(raw["timeout"]),
        grail_scan_limit_gb=int(raw["grail_scan_limit_gb"]),
        grail_max_records=int(raw["grail_max_records"]),
        grail_poll_interval_secs=float(raw["grail_poll_interval_secs"]),
        grail_max_wait_secs=float(raw["grail_max_wait_secs"]),
    )
