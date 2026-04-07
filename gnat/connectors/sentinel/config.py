# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sentinel.config
=====================================
Configuration schema for the Microsoft Sentinel connector.

INI example
-----------
[sentinel]
tenant_id         = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_id         = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_secret     =
subscription_id   = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
resource_group    = my-sentinel-rg
workspace_name    = my-sentinel-workspace
workspace_id      =
verify_ssl        = true
timeout           = 30
max_results       = 100
api_version       = 2023-11-01

Azure setup notes
-----------------
1. Register an app in Azure Active Directory (App registrations).
2. Create a client secret under Certificates & secrets.
3. Assign RBAC roles to the service principal at the workspace scope:
     Microsoft Sentinel Reader / Responder / Contributor
4. Note tenant_id (Directory ID), client_id (Application ID), secret value.

The workspace_id (GUID) is needed for some Log Analytics queries.
Find it in: Azure Portal → Log Analytics workspaces → <workspace> → Overview.
"""

import configparser
from dataclasses import dataclass, field

from .exceptions import SentinelConfigError

_REQUIRED = {
    "tenant_id",
    "client_id",
    "client_secret",
    "subscription_id",
    "resource_group",
    "workspace_name",
}

_DEFAULTS: dict = {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "subscription_id": "",
    "resource_group": "",
    "workspace_name": "",
    "workspace_id": "",
    "verify_ssl": "true",
    "timeout": "30",
    "max_results": "100",
    "api_version": "2023-11-01",
}

_AZURE_MGMT_BASE = "https://management.azure.com"
_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_MGMT_SCOPE = "https://management.azure.com/.default"


@dataclass
class SentinelConfig:
    """Validated configuration for the Microsoft Sentinel connector."""

    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    resource_group: str
    workspace_name: str
    workspace_id: str = ""
    verify_ssl: bool = True
    timeout: int = 30
    max_results: int = 100
    api_version: str = "2023-11-01"
    sentinel_base_url: str = field(init=False)
    token_url: str = field(init=False)

    def __post_init__(self) -> None:
        """Post-init setup for SentinelConfig."""
        ws_path = (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )
        self.sentinel_base_url = f"{_AZURE_MGMT_BASE}{ws_path}"
        self.token_url = _TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        self._validate()

    def _validate(self) -> None:
        """Internal helper for validate."""
        missing = {k for k in _REQUIRED if not getattr(self, k, "").strip()}
        if missing:
            raise SentinelConfigError(
                f"Missing required [sentinel] config keys: {', '.join(sorted(missing))}"
            )

    def endpoint(self, resource: str) -> str:
        """Build a full Sentinel API URL with api-version query param."""
        resource = resource.lstrip("/")
        return f"{self.sentinel_base_url}/{resource}?api-version={self.api_version}"

    def endpoint_no_version(self, resource: str) -> str:
        """Build URL without appending api-version (for nextLink pagination)."""
        return f"{self.sentinel_base_url}/{resource.lstrip('/')}"

    @property
    def token_request_body(self) -> bytes:
        """Return URL-encoded body for the OAuth2 token request."""
        import urllib.parse

        params = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": _MGMT_SCOPE,
        }
        return urllib.parse.urlencode(params).encode("utf-8")

    @property
    def token_expiry_secs(self) -> int:
        """Azure access tokens expire in 3600 seconds."""
        return 3600

    @property
    def token_renewal_threshold(self) -> float:
        """Renew at 80% of expiry window (720 seconds early)."""
        return self.token_expiry_secs * 0.20


def load_sentinel_config(
    config: configparser.ConfigParser,
    section: str = "sentinel",
) -> SentinelConfig:
    """Parse [sentinel] section from gnat.ini."""
    if not config.has_section(section):
        raise SentinelConfigError(f"Configuration section '[{section}]' not found in gnat.ini.")
    raw = dict(_DEFAULTS)
    raw.update(dict(config.items(section)))

    def _bool(v: str) -> bool:
        """Internal helper for bool."""
        return v.strip().lower() in ("true", "1", "yes")

    return SentinelConfig(
        tenant_id=raw["tenant_id"].strip(),
        client_id=raw["client_id"].strip(),
        client_secret=raw["client_secret"].strip(),
        subscription_id=raw["subscription_id"].strip(),
        resource_group=raw["resource_group"].strip(),
        workspace_name=raw["workspace_name"].strip(),
        workspace_id=raw["workspace_id"].strip(),
        verify_ssl=_bool(raw["verify_ssl"]),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
        api_version=raw["api_version"].strip(),
    )
