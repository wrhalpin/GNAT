# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.auth
===============================
Authentication manager for the MISP connector.

MISP uses a static API key sent as the ``Authorization`` header.
No token acquisition, expiry, or refresh. Simpler than Wazuh/Sentinel.

Note: MISP uses ``Authorization: <key>`` (no 'Bearer' prefix),
distinct from both QRadar's ``SEC: <token>`` and Elastic's
``Authorization: ApiKey <base64>``.
"""

import json

import urllib3

from .config import MISPConfig
from .exceptions import MISPAuthError


class MISPAuthManager:
    """Manages MISP static API key authentication."""

    def __init__(self, config: MISPConfig, http: urllib3.PoolManager) -> None:
        """Initialize MISPAuthManager."""
        self._config = config
        self._http = http

    def get_headers(self) -> dict[str, str]:
        """Return MISP request headers with API key."""
        return self._config.base_headers

    def verify(self) -> dict:
        """
        Verify API key by hitting the /servers/getPyMISPVersion endpoint.

        Returns
        -------
        dict
            MISP version info.

        Raises
        ------
        MISPAuthError
        """
        url = self._config.endpoint("servers/getPyMISPVersion.json")
        try:
            response = self._http.request(
                "GET",
                url,
                headers=self._config.base_headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise MISPAuthError(f"Cannot connect to MISP at {url}: {exc}") from exc

        if response.status == 401:
            raise MISPAuthError("MISP API key rejected (HTTP 401). Check api_key in [misp] config.")
        if response.status == 403:
            raise MISPAuthError("MISP API key lacks required permissions (HTTP 403).")
        if response.status != 200:
            raise MISPAuthError(f"Unexpected response from MISP: HTTP {response.status}")

        try:
            return json.loads(response.data.decode("utf-8"))
        except Exception:
            return {}
