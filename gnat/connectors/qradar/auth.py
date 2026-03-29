"""
gnat.connectors.qradar.auth
================================
Authentication manager for the QRadar connector.

QRadar uses a static Authorized Service token sent as the ``SEC``
header on every request. There is no token refresh, session management,
or expiry handling — the token is valid until revoked in the QRadar
admin console.

This is the simplest auth pattern across all GNAT connectors.
The auth manager focuses on header construction and a verify() method
that hits the lightweight ``/api/help/version`` endpoint to confirm
connectivity and token validity.

Token scoping
-------------
QRadar tokens inherit capabilities from the user role they are assigned.
The required capabilities for GNAT operations are:
  OFFENSE MANAGER            — read/update offenses and notes
  NETWORK ACTIVITY           — execute Ariel AQL searches
  REFERENCE DATA MANAGER     — create/update reference sets and maps
  LOG SOURCE MANAGEMENT      — read log source inventory (optional)
  ASSET MANAGEMENT           — read asset inventory (optional)

If a request requires a capability not held by the token, QRadar returns
HTTP 403 with QRadar error code 1002.

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-restful-overview
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-authorized-service-tokens
"""

import json
import urllib3

from .config import QRadarConfig
from .exceptions import QRadarAuthError


class QRadarAuthManager:
    """
    Manages QRadar SEC token authentication.

    Since QRadar tokens are static, this class focuses on header
    construction and connectivity verification.

    Parameters
    ----------
    config : QRadarConfig
        Validated connector configuration.
    http : urllib3.PoolManager
        Shared connection pool (owned by QRadarClient).
    """

    def __init__(self, config: QRadarConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http

    # ── Public ─────────────────────────────────────────────────────────────

    def get_headers(self, with_body: bool = False) -> dict[str, str]:
        """
        Return request headers for a QRadar API call.

        Parameters
        ----------
        with_body : bool
            If True, include Content-Type: application/json.

        Returns
        -------
        dict[str, str]
            Headers including SEC token, Version, and Accept.
        """
        if with_body:
            return self._config.json_headers
        return self._config.base_headers

    def verify(self) -> dict:
        """
        Verify connectivity and token validity by hitting /api/help/version.

        Returns
        -------
        dict
            QRadar version info.

        Raises
        ------
        QRadarAuthError
            If the token is invalid (401/403) or QRadar is unreachable.
        """
        url = self._config.endpoint("help/version")
        try:
            response = self._http.request(
                "GET",
                url,
                headers=self._config.base_headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise QRadarAuthError(
                f"Cannot connect to QRadar at {url}: {exc}"
            ) from exc

        if response.status == 401:
            raise QRadarAuthError(
                "QRadar rejected the SEC token (HTTP 401). "
                "Check 'token' in [qradar] config."
            )
        if response.status == 403:
            raise QRadarAuthError(
                "QRadar SEC token lacks required capability (HTTP 403). "
                "Check token capability assignments in Admin → Authorized Services."
            )
        if response.status != 200:
            raise QRadarAuthError(
                f"Unexpected response from QRadar: HTTP {response.status}"
            )

        try:
            return json.loads(response.data.decode("utf-8"))
        except Exception:
            return {}
