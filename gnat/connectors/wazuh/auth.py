# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.wazuh.auth

JWT authentication manager for the Wazuh connector.

## Wazuh auth flow

1. POST /security/user/authenticate
   Body: Basic Auth header (base64 username:password)
   Returns: {"data": {"token": "<JWT>"}, "error": 0}
1. Attach to all subsequent requests:
   Authorization: Bearer <JWT>
1. Token expiry is controlled by `auth_token_exp_timeout` in
   /var/ossec/api/configuration/api.yaml (default: 900 seconds).
   Wazuh returns HTTP 401 with error code 4009 on expiry.
1. WazuhAuthManager proactively renews at 80% of configured expiry
   (`token_renewal_threshold`) to avoid mid-request expiry in
   long-running operations.

## Run-as support

Wazuh supports impersonation via the `?raw=true` flag and a
`run_as` POST body parameter for pre-configured service accounts.
This connector uses standard authentication; run-as is not implemented.

## References

- https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- https://documentation.wazuh.com/current/user-manual/api/securing-api.html
"""

import base64
import json
import time

import urllib3

from .config import WazuhConfig
from .exceptions import WazuhAuthError


class WazuhAuthManager:
    """
    Manages Wazuh JWT authentication with proactive token renewal.

    Parameters
    ----------
    config : WazuhConfig
        Validated connector configuration.
    http : urllib3.PoolManager
        Shared connection pool (owned by WazuhClient).
    """

    def __init__(self, config: WazuhConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http
        self._token: str | None = None
        self._token_acquired_at: float = 0.0

    # ── Public ─────────────────────────────────────────────────────────────

    def get_auth_headers(self) -> dict[str, str]:
        """
        Return Authorization header with a valid JWT.

        Proactively renews the token before it expires. On a fresh
        instance, this triggers the first login.

        Returns
        -------
        dict[str, str]
            ``{"Authorization": "Bearer <token>"}``

        Raises
        ------
        WazuhAuthError
            If authentication fails.
        """
        if not self._token_is_valid():
            self._login()
        return {"Authorization": f"Bearer {self._token}"}

    def invalidate_token(self) -> None:
        """
        Force the next call to ``get_auth_headers`` to re-authenticate.
        Called when a 401 is received mid-session.
        """
        self._token = None
        self._token_acquired_at = 0.0

    def is_authenticated(self) -> bool:
        """Return True if a valid (non-expired) token is held."""
        return self._token_is_valid()

    # ── Internal ───────────────────────────────────────────────────────────

    def _token_is_valid(self) -> bool:
        """
        Token is valid if it exists and we are within the renewal window.
        Renewal threshold is config.token_renewal_threshold seconds before
        the token expires (defaults to 20% of token_expiry_secs).
        """
        if not self._token:
            return False
        elapsed = time.time() - self._token_acquired_at
        valid_window = self._config.token_expiry_secs - self._config.token_renewal_threshold
        return elapsed < valid_window

    def _login(self) -> None:
        """
        Authenticate against POST /security/user/authenticate and cache token.

        Wazuh uses HTTP Basic Auth on the login endpoint.

        Raises
        ------
        WazuhAuthError
            On bad credentials (401) or account locked (403/4000).
        """
        url = self._config.endpoint("security/user/authenticate")
        credentials = f"{self._config.username}:{self._config.password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
        }

        try:
            response = self._http.request(
                "POST",
                url,
                headers=headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise WazuhAuthError(f"HTTP error during Wazuh authentication: {exc}") from exc

        if response.status == 401:
            raise WazuhAuthError("Wazuh authentication failed: invalid username or password.")
        if response.status == 403:
            raise WazuhAuthError(
                "Wazuh authentication failed: account is disabled "
                "or insufficient RBAC permissions on the auth endpoint."
            )
        if response.status not in (200, 201):
            raise WazuhAuthError(f"Unexpected status {response.status} from Wazuh auth endpoint.")

        try:
            body = json.loads(response.data.decode("utf-8"))
            token = body["data"]["token"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise WazuhAuthError(
                f"Could not parse JWT token from Wazuh auth response: {exc}"
            ) from exc

        self._token = token
        self._token_acquired_at = time.time()

    def _handle_expired_response(self) -> None:
        """
        Called when a 401 with error code 4009 is detected mid-request.
        Invalidates the cached token so the next get_auth_headers() call
        triggers a fresh login.
        """
        self.invalidate_token()
