# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dynatrace.auth
===================================
OAuth2 client credentials authentication for Dynatrace Grail / Platform Storage API.

Dynatrace OAuth2 token acquisition flow
-----------------------------------------
1. POST https://sso.dynatrace.com/sso/oauth2/token
   (or https://<env>.apps.dynatrace.com/sso/oauth2/token for managed environments)
   Content-Type: application/x-www-form-urlencoded
   Body:
     grant_type=client_credentials
     &client_id=<oauth_client_id>
     &client_secret=<oauth_client_secret>
     &scope=storage:logs:read storage:events:read storage:query:execute ...

2. Response (200 OK):
   {
     "access_token": "eyJ0...",
     "token_type": "Bearer",
     "expires_in": 3600
   }

3. Attach to all Grail (/platform/storage/...) requests:
   Authorization: Bearer <access_token>

Token lifecycle
---------------
Tokens expire in 3600 seconds (1 hour). DynatraceOAuthManager:
  - Caches the token after acquisition
  - Proactively renews at 80% of expiry (720 seconds before expiry)
  - On 401, invalidates and re-acquires once before raising

Note: This manager is ONLY for Grail/Platform Storage API calls.
      Environment API v2 uses a static Api-Token header set in authenticate().
"""

import json
import time

import urllib3

from .config import DynatraceConfig
from .exceptions import DynatraceAuthError, DynatraceConfigError


class DynatraceOAuthManager:
    """
    Manages Dynatrace OAuth2 client credentials token lifecycle for Grail.

    Parameters
    ----------
    config : DynatraceConfig
    http : urllib3.PoolManager
    """

    def __init__(self, config: DynatraceConfig, http: urllib3.PoolManager) -> None:
        """Initialize DynatraceOAuthManager."""
        self._config = config
        self._http = http
        self._token: str | None = None
        self._acquired_at: float = 0.0
        self._expires_in: int = 3600

    def get_headers(self) -> dict[str, str]:
        """Return Authorization header with a valid OAuth2 Bearer token."""
        if not self._config.oauth_client_id:
            raise DynatraceConfigError(
                "Grail OAuth2 credentials not configured. "
                "Set oauth_client_id and oauth_client_secret in [dynatrace] config."
            )
        if not self._token_is_valid():
            self._acquire_token()
        return {
            "Authorization": f"Bearer {self._token}",
        }

    def invalidate_token(self) -> None:
        """Force re-acquisition on next get_headers() call."""
        self._token = None
        self._acquired_at = 0.0

    def is_authenticated(self) -> bool:
        """True if a valid non-expiring token is held."""
        return self._token_is_valid()

    # ── Internal ───────────────────────────────────────────────────────────

    def _token_is_valid(self) -> bool:
        """Internal helper for token is valid."""
        if not self._token:
            return False
        elapsed = time.time() - self._acquired_at
        valid_window = self._expires_in - self._config.token_renewal_threshold
        return elapsed < valid_window

    def _acquire_token(self) -> None:
        """Obtain a new token from the Dynatrace OAuth2 token endpoint."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = self._http.request(
                "POST",
                self._config.resolved_oauth_token_url,
                body=self._config.token_request_body,
                headers=headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise DynatraceAuthError(
                f"Failed to connect to Dynatrace OAuth2 token endpoint: {exc}"
            ) from exc

        if response.status == 400:
            try:
                body = json.loads(response.data.decode("utf-8"))
                error = body.get("error", "")
                desc = body.get("error_description", "")
            except Exception:
                error, desc = "unknown", ""
            raise DynatraceAuthError(
                f"Dynatrace token request failed: {error} — {desc}",
                dt_error_code=error,
            )

        if response.status == 401:
            raise DynatraceAuthError(
                "Dynatrace rejected token request (HTTP 401). "
                "Check oauth_client_id and oauth_client_secret in [dynatrace] config."
            )

        if response.status != 200:
            raise DynatraceAuthError(
                f"Unexpected HTTP {response.status} from Dynatrace OAuth2 token endpoint."
            )

        try:
            body = json.loads(response.data.decode("utf-8"))
            self._token = body["access_token"]
            self._expires_in = int(body.get("expires_in", 3600))
            self._acquired_at = time.time()
        except (KeyError, json.JSONDecodeError) as exc:
            raise DynatraceAuthError(f"Could not parse Dynatrace token response: {exc}") from exc
