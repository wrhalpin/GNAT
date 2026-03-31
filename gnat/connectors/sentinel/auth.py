"""
gnat.connectors.sentinel.auth
===================================
Azure OAuth2 client credentials authentication for the Sentinel connector.

Azure token acquisition flow
------------------------------
1. POST https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token
   Content-Type: application/x-www-form-urlencoded
   Body:
     grant_type=client_credentials
     &client_id=<app_id>
     &client_secret=<secret>
     &scope=https://management.azure.com/.default

2. Response (200 OK):
   {
     "access_token": "eyJ0...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "ext_expires_in": 3600
   }

3. Attach to all subsequent requests:
   Authorization: Bearer <access_token>
   Content-Type: application/json

Token lifecycle
---------------
Tokens expire in 3600 seconds (1 hour). SentinelAuthManager:
  - Caches the token after acquisition
  - Proactively renews at 80% of expiry (720 seconds before expiry)
  - On 401, invalidates and re-acquires once before raising

This pattern is identical in concept to WazuhAuthManager but uses
Azure's token endpoint rather than Wazuh's /security/user/authenticate.
"""

import json
import time

import urllib3

from .config import SentinelConfig
from .exceptions import SentinelAuthError


class SentinelAuthManager:
    """
    Manages Azure OAuth2 client credentials token lifecycle.

    Parameters
    ----------
    config : SentinelConfig
    http : urllib3.PoolManager
    """

    def __init__(self, config: SentinelConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http
        self._token: str | None = None
        self._acquired_at: float = 0.0
        self._expires_in: int = 3600

    def get_headers(self) -> dict[str, str]:
        """Return Authorization + Content-Type headers with a valid token."""
        if not self._token_is_valid():
            self._acquire_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
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
        if not self._token:
            return False
        elapsed = time.time() - self._acquired_at
        # Renew when within renewal_threshold of expiry
        valid_window = self._expires_in - self._config.token_renewal_threshold
        return elapsed < valid_window

    def _acquire_token(self) -> None:
        """Obtain a new token from the Azure token endpoint."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = self._http.request(
                "POST",
                self._config.token_url,
                body=self._config.token_request_body,
                headers=headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise SentinelAuthError(
                f"Failed to connect to Azure token endpoint: {exc}"
            ) from exc

        if response.status == 400:
            try:
                body = json.loads(response.data.decode("utf-8"))
                error = body.get("error", "")
                desc = body.get("error_description", "")
            except Exception:
                error, desc = "unknown", ""
            raise SentinelAuthError(
                f"Azure token request failed: {error} — {desc}",
                azure_error_code=error,
            )

        if response.status == 401:
            raise SentinelAuthError(
                "Azure rejected token request (HTTP 401). "
                "Check client_id and client_secret in [sentinel] config."
            )

        if response.status != 200:
            raise SentinelAuthError(
                f"Unexpected HTTP {response.status} from Azure token endpoint."
            )

        try:
            body = json.loads(response.data.decode("utf-8"))
            self._token = body["access_token"]
            self._expires_in = int(body.get("expires_in", 3600))
            self._acquired_at = time.time()
        except (KeyError, json.JSONDecodeError) as exc:
            raise SentinelAuthError(
                f"Could not parse Azure token response: {exc}"
            ) from exc
