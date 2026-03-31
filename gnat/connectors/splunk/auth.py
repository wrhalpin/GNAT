"""
gnat.connectors.splunk.auth

Authentication manager for the Splunk connector.

Splunk supports two auth modes used by GNAT:

1. Pre-generated Token (preferred)
- Created in Splunk Web: Settings -> Tokens
- Passed as `Authorization: Splunk <token>` on every request
- No session management needed; token has a configurable expiry
- Supported since Splunk 7.3
1. Session Key (username + password)
- POST /services/auth/login -> returns sessionKey
- Passed as `Authorization: Splunk <sessionKey>`
- Sessions expire after idle timeout (default 1 hour)
- SplunkAuthManager handles automatic renewal

Both modes produce the same Authorization header format, so the
HTTP client layer is identical once auth is resolved.

## Note on OAuth2

Splunk Cloud Platform supports OAuth2 / OIDC for SSO environments.
That flow is NOT implemented here -- use pre-generated tokens for
service accounts connecting to Splunk Cloud.

## References

- https://docs.splunk.com/Documentation/Splunk/latest/Security/UseAuthTokens
- https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTaccess
  """

import json
import time
import urllib.parse

import urllib3

from .config import SplunkConfig
from .exceptions import SplunkAuthError

# Splunk session keys typically expire after 3600s idle; renew 5 min early.

_SESSION_EXPIRY_BUFFER_SECONDS = 300

class SplunkAuthManager:
    """
    Manages Splunk authentication state for the urllib3-based HTTP client.

    Usage
    -----
    auth = SplunkAuthManager(config, http_pool)
    headers = auth.get_auth_headers()   # always returns a valid token header

    Parameters
    ----------
    config : SplunkConfig
        Validated connector configuration.
    http : urllib3.PoolManager
        Shared urllib3 connection pool (owned by SplunkClient).
    """

    def __init__(self, config: SplunkConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http
        self._session_key: str | None = None
        self._session_expires_at: float = 0.0

    # ── Public ─────────────────────────────────────────────────────────────

    def get_auth_headers(self) -> dict[str, str]:
        """
        Return a dict containing the Authorization header value.

        If the config supplies a pre-generated token, it is returned
        directly. Otherwise a session key is obtained (or renewed)
        via username/password login.

        Returns
        -------
        dict[str, str]
            ``{"Authorization": "Splunk <token_or_session_key>"}``

        Raises
        ------
        SplunkAuthError
            If authentication fails or credentials are invalid.
        """
        token = self._resolve_token()
        return {"Authorization": f"Splunk {token}"}

    def invalidate_session(self) -> None:
        """
        Force the next call to ``get_auth_headers`` to re-authenticate.
        Call this when a 401/403 is received on a non-auth endpoint.
        """
        self._session_key = None
        self._session_expires_at = 0.0

    def logout(self) -> None:
        """
        Explicitly terminate the current Splunk session.
        Only applicable to session key (username/password) auth;
        no-op for pre-generated token auth.
        """
        if self._config.uses_token_auth or not self._session_key:
            return
        try:
            self._post_logout(self._session_key)
        finally:
            self.invalidate_session()

    # ── Internal ───────────────────────────────────────────────────────────

    def _resolve_token(self) -> str:
        """Return the active token string, refreshing if necessary."""
        if self._config.uses_token_auth:
            return self._config.token

        if self._session_is_valid():
            return self._session_key  # type: ignore[return-value]

        return self._login()

    def _session_is_valid(self) -> bool:
        return (
            self._session_key is not None
            and time.time() < self._session_expires_at - _SESSION_EXPIRY_BUFFER_SECONDS
        )

    def _login(self) -> str:
        """
        POST to /services/auth/login and cache the returned session key.

        Splunk returns XML by default; we request JSON via output_mode.

        Returns
        -------
        str
            The Splunk session key.

        Raises
        ------
        SplunkAuthError
            On 401/403, or if the response cannot be parsed.
        """
        endpoint = f"{self._config.base_url}/services/auth/login"
        body = urllib.parse.urlencode(
            {
                "username": self._config.username,
                "password": self._config.password,
                "output_mode": "json",
            }
        ).encode("utf-8")

        try:
            response = self._http.request(
                "POST",
                endpoint,
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise SplunkAuthError(
                f"HTTP error during Splunk login: {exc}"
            ) from exc

        if response.status == 401:
            raise SplunkAuthError(
                "Splunk login failed: invalid username or password."
            )
        if response.status == 403:
            raise SplunkAuthError(
                "Splunk login failed: account disabled or insufficient permissions."
            )
        if response.status not in (200, 201):
            raise SplunkAuthError(
                f"Splunk login returned unexpected status {response.status}."
            )

        try:
            data = json.loads(response.data.decode("utf-8"))
            session_key = data["sessionKey"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise SplunkAuthError(
                f"Could not parse session key from Splunk login response: {exc}"
            ) from exc

        self._session_key = session_key
        # Splunk does not expose expiry in the login response; assume 1 hour.
        self._session_expires_at = time.time() + 3600.0
        return session_key

    def _post_logout(self, session_key: str) -> None:
        """DELETE the current session from Splunk."""
        endpoint = f"{self._config.base_url}/services/authentication/httpauth-tokens/{session_key}"
        try:
            self._http.request(
                "DELETE",
                endpoint,
                headers={"Authorization": f"Splunk {session_key}"},
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError:
            pass  # Best-effort logout; do not raise.
