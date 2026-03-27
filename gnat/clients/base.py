"""
gnat.clients.base
====================

urllib3-based base HTTP client that all connector clients inherit from.

All connector-specific clients should subclass :class:`BaseClient` and
implement :meth:`authenticate`.  The base class provides:

* Connection pool management via ``urllib3.PoolManager``
* JSON request/response helpers
* Retry logic with exponential back-off
* Configurable SSL verification and timeout
* Structured error handling via :class:`SAKClientError`

Example (connector authors)::

    from gnat.clients.base import BaseClient

    class ThreatQClient(BaseClient):
        def authenticate(self):
            resp = self.post("/api/token", json={"grant_type": "client_credentials"})
            self._auth_headers["Authorization"] = f"Bearer {resp['access_token']}"
"""

import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlencode

import urllib3
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class SAKClientError(Exception):
    """
    Raised when an HTTP request to a security platform fails.

    Attributes
    ----------
    status : int
        HTTP status code returned by the server (0 if no response).
    body : str
        Raw response body (empty string if unavailable).
    """

    def __init__(self, message: str, status: int = 0, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class BaseClient:
    """
    urllib3-backed HTTP client base class for all GNAT connectors.

    Parameters
    ----------
    host : str
        Base URL of the target API, e.g. ``"https://threatq.example.com"``.
    verify_ssl : bool
        Whether to verify TLS certificates.  Defaults to ``True``.
    timeout : float
        Request timeout in seconds.  Defaults to ``30``.
    max_retries : int
        Number of automatic retries on transient failures.  Defaults to ``3``.
    config : dict, optional
        Raw config dict (typically from :class:`~gnat.config.SAKConfig`)
        for subclass use.

    Attributes
    ----------
    _auth_headers : dict
        Headers injected into every request after :meth:`authenticate` runs.
        Subclasses should populate this during authentication.
    """

    def __init__(
        self,
        host: str,
        verify_ssl: bool = True,
        timeout: float = 30.0,
        max_retries: int = 3,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.host = host.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.config = config or {}
        self._auth_headers: Dict[str, str] = {}
        self._authenticated = False

        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist={429, 500, 502, 503, 504},
            allowed_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
        )

        kwargs: Dict[str, Any] = {
            "retries": retry,
            "timeout": urllib3.Timeout(connect=timeout, read=timeout),
        }
        if not verify_ssl:
            kwargs["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._http = urllib3.PoolManager(**kwargs)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Perform platform authentication and populate :attr:`_auth_headers`.

        Must be implemented by every connector subclass.

        Raises
        ------
        NotImplementedError
            If the subclass does not override this method.
        """
        raise NotImplementedError("Connector subclasses must implement authenticate()")

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        Issue an HTTP GET request.

        Parameters
        ----------
        path : str
            API endpoint path relative to :attr:`host`.
        params : dict, optional
            Query string parameters.
        headers : dict, optional
            Additional request headers (merged with auth headers).

        Returns
        -------
        Any
            Parsed JSON response body.
        """
        return self._request("GET", path, params=params, extra_headers=headers)

    def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP POST request. Provide either *json* or *data*."""
        return self._request(
            "POST", path, body=json, form_data=data, extra_headers=headers
        )

    def put(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP PUT request."""
        return self._request("PUT", path, body=json, extra_headers=headers)

    def patch(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP PATCH request."""
        return self._request("PATCH", path, body=json, extra_headers=headers)

    def delete(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP DELETE request."""
        return self._request("DELETE", path, extra_headers=headers)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        Core request dispatcher.  Handles encoding, auth headers, and errors.
        """
        if not self._authenticated:
            self.authenticate()
            self._authenticated = True

        url = urljoin(self.host + "/", path.lstrip("/"))
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"

        headers: Dict[str, str] = {"Accept": "application/json"}
        headers.update(self._auth_headers)
        if extra_headers:
            headers.update(extra_headers)

        encoded_body: Optional[bytes] = None
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form_data is not None:
            encoded_body = urlencode(form_data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        logger.debug("%s %s", method, url)
        response = self._http.request(
            method,
            url,
            body=encoded_body,
            headers=headers,
        )

        if response.status >= 400:
            body_text = response.data.decode("utf-8", errors="replace")
            raise SAKClientError(
                f"HTTP {response.status} from {url}",
                status=response.status,
                body=body_text,
            )

        if not response.data:
            return None

        try:
            return json.loads(response.data.decode("utf-8"))
        except json.JSONDecodeError:
            return response.data.decode("utf-8", errors="replace")

    def __repr__(self) -> str:  # pragma: no cover
        cls = type(self).__name__
        return f"{cls}(host={self.host!r}, authenticated={self._authenticated})"
