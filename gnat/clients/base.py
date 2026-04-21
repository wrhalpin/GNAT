# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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
* Structured error handling via :class:`GNATClientError`

Example (connector authors)::

    from gnat.clients.base import BaseClient

    class ThreatQClient(BaseClient):
        def authenticate(self):
            resp = self.post("/api/token", json={"grant_type": "client_credentials"})
            self._auth_headers["Authorization"] = f"Bearer {resp['access_token']}"
"""

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlencode, urljoin

import urllib3
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class ConnectorHealthResult:
    """
    Detailed health result returned by :meth:`BaseClient.health_check_detailed`.

    Parameters
    ----------
    ok : bool
        ``True`` if the health check passed.
    latency_ms : float
        Round-trip latency in milliseconds.
    error : str | None
        Error message when ``ok=False``.
    checked_at : datetime
        UTC timestamp of the check.
    trust_level : str
        Connector ``TRUST_LEVEL`` value.
    """

    ok: bool = False
    latency_ms: float = 0.0
    error: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trust_level: str = "semi_trusted"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "ok": self.ok,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
            "checked_at": self.checked_at.isoformat(),
            "trust_level": self.trust_level,
        }


class GNATClientError(Exception):
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
        """Initialize GNATClientError."""
        super().__init__(message)
        self.status = status
        self.body = body


class BudgetExceeded(GNATClientError):
    """
    Raised when an :class:`~gnat.core.context.ExecutionContext` query budget
    is exhausted before the requested operation can complete.

    Attributes
    ----------
    connector : str
        Name of the connector that triggered the budget check.
    cost : int
        Cost units the connector attempted to consume.
    remaining : int
        Budget units remaining when the check failed (always 0 or negative).
    """

    def __init__(self, connector: str, cost: int, remaining: int) -> None:
        """Initialize BudgetExceeded."""
        super().__init__(
            f"Query budget exhausted: {connector!r} requires {cost} units "
            f"but only {remaining} remaining.",
            status=0,
            body="",
        )
        self.connector = connector
        self.cost = cost
        self.remaining = remaining


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
        Raw config dict (typically from :class:`~gnat.config.GNATConfig`)
        for subclass use.

    Attributes
    ----------
    _auth_headers : dict
        Headers injected into every request after :meth:`authenticate` runs.
        Subclasses should populate this during authentication.

    Class Variables
    ---------------
    TRUST_LEVEL : str
        Trust classification for this connector.  Set explicitly on each
        subclass.  Valid values: ``"trusted_internal"``, ``"semi_trusted"``,
        ``"untrusted_external"``.  Defaults to ``"semi_trusted"``.
    API_VERSION : str
        API version string (e.g. ``"v2"``).  Empty string means unversioned.
    API_PREFIX : str
        URL path prefix used by this connector's API version (e.g. ``"/v3"``).
    COST_UNIT : int
        Relative cost weight for budget accounting.  Single-object lookups
        use 1; bulk pulls use 10; search operations use 5.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = ""
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    def __init__(
        self,
        host: str,
        verify_ssl: bool = True,
        timeout: float = 30.0,
        max_retries: int = 3,
        config: Optional[dict[str, Any]] = None,
        **_ignored: Any,
    ):
        """Initialize BaseClient."""
        self.host = host.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = float(timeout)
        self.config = config or {}
        self._auth_headers: dict[str, str] = {}
        self._authenticated = False
        # Optional ExecutionContext for budget tracking (set by callers)
        self._context: Any = None

        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist={429, 500, 502, 503, 504},
            allowed_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
        )

        kwargs: dict[str, Any] = {
            "retries": retry,
            "timeout": urllib3.Timeout(connect=self.timeout, read=self.timeout),
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

    def health_check_detailed(self) -> "ConnectorHealthResult":
        """
        Return a detailed health result including latency timing.

        Default implementation delegates to :meth:`health_check` (which
        connectors override) and wraps the result in a
        :class:`ConnectorHealthResult`.

        Connector subclasses may override this method to return richer
        diagnostic information.

        Returns
        -------
        ConnectorHealthResult
        """
        import time
        from datetime import datetime, timezone

        start_ns = time.perf_counter_ns()
        error: str | None = None
        ok = False
        try:
            result = self.health_check()  # type: ignore[attr-defined]
            ok = bool(result) if result is not None else True
        except Exception as exc:
            error = str(exc)
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        return ConnectorHealthResult(
            ok=ok,
            latency_ms=elapsed_ms,
            error=error,
            checked_at=datetime.now(timezone.utc),
            trust_level=getattr(self, "TRUST_LEVEL", "semi_trusted"),
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _basic_auth(username: str, password: str) -> str:
        """Return a Basic Auth header value for *username* and *password*."""
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return f"Basic {token}"

    def get(
        self,
        path: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
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
        json: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        files: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Issue an HTTP POST request. Provide either *json*, *data*, or *files*."""
        return self._request(
            "POST",
            path,
            body=json,
            form_data=data,
            params=params,
            extra_headers=headers,
            files=files,
        )

    def put(
        self,
        path: str,
        json: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP PUT request."""
        return self._request("PUT", path, body=json, params=params, extra_headers=headers)

    def patch(
        self,
        path: str,
        json: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP PATCH request."""
        return self._request("PATCH", path, body=json, params=params, extra_headers=headers)

    def delete(
        self,
        path: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Issue an HTTP DELETE request."""
        return self._request("DELETE", path, params=params, extra_headers=headers)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        body: Optional[dict[str, Any]] = None,
        form_data: Optional[dict[str, Any]] = None,
        extra_headers: Optional[dict[str, str]] = None,
        files: Optional[dict[str, Any]] = None,
    ) -> Any:
        """
        Core request dispatcher.  Handles encoding, auth headers, and errors.
        """
        if not self._authenticated:
            self.authenticate()
            self._authenticated = True

        # Deduct from query budget if one is attached via ExecutionContext
        if self._context is not None:
            budget = getattr(self._context, "budget", None)
            if budget is not None:
                budget.consume(self.COST_UNIT, type(self).__name__)

        url = urljoin(self.host + "/", path.lstrip("/"))
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"

        headers: dict[str, str] = {"Accept": "application/json"}
        headers.update(self._auth_headers)
        if extra_headers:
            headers.update(extra_headers)

        encoded_body: Optional[bytes] = None
        if files is not None:
            # Multipart form upload via urllib3's encode_multipart_formdata
            fields: dict[str, Any] = {}
            if form_data:
                fields.update(form_data)
            for field_name, file_tuple in files.items():
                if isinstance(file_tuple, tuple) and len(file_tuple) == 3:
                    fname, fdata, ftype = file_tuple
                    fields[field_name] = (fname, fdata, ftype)
                else:
                    fields[field_name] = file_tuple
            encoded_body, content_type = urllib3.encode_multipart_formdata(fields)
            headers["Content-Type"] = content_type
        elif body is not None:
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
            raise GNATClientError(
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
        """Return unambiguous string representation."""
        cls = type(self).__name__
        return f"{cls}(host={self.host!r}, authenticated={self._authenticated})"
