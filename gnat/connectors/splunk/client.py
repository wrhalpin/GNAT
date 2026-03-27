"""
gnat.connectors.splunk.client

Core HTTP client for the Splunk connector.

Wraps urllib3.PoolManager with:

- Automatic auth header injection via SplunkAuthManager
- JSON request/response handling
- Splunk-specific error parsing and exception mapping
- Retry logic with exponential backoff for transient errors
- output_mode=json enforcement on all requests
- Context manager support for connection lifecycle

## Splunk REST conventions

- Management port: 8089 (splunkd)
- All endpoints return JSON when `?output_mode=json` is appended
- POST bodies are `application/x-www-form-urlencoded` unless sending
  raw file content (threat intel upload uses multipart/form-data)
- Pagination: `count` + `offset` parameters; no cursor tokens
- Error body shape:
  {"messages": [{"type": "ERROR", "text": "…"}]}

## Usage

cfg = load_splunk_config(parser)
client = SplunkClient(cfg)
with client:
    jobs = client.get("search/jobs", params={"count": 10})

"""

import json
import time
import urllib.parse
import urllib3

from .auth import SplunkAuthManager
from .config import SplunkConfig
from .exceptions import (
SplunkAPIError,
SplunkAuthError,
SplunkNotFoundError,
SplunkRateLimitError,
)

# ── Retry configuration ───────────────────────────────────────────────────────

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0   # seconds
_RETRY_BACKOFF = 2.0      # multiplier

class SplunkClient:
    """
    urllib3-based HTTP client for the Splunk REST API.

    Parameters
    ----------
    config : SplunkConfig
        Validated connector configuration.

    Attributes
    ----------
    config : SplunkConfig
        The active configuration.
    auth : SplunkAuthManager
        The authentication manager (accessible for token introspection).
    """

    def __init__(self, config: SplunkConfig) -> None:
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = SplunkAuthManager(config, self._http)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "SplunkClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        """Logout from Splunk (session key auth) and release connections."""
        try:
            self.auth.logout()
        finally:
            self._http.clear()

    # ── Public HTTP verbs ──────────────────────────────────────────────────

    def get(
        self,
        endpoint: str,
        params: dict | None = None,
        namespaced: bool = True,
        raw: bool = False,
    ) -> dict | bytes:
        """
        HTTP GET against a Splunk REST endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to the namespace root, e.g. ``"search/jobs"``.
        params : dict | None
            Query parameters. ``output_mode=json`` is always appended.
        namespaced : bool
            If True, uses /servicesNS/<owner>/<app>/<endpoint>.
            If False, uses /services/<endpoint> (global scope).
        raw : bool
            If True, return the raw response bytes instead of parsed JSON.

        Returns
        -------
        dict | bytes
            Parsed JSON dict, or raw bytes when ``raw=True``.
        """
        url = self._build_url(endpoint, namespaced)
        qp = self._inject_output_mode(params)
        return self._request("GET", url, fields=qp, raw=raw)

    def post(
        self,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        namespaced: bool = True,
        content_type: str = "application/x-www-form-urlencoded",
        raw_body: bytes | None = None,
    ) -> dict:
        """
        HTTP POST against a Splunk REST endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to the namespace root.
        data : dict | None
            Form data (encoded as x-www-form-urlencoded by default).
        params : dict | None
            Query parameters appended to the URL.
        namespaced : bool
            Namespace vs global scope toggle.
        content_type : str
            Override Content-Type header.
        raw_body : bytes | None
            Send a raw body (e.g. multipart for file upload).
            Mutually exclusive with ``data``.

        Returns
        -------
        dict
            Parsed JSON response.
        """
        url = self._build_url(endpoint, namespaced)
        qp = self._inject_output_mode(params)
        if qp:
            url = f"{url}?{urllib.parse.urlencode(qp)}"

        if raw_body is not None:
            body = raw_body
            headers = {"Content-Type": content_type}
        elif data:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            body = b""
            headers = {}

        return self._request("POST", url, body=body, extra_headers=headers)

    def delete(self, endpoint: str, namespaced: bool = True) -> dict:
        """HTTP DELETE against a Splunk REST endpoint."""
        url = self._build_url(endpoint, namespaced)
        url = f"{url}?output_mode=json"
        return self._request("DELETE", url)

    def put(
        self,
        endpoint: str,
        data: dict | None = None,
        namespaced: bool = True,
    ) -> dict:
        """HTTP PUT (used for KV Store document updates)."""
        url = self._build_url(endpoint, namespaced)
        url = f"{url}?output_mode=json"
        body = json.dumps(data or {}).encode("utf-8")
        return self._request(
            "PUT",
            url,
            body=body,
            extra_headers={"Content-Type": "application/json"},
        )

    # ── Pagination helper ──────────────────────────────────────────────────

    def paginate(
        self,
        endpoint: str,
        params: dict | None = None,
        namespaced: bool = True,
        page_size: int = 100,
        result_key: str = "entry",
    ):
        """
        Generator that yields all pages of a list endpoint.

        Splunk paginates via ``count`` + ``offset``. Iterates until
        the response contains fewer results than ``page_size``.

        Parameters
        ----------
        endpoint : str
            REST endpoint path.
        params : dict | None
            Additional query parameters.
        namespaced : bool
            Namespace vs global scope.
        page_size : int
            Results per page (Splunk ``count`` parameter).
        result_key : str
            Top-level JSON key that contains the list (usually 'entry').

        Yields
        ------
        dict
            Individual result entries.
        """
        offset = 0
        base_params = dict(params or {})
        base_params["count"] = page_size

        while True:
            base_params["offset"] = offset
            response = self.get(endpoint, params=base_params, namespaced=namespaced)
            entries = response.get(result_key, [])
            yield from entries

            if len(entries) < page_size:
                break
            offset += page_size

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
        """Create urllib3.PoolManager with TLS and retry configuration."""
        kwargs: dict = {
            "num_pools": 4,
            "maxsize": 10,
            "timeout": urllib3.Timeout(
                connect=10.0,
                read=float(self.config.timeout),
            ),
            "retries": urllib3.Retry(
                total=0,  # GNAT handles retries manually for full control
                raise_on_status=False,
            ),
        }

        if not self.config.verify_ssl:
            kwargs["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            kwargs["cert_reqs"] = "CERT_REQUIRED"

        return urllib3.PoolManager(**kwargs)

    def _build_url(self, endpoint: str, namespaced: bool) -> str:
        endpoint = endpoint.lstrip("/")
        if namespaced:
            return self.config.namespace_path(endpoint)
        return self.config.services_path(endpoint)

    @staticmethod
    def _inject_output_mode(params: dict | None) -> dict:
        result = dict(params or {})
        result.setdefault("output_mode", "json")
        return result

    def _request(
        self,
        method: str,
        url: str,
        fields: dict | None = None,
        body: bytes | None = None,
        extra_headers: dict | None = None,
        raw: bool = False,
    ) -> dict | bytes:
        """
        Execute an HTTP request with auth injection, retries, and error mapping.

        Parameters
        ----------
        method : str
            HTTP verb.
        url : str
            Fully qualified URL.
        fields : dict | None
            Query parameters for GET; form fields for POST when body is None.
        body : bytes | None
            Raw request body.
        extra_headers : dict | None
            Headers to merge with auth headers.
        raw : bool
            Return raw bytes instead of parsed JSON.

        Returns
        -------
        dict | bytes

        Raises
        ------
        SplunkAuthError, SplunkRateLimitError, SplunkNotFoundError,
        SplunkAPIError
        """
        headers = self.auth.get_auth_headers()
        if extra_headers:
            headers.update(extra_headers)

        delay = _RETRY_BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                if body is not None:
                    response = self._http.request(
                        method,
                        url,
                        body=body,
                        headers=headers,
                    )
                else:
                    response = self._http.request(
                        method,
                        url,
                        fields=fields,
                        headers=headers,
                    )
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SplunkAPIError(
                    f"Connection error after {_MAX_RETRIES} retries: {exc}",
                    endpoint=url,
                ) from exc

            # ── Auth retry on 401 ──────────────────────────────────────
            if response.status == 401:
                if attempt == 0:
                    # Token may have expired -- invalidate and retry once
                    self.auth.invalidate_session()
                    headers = self.auth.get_auth_headers()
                    if extra_headers:
                        headers.update(extra_headers)
                    continue
                raise SplunkAuthError(
                    "Splunk returned 401 after token refresh. "
                    "Check credentials or token expiry."
                )

            # ── Rate limit ─────────────────────────────────────────────
            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SplunkRateLimitError(
                    "Splunk rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            # ── Transient server errors ────────────────────────────────
            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            # ── Map remaining error codes ──────────────────────────────
            if response.status == 404:
                raise SplunkNotFoundError(
                    f"Resource not found: {url}",
                    status_code=404,
                    endpoint=url,
                )

            if response.status == 403:
                raise SplunkAuthError(
                    f"Permission denied: {url} (HTTP 403). "
                    "Check the token's capability set."
                )

            if response.status not in (200, 201):
                messages = self._extract_error_messages(response.data)
                raise SplunkAPIError(
                    f"Unexpected response from Splunk.",
                    status_code=response.status,
                    endpoint=url,
                    messages=messages,
                )

            # ── Success ────────────────────────────────────────────────
            if raw:
                return response.data

            return self._parse_json(response.data, url)

        # Should not reach here, but satisfy the type checker.
        if last_exc:
            raise SplunkAPIError(str(last_exc), endpoint=url) from last_exc
        raise SplunkAPIError("Request failed after retries.", endpoint=url)

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SplunkAPIError(
                f"Failed to parse JSON response from {url}: {exc}",
                endpoint=url,
            ) from exc

    @staticmethod
    def _extract_error_messages(data: bytes) -> list[str]:
        try:
            body = json.loads(data.decode("utf-8"))
            return [m.get("text", "") for m in body.get("messages", [])]
        except Exception:
            return []
