"""
gnat.connectors.qradar.client
===================================
Core HTTP client for the QRadar connector.

QRadar REST API conventions
-----------------------------
- Base URL:    https://<host>/api/<endpoint>
- Auth header: ``SEC: <token>``
- Version:     ``Version: 20.0`` (on every request)
- Accept:      ``application/json``

Pagination — Range header protocol
------------------------------------
QRadar uses HTTP Range headers for pagination, not query parameters.
This is the most distinctive feature of the QRadar API.

  Request:   Range: items=0-49
  Response:  Content-Range: items 0-49/1234
             (body contains items 0–49 of 1234 total)

  Next page: Range: items=50-99

The paginate() method handles this automatically, iterating until
the response Content-Range indicates no more items remain.

Error response shape
---------------------
  {
    "http_response": {"code": 403, "message": "Forbidden"},
    "code": 1002,
    "description": "You are not authorized...",
    "details": {},
    "message": "403 Forbidden"
  }

  Notable codes:
    1002 — not authorized (capability missing)
    1003 — resource not found
    38001 — AQL syntax error

POST/PUT bodies
---------------
  Content-Type: application/json
  Body: JSON-encoded dict

PATCH bodies (for partial updates)
------------------------------------
  Some QRadar endpoints (e.g. offense status update) use POST with
  query params rather than PATCH. Others use POST with a JSON body.
  The client exposes both patterns.

Usage
-----
    cfg = load_qradar_config(parser)
    with QRadarClient(cfg) as client:
        offenses = client.get("siem/offenses", params={"filter": "status=OPEN"})
        for page in client.paginate("siem/offenses"):
            process(page)
"""

import json
import time
import urllib.parse

import urllib3

from .auth import QRadarAuthManager
from .config import QRadarConfig
from .exceptions import (
    QRadarAPIError,
    QRadarAuthError,
    QRadarConflictError,
    QRadarNotFoundError,
    QRadarRateLimitError,
)

_RETRYABLE_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0
_RETRY_BACKOFF = 2.0

# QRadar error codes
_CODE_NOT_FOUND = 1003
_CODE_NOT_AUTH = 1002


class QRadarClient:
    """
    urllib3-based HTTP client for the QRadar REST API.

    Parameters
    ----------
    config : QRadarConfig
        Validated connector configuration.
    """

    def __init__(self, config: QRadarConfig) -> None:
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = QRadarAuthManager(config, self._http)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "QRadarClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        """Release connection pool resources."""
        self._http.clear()

    # ── Public HTTP verbs ──────────────────────────────────────────────────

    def get(
        self,
        endpoint: str,
        params: dict | None = None,
        range_header: str | None = None,
        raw: bool = False,
    ) -> dict | list | bytes:
        """
        HTTP GET against a QRadar API endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to /api/, e.g. ``"siem/offenses"``.
        params : dict | None
            Query parameters (filter, sort, fields, etc.).
        range_header : str | None
            Value for Range header, e.g. ``"items=0-49"``.
        raw : bool
            Return raw bytes instead of parsed JSON.

        Returns
        -------
        dict | list | bytes
        """
        url = self.config.endpoint(endpoint)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        extra = {"Range": range_header} if range_header else {}
        return self._request("GET", url, extra_headers=extra, raw=raw)

    def post(
        self,
        endpoint: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict | list:
        """HTTP POST against a QRadar API endpoint."""
        url = self.config.endpoint(endpoint)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._request("POST", url, body=body)

    def put(
        self,
        endpoint: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict | list:
        """HTTP PUT against a QRadar API endpoint."""
        url = self.config.endpoint(endpoint)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._request("PUT", url, body=body)

    def delete(
        self,
        endpoint: str,
        params: dict | None = None,
    ) -> dict | list:
        """HTTP DELETE against a QRadar API endpoint."""
        url = self.config.endpoint(endpoint)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._request("DELETE", url)

    # ── Range-based pagination ─────────────────────────────────────────────

    def paginate(
        self,
        endpoint: str,
        params: dict | None = None,
        page_size: int | None = None,
    ):
        """
        Generator that paginates through a QRadar list endpoint using
        Range headers.

        QRadar Range protocol:
          Request header:  Range: items=<start>-<end>
          Response header: Content-Range: items <start>-<end>/<total>

        Iteration stops when the start of the next page exceeds total.

        Parameters
        ----------
        endpoint : str
            QRadar API endpoint path.
        params : dict | None
            Query parameters (filter, sort, fields, etc.)
        page_size : int | None
            Items per page. Defaults to config.max_results.

        Yields
        ------
        dict
            Individual item dicts from each page.
        """
        size = page_size or self.config.max_results
        start = 0
        total: int | None = None

        while True:
            end = start + size - 1
            range_val = f"items={start}-{end}"

            url = self.config.endpoint(endpoint)
            if params:
                url = f"{url}?{urllib.parse.urlencode(params)}"

            headers = {**self.config.base_headers, "Range": range_val}
            response_raw = self._raw_request("GET", url, headers=headers)

            # Parse Content-Range to get total
            content_range = response_raw.headers.get("Content-Range", "")
            if content_range and total is None:
                total = self._parse_content_range_total(content_range)

            items = self._parse_json_response(response_raw, url)
            if not isinstance(items, list):
                items = [items] if items else []

            yield from items

            start += len(items)
            if not items:
                break
            if total is not None and start >= total:
                break

    def get_total_count(
        self,
        endpoint: str,
        params: dict | None = None,
    ) -> int:
        """
        Get the total number of items available at an endpoint without
        fetching all items.

        Sends a Range: items=0-0 request and reads Content-Range total.

        Parameters
        ----------
        endpoint : str
            QRadar API endpoint.
        params : dict | None
            Query parameters.

        Returns
        -------
        int
            Total item count.
        """
        url = self.config.endpoint(endpoint)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        headers = {**self.config.base_headers, "Range": "items=0-0"}
        response = self._raw_request("GET", url, headers=headers)
        content_range = response.headers.get("Content-Range", "")
        return self._parse_content_range_total(content_range)

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
        kwargs: dict = {
            "num_pools": 4,
            "maxsize": 10,
            "timeout": urllib3.Timeout(
                connect=10.0,
                read=float(self.config.timeout),
            ),
            "retries": urllib3.Retry(total=0, raise_on_status=False),
        }
        if not self.config.verify_ssl:
            kwargs["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            kwargs["cert_reqs"] = "CERT_REQUIRED"
        return urllib3.PoolManager(**kwargs)

    def _request(
        self,
        method: str,
        url: str,
        body: dict | None = None,
        extra_headers: dict | None = None,
        raw: bool = False,
    ) -> dict | list | bytes:
        """Execute a request and return parsed JSON or raw bytes."""
        response = self._raw_request(
            method, url, body=body, extra_headers=extra_headers
        )
        if raw:
            return response.data
        return self._parse_json_response(response, url)

    def _raw_request(
        self,
        method: str,
        url: str,
        body: dict | None = None,
        extra_headers: dict | None = None,
        headers: dict | None = None,
    ) -> urllib3.HTTPResponse:
        """
        Execute a raw HTTP request with retry logic.

        Returns the urllib3 response object for caller inspection
        (e.g. to read response headers like Content-Range).
        """
        if headers is None:
            headers = dict(
                self.config.json_headers if body is not None
                else self.config.base_headers
            )
        if extra_headers:
            headers.update(extra_headers)

        encoded: bytes | None = (
            json.dumps(body).encode("utf-8") if body is not None else None
        )

        delay = _RETRY_BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                if encoded is not None:
                    response = self._http.request(
                        method, url, body=encoded, headers=headers
                    )
                else:
                    response = self._http.request(method, url, headers=headers)
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise QRadarAPIError(
                    f"Connection error after {_MAX_RETRIES} retries: {exc}",
                    endpoint=url,
                ) from exc

            if response.status == 401:
                raise QRadarAuthError(
                    "QRadar rejected the SEC token (HTTP 401). "
                    "Check token in [qradar] config."
                )

            if response.status == 403:
                body_parsed = self._safe_parse(response.data)
                raise QRadarAuthError(
                    "QRadar SEC token lacks required capability (HTTP 403). "
                    f"{body_parsed.get('description', '')}",
                )

            if response.status == 404:
                body_parsed = self._safe_parse(response.data)
                raise QRadarNotFoundError(
                    f"QRadar resource not found: {url}",
                    status_code=404,
                    qradar_code=body_parsed.get("code"),
                    description=body_parsed.get("description", ""),
                    endpoint=url,
                )

            if response.status == 409:
                body_parsed = self._safe_parse(response.data)
                raise QRadarConflictError(
                    "QRadar conflict (duplicate resource).",
                    status_code=409,
                    qradar_code=body_parsed.get("code"),
                    description=body_parsed.get("description", ""),
                    endpoint=url,
                )

            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise QRadarRateLimitError(
                    "QRadar rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            if response.status not in (200, 201, 202):
                body_parsed = self._safe_parse(response.data)
                raise QRadarAPIError(
                    "Unexpected QRadar response.",
                    status_code=response.status,
                    qradar_code=body_parsed.get("code"),
                    description=body_parsed.get("description", ""),
                    endpoint=url,
                )

            return response

        if last_exc:
            raise QRadarAPIError(str(last_exc), endpoint=url) from last_exc
        raise QRadarAPIError("Request failed after retries.", endpoint=url)

    def _parse_json_response(
        self, response: urllib3.HTTPResponse, url: str
    ) -> dict | list:
        try:
            return json.loads(response.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise QRadarAPIError(
                f"Failed to parse JSON response from {url}: {exc}",
                endpoint=url,
            ) from exc

    @staticmethod
    def _safe_parse(data: bytes) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _parse_content_range_total(content_range: str) -> int:
        """
        Extract the total item count from a Content-Range header.

        Format: ``items 0-49/1234``  →  1234
        """
        try:
            return int(content_range.split("/")[-1].strip())
        except (ValueError, IndexError):
            return 0
