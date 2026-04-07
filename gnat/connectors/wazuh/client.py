# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.wazuh.client

Core HTTP client for the Wazuh connector.

## Wazuh REST conventions

- Manager API: https://<host>:55000/<endpoint>
- All endpoints return JSON; no output_mode parameter needed
- POST bodies are application/json
- Pagination: `limit` (max 500) + `offset` parameters
- Success envelope:
  {
  "data": {
  "affected_items": […],
  "total_affected_items": N,
  "failed_items": [],
  "total_failed_items": 0
  },
  "message": "All items were returned",
  "error": 0
  }
- Error envelope:
  {
  "title":       "Permission Denied",
  "detail":      "…",
  "remediation": "…",
  "error":       4000
  }
- HTTP 200 with error != 0 indicates a partial failure (some items failed)
- HTTP 4xx with Wazuh error codes:
  4000 -- Permission denied
  4001 -- Authentication error
  4009 -- Token expired  -> triggers token renewal + retry
  6001 -- Agent not found
  1750 -- Rule not found

## Usage

cfg = load_wazuh_config(parser)
with WazuhClient(cfg) as client:
    agents = client.get("agents", params={"status": "active"})
    items = agents["data"]["affected_items"]

"""

import json
import time
import urllib.parse

import urllib3

from .auth import WazuhAuthManager
from .config import WazuhConfig
from .exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhNotFoundError,
    WazuhPermissionError,
    WazuhRateLimitError,
)

_RETRYABLE_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0
_RETRY_BACKOFF = 2.0

# Wazuh error codes

_WAZUH_ERR_TOKEN_EXPIRED = 4009
_WAZUH_ERR_PERMISSION = 4000
_WAZUH_ERR_AUTH = 4001
_WAZUH_NOT_FOUND_CODES = {1002, 6001, 6061, 1750, 1802}


class WazuhClient:
    """
    urllib3-based HTTP client for the Wazuh Manager API.

    Parameters
    ----------
    config : WazuhConfig
        Validated connector configuration.
    """

    def __init__(self, config: WazuhConfig) -> None:
        """Initialize WazuhClient."""
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = WazuhAuthManager(config, self._http)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "WazuhClient":
        """Enter the context manager."""
        return self

    def __exit__(self, *_) -> None:
        """Exit the context manager, handling any exceptions."""
        self.close()

    def close(self) -> None:
        """Release connection pool resources."""
        self._http.clear()

    # ── Public HTTP verbs ──────────────────────────────────────────────────

    def get(
        self,
        endpoint: str,
        params: dict | None = None,
        raw: bool = False,
    ) -> dict | bytes:
        """
        HTTP GET against a Wazuh Manager API endpoint.

        Parameters
        ----------
        endpoint : str
            Path relative to the base URL, e.g. ``"agents"``.
        params : dict | None
            Query parameters (limit, offset, filters, etc.).
        raw : bool
            If True, return raw response bytes instead of parsed JSON.

        Returns
        -------
        dict | bytes
            Parsed response dict, or raw bytes when ``raw=True``.
        """
        url = self.config.endpoint(endpoint)
        return self._request("GET", url, params=params, raw=raw)

    def post(
        self,
        endpoint: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        HTTP POST against a Wazuh Manager API endpoint.

        Parameters
        ----------
        endpoint : str
            Endpoint path.
        body : dict | None
            JSON request body.
        params : dict | None
            Query parameters.

        Returns
        -------
        dict
            Parsed response dict.
        """
        url = self.config.endpoint(endpoint)
        return self._request("POST", url, body=body, params=params)

    def put(
        self,
        endpoint: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """HTTP PUT against a Wazuh Manager API endpoint."""
        url = self.config.endpoint(endpoint)
        return self._request("PUT", url, body=body, params=params)

    def delete(
        self,
        endpoint: str,
        params: dict | None = None,
    ) -> dict:
        """HTTP DELETE against a Wazuh Manager API endpoint."""
        url = self.config.endpoint(endpoint)
        return self._request("DELETE", url, params=params)

    # ── Data extraction helpers ────────────────────────────────────────────

    @staticmethod
    def extract_items(response: dict) -> list[dict]:
        """
        Extract the ``affected_items`` list from a Wazuh API response.

        Parameters
        ----------
        response : dict
            Raw parsed API response.

        Returns
        -------
        list[dict]
            The affected items list, or empty list if not present.
        """
        return response.get("data", {}).get("affected_items", [])

    @staticmethod
    def extract_total(response: dict) -> int:
        """Extract ``total_affected_items`` from a Wazuh API response."""
        return response.get("data", {}).get("total_affected_items", 0)

    # ── Pagination helper ──────────────────────────────────────────────────

    def paginate(
        self,
        endpoint: str,
        params: dict | None = None,
        page_size: int = 500,
    ):
        """
        Generator that yields all items from a paginated Wazuh endpoint.

        Wazuh paginates via ``limit`` (max 500) + ``offset``.
        Iterates until ``total_affected_items`` is reached.

        Parameters
        ----------
        endpoint : str
            Wazuh endpoint path.
        params : dict | None
            Additional query parameters (filters, sort, select, etc.).
        page_size : int
            Records per page. Capped at WAZUH_MAX_LIMIT (500).

        Yields
        ------
        dict
            Individual item dicts from affected_items.
        """
        from .config import WAZUH_MAX_LIMIT

        limit = min(page_size, WAZUH_MAX_LIMIT)
        base_params = dict(params or {})
        base_params["limit"] = limit
        offset = 0
        total: int | None = None

        while True:
            base_params["offset"] = offset
            response = self.get(endpoint, params=base_params)
            items = self.extract_items(response)

            if total is None:
                total = self.extract_total(response)

            yield from items

            offset += len(items)
            if not items or offset >= total:
                break

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
        """Internal helper for build pool manager."""
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
        params: dict | None = None,
        body: dict | None = None,
        raw: bool = False,
    ) -> dict | bytes:
        """
        Execute an HTTP request with auth injection, token refresh, and
        retry logic.

        Wazuh-specific handling:
        - 401 + error code 4009 -> token expired -> re-authenticate + retry once
        - 401 + other           -> bad credentials -> raise WazuhAuthError
        - 403 + error code 4000 -> permission denied -> raise WazuhPermissionError
        - HTTP 200 + error != 0 -> partial failure -- still returned as dict so
                                   callers can inspect failed_items
        """
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        encoded_body: bytes | None = None
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")

        delay = _RETRY_BASE_DELAY
        token_refreshed = False
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            headers = self.auth.get_auth_headers()
            headers["Content-Type"] = "application/json"

            try:
                if encoded_body is not None:
                    response = self._http.request(
                        method,
                        url,
                        body=encoded_body,
                        headers=headers,
                    )
                else:
                    response = self._http.request(
                        method,
                        url,
                        headers=headers,
                    )
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise WazuhAPIError(
                    f"Connection error after {_MAX_RETRIES} retries: {exc}",
                    endpoint=url,
                ) from exc

            # ── Handle 401 (auth errors + token expiry) ────────────────
            if response.status == 401:
                err_code = self._extract_error_code(response.data)
                if err_code == _WAZUH_ERR_TOKEN_EXPIRED and not token_refreshed:
                    self.auth.invalidate_token()
                    token_refreshed = True
                    continue  # retry with fresh token
                raise WazuhAuthError(
                    "Wazuh authentication failed.",
                    status_code=401,
                    endpoint=url,
                )

            # ── Handle 403 (permission denied) ─────────────────────────
            if response.status == 403:
                err_code = self._extract_error_code(response.data)
                body_parsed = self._safe_parse_json(response.data)
                raise WazuhPermissionError(
                    "Wazuh permission denied.",
                    status_code=403,
                    error_code=err_code,
                    endpoint=url,
                    title=body_parsed.get("title", ""),
                    detail=body_parsed.get("detail", ""),
                    remediation=body_parsed.get("remediation", ""),
                )

            # ── Handle 404 ─────────────────────────────────────────────
            if response.status == 404:
                body_parsed = self._safe_parse_json(response.data)
                raise WazuhNotFoundError(
                    f"Resource not found: {url}",
                    status_code=404,
                    error_code=self._extract_error_code(response.data),
                    endpoint=url,
                    title=body_parsed.get("title", ""),
                    detail=body_parsed.get("detail", ""),
                )

            # ── Handle 429 rate limiting ───────────────────────────────
            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise WazuhRateLimitError(
                    "Wazuh rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            # ── Transient server errors ────────────────────────────────
            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            # ── Non-success, non-handled status ───────────────────────
            if response.status not in (200, 201):
                body_parsed = self._safe_parse_json(response.data)
                raise WazuhAPIError(
                    "Unexpected response from Wazuh.",
                    status_code=response.status,
                    error_code=body_parsed.get("error"),
                    endpoint=url,
                    title=body_parsed.get("title", ""),
                    detail=body_parsed.get("detail", ""),
                    remediation=body_parsed.get("remediation", ""),
                )

            # ── Success ────────────────────────────────────────────────
            if raw:
                return response.data

            return self._parse_json(response.data, url)

        if last_exc:
            raise WazuhAPIError(str(last_exc), endpoint=url) from last_exc
        raise WazuhAPIError("Request failed after retries.", endpoint=url)

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict:
        """Internal helper for parse json."""
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WazuhAPIError(
                f"Failed to parse JSON response from {url}: {exc}",
                endpoint=url,
            ) from exc

    @staticmethod
    def _safe_parse_json(data: bytes) -> dict:
        """Internal helper for safe parse json."""
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _extract_error_code(data: bytes) -> int | None:
        """Internal helper for extract error code."""
        try:
            body = json.loads(data.decode("utf-8"))
            return body.get("error") or body.get("data", {}).get("error")
        except Exception:
            return None
