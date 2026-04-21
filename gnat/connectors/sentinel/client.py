# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sentinel.client
=====================================
Core HTTP client for the Microsoft Sentinel connector.

Azure REST API conventions
---------------------------
- Auth: Bearer token (OAuth2 client credentials)
- Content-Type: application/json
- All Sentinel resources scoped under workspace path
- api-version appended as query param on every call

Pagination — nextLink pattern
-------------------------------
Azure REST APIs paginate via a ``nextLink`` field in the response body:
  {
    "value": [...items...],
    "nextLink": "https://management.azure.com/...&$skipToken=..."
  }

When nextLink is present, fetch it directly to get the next page.
When absent, iteration is complete. The paginate() method handles this.

Error response shape
---------------------
  {
    "error": {
      "code": "AuthorizationFailed",
      "message": "The client '...' does not have authorization..."
    }
  }
"""

import json
import time
import urllib.parse

import urllib3

from .auth import SentinelAuthManager
from .config import SentinelConfig
from .exceptions import (
    SentinelAPIError,
    SentinelAuthError,
    SentinelConflictError,
    SentinelNotFoundError,
    SentinelRateLimitError,
)

_RETRYABLE_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0
_RETRY_BACKOFF = 2.0


class SentinelClient:
    """urllib3-based HTTP client for the Microsoft Sentinel REST API."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api"
    COST_UNIT: int = 1

    def __init__(self, config: SentinelConfig) -> None:
        """Initialize SentinelClient."""
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = SentinelAuthManager(config, self._http)

    def __enter__(self) -> "SentinelClient":
        """Enter the context manager."""
        return self

    def __exit__(self, *_) -> None:
        """Exit the context manager, handling any exceptions."""
        self.close()

    def close(self) -> None:
        """Release resources and close any open connections."""
        self._http.clear()

    # ── HTTP verbs ────────────────────────────────────────────────────────

    def get(self, resource: str, params: dict | None = None) -> dict:
        """Get."""
        url = self.config.endpoint(resource)
        if params:
            # Merge extra params with existing api-version
            url += "&" + urllib.parse.urlencode(params)
        return self._request("GET", url)

    def post(self, resource: str, body: dict | None = None) -> dict:
        """Post."""
        return self._request("POST", self.config.endpoint(resource), body=body)

    def put(self, resource: str, body: dict | None = None) -> dict:
        """Put."""
        return self._request("PUT", self.config.endpoint(resource), body=body)

    def patch(self, resource: str, body: dict | None = None) -> dict:
        """Apply a partial update to the object."""
        return self._request("PATCH", self.config.endpoint(resource), body=body)

    def delete(self, resource: str) -> dict:
        """Delete."""
        return self._request("DELETE", self.config.endpoint(resource))

    # ── nextLink pagination ────────────────────────────────────────────────

    def paginate(
        self,
        resource: str,
        params: dict | None = None,
        page_size: int | None = None,
    ):
        """
        Generator yielding all items from a paginated Azure list endpoint.

        Azure paginates via a ``nextLink`` field in the response body.
        Each response contains ``{"value": [...], "nextLink": "..."}``

        Parameters
        ----------
        resource : str
            Sentinel resource path.
        params : dict | None
            Additional query parameters.
        page_size : int | None
            Adds ``$top`` param for page size.

        Yields
        ------
        dict
            Individual item dicts from the ``value`` array.
        """
        url = self.config.endpoint(resource)
        extra: dict = {}
        if page_size:
            extra["$top"] = page_size
        elif self.config.max_results:
            extra["$top"] = self.config.max_results
        if params:
            extra.update(params)
        if extra:
            url += "&" + urllib.parse.urlencode(extra)

        while url:
            response = self._request("GET", url)
            items = response.get("value", [])
            yield from items
            url = response.get("nextLink")  # None stops iteration

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
        """Internal helper for build pool manager."""
        kwargs: dict = {
            "num_pools": 4,
            "maxsize": 10,
            "timeout": urllib3.Timeout(connect=10.0, read=float(self.config.timeout)),
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
        retry_on_401: bool = True,
    ) -> dict:
        """Internal helper for request."""
        headers = self.auth.get_headers()
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        delay = _RETRY_BASE_DELAY

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = self._http.request(
                    method,
                    url,
                    body=encoded,
                    headers=headers,
                )
            except urllib3.exceptions.HTTPError as exc:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SentinelAPIError(f"Connection error: {exc}", endpoint=url) from exc

            if response.status == 401:
                if retry_on_401 and attempt == 0:
                    self.auth.invalidate_token()
                    headers = self.auth.get_headers()
                    continue
                err = self._safe_parse(response.data)
                raise SentinelAuthError(
                    "Sentinel authentication failed (HTTP 401).",
                    azure_error_code=err.get("error", {}).get("code", ""),
                )

            if response.status == 403:
                err = self._safe_parse(response.data)
                raise SentinelAuthError(
                    "Service principal lacks required RBAC role (HTTP 403). "
                    f"{err.get('error', {}).get('message', '')}",
                    azure_error_code=err.get("error", {}).get("code", ""),
                )

            if response.status == 404:
                err = self._safe_parse(response.data)
                raise SentinelNotFoundError(
                    f"Resource not found: {url}",
                    status_code=404,
                    azure_error_code=err.get("error", {}).get("code", ""),
                    azure_message=err.get("error", {}).get("message", ""),
                    endpoint=url,
                )

            if response.status == 409:
                err = self._safe_parse(response.data)
                raise SentinelConflictError(
                    "Resource conflict.",
                    status_code=409,
                    azure_error_code=err.get("error", {}).get("code", ""),
                    endpoint=url,
                )

            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise SentinelRateLimitError("Sentinel rate limit exceeded.", status_code=429)

            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            if response.status not in (200, 201, 202, 204):
                err = self._safe_parse(response.data)
                raise SentinelAPIError(
                    "Unexpected Sentinel response.",
                    status_code=response.status,
                    azure_error_code=err.get("error", {}).get("code", ""),
                    azure_message=err.get("error", {}).get("message", ""),
                    endpoint=url,
                )

            # 204 No Content
            if response.status == 204 or not response.data:
                return {}

            return self._parse_json(response.data, url)

        raise SentinelAPIError("Request failed after retries.", endpoint=url)

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict:
        """Internal helper for parse json."""
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SentinelAPIError(f"Failed to parse JSON from {url}: {exc}", endpoint=url) from exc

    @staticmethod
    def _safe_parse(data: bytes) -> dict:
        """Internal helper for safe parse."""
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}
