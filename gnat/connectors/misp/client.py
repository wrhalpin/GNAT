"""
gnat.connectors.misp.client
=================================
Core HTTP client for the MISP connector.

MISP REST API conventions
---------------------------
- Base URL: https://<host>/<endpoint>.json
- Auth:     Authorization: <api_key>
- Accept:   application/json
- Bodies:   application/json

Response envelope patterns
---------------------------
MISP is inconsistent across endpoints:
  List events:    {"response": [{"Event": {...}}, ...]}
  Get event:      {"Event": {...}}
  Search:         [{"Event": {...}}, ...]  OR  {"response": [...]}
  Add attribute:  {"Attribute": {...}, "errors": false}
  Error (200!):   {"saved": false, "errors": {"field": ["msg"]}}
  Error (4xx):    {"message": "...", "name": "...", "url": "..."}

The client normalises these inconsistencies. For list endpoints it
always returns a plain list; for single-object endpoints a dict.

Pagination
----------
MISP paginates via ``page`` + ``limit`` query parameters on
restSearch and list endpoints. No cursor tokens.

Usage
-----
    cfg = load_misp_config(parser)
    with MISPClient(cfg) as client:
        events = client.get_json("events/index")
        result = client.post_json("events/restSearch", body={...})
"""

import json
import time
import urllib.parse

import urllib3

from .auth import MISPAuthManager
from .config import MISPConfig
from .exceptions import (
    MISPAPIError,
    MISPAuthError,
    MISPNotFoundError,
    MISPRateLimitError,
    MISPValidationError,
)

_RETRYABLE_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0
_RETRY_BACKOFF = 2.0


class MISPClient:
    """urllib3-based HTTP client for the MISP REST API."""

    def __init__(self, config: MISPConfig) -> None:
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = MISPAuthManager(config, self._http)

    def __enter__(self) -> "MISPClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        self._http.clear()

    # ── HTTP verbs ─────────────────────────────────────────────────────────

    def get_json(
        self,
        endpoint: str,
        params: dict | None = None,
    ) -> dict | list:
        """GET endpoint.json and return parsed response."""
        path = endpoint.rstrip(".json") + ".json"
        url = self.config.endpoint(path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._request("GET", url)

    def post_json(
        self,
        endpoint: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict | list:
        """POST to endpoint.json with JSON body."""
        path = endpoint.rstrip(".json") + ".json"
        url = self.config.endpoint(path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._request("POST", url, body=body)

    def put_json(self, endpoint: str, body: dict | None = None) -> dict | list:
        """PUT to endpoint.json."""
        path = endpoint.rstrip(".json") + ".json"
        return self._request("PUT", self.config.endpoint(path), body=body)

    def delete_json(self, endpoint: str) -> dict | list:
        """DELETE endpoint.json."""
        path = endpoint.rstrip(".json") + ".json"
        return self._request("DELETE", self.config.endpoint(path))

    # ── Pagination helper ──────────────────────────────────────────────────

    def paginate(
        self,
        endpoint: str,
        body: dict | None = None,
        page_size: int | None = None,
        response_key: str | None = None,
    ):
        """
        Generator that paginates through a MISP restSearch endpoint.

        MISP paginates via page + limit in the request body (for POST
        restSearch) or query params (for GET list endpoints).

        Parameters
        ----------
        endpoint : str
            MISP endpoint path.
        body : dict | None
            Base restSearch body (page/limit merged in).
        page_size : int | None
            Items per page. Defaults to config.max_results.
        response_key : str | None
            If set, extract this key from each response item
            (e.g. 'Event' for event list responses).

        Yields
        ------
        dict
            Individual item dicts.
        """
        limit = page_size or self.config.max_results
        page = 1
        base_body = dict(body or {})

        while True:
            request_body = {**base_body, "page": page, "limit": limit}
            response = self.post_json(endpoint, body=request_body)

            # Normalise response to list
            if isinstance(response, dict):
                items = response.get("response", []) or response.get("value", [])
            elif isinstance(response, list):
                items = response
            else:
                items = []

            if not items:
                break

            for item in items:
                yield item.get(response_key, item) if response_key else item

            if len(items) < limit:
                break
            page += 1

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_pool_manager(self) -> urllib3.PoolManager:
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
    ) -> dict | list:
        headers = self.auth.get_headers()
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        delay = _RETRY_BASE_DELAY

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = self._http.request(method, url, body=encoded, headers=headers)
            except urllib3.exceptions.HTTPError as exc:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise MISPAPIError(f"Connection error: {exc}", endpoint=url) from exc

            if response.status == 401:
                raise MISPAuthError(
                    "MISP API key rejected (HTTP 401). Check api_key in [misp] config."
                )
            if response.status == 403:
                raise MISPAuthError("MISP API key lacks required permissions (HTTP 403).")
            if response.status == 404:
                parsed = self._safe_parse(response.data)
                raise MISPNotFoundError(
                    f"MISP resource not found: {url}",
                    status_code=404,
                    misp_message=parsed.get("message", ""),
                    endpoint=url,
                )
            if response.status == 400:
                parsed = self._safe_parse(response.data)
                raise MISPValidationError(
                    "MISP validation error.",
                    status_code=400,
                    misp_message=parsed.get("message", str(parsed.get("errors", ""))),
                    endpoint=url,
                )
            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise MISPRateLimitError("MISP rate limit.", status_code=429)
            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue
            if response.status not in (200, 201):
                parsed = self._safe_parse(response.data)
                raise MISPAPIError(
                    "Unexpected MISP response.",
                    status_code=response.status,
                    misp_message=parsed.get("message", ""),
                    endpoint=url,
                )

            result = self._parse_json(response.data, url)

            # MISP 200 with embedded errors
            if isinstance(result, dict) and result.get("errors"):
                raise MISPValidationError(
                    "MISP returned validation errors.",
                    status_code=200,
                    misp_message=str(result.get("errors", "")),
                    endpoint=url,
                )
            return result

        raise MISPAPIError("Request failed after retries.", endpoint=url)

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict | list:
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MISPAPIError(f"Failed to parse JSON from {url}: {exc}", endpoint=url) from exc

    @staticmethod
    def _safe_parse(data: bytes) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}
