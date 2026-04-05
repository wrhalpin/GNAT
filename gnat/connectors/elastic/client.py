"""
gnat.connectors.elastic.client

Core HTTP client for the Elastic Security connector.

Manages two urllib3 request surfaces:

- Elasticsearch REST API  (self.es_request)
- Kibana API              (self.kibana_request)

Both share the same PoolManager and API key, but have different:

- Base URLs (port 9200 vs 5601)
- Required headers (kbn-xsrf for Kibana writes)
- Error response shapes

## Elasticsearch response conventions

- Success: raw JSON (no standard envelope)
- Pagination: `from` + `size` (max 10,000), or PIT scroll
- Errors: {"error": {"type": "…", "reason": "…"}, "status": N}
- Shard failures: {"_shards": {"failed": N, "failures": […]}}
- 200 with shard failures = partial success (data returned with warnings)

## Kibana Security API response conventions

- List endpoints: {"data": […], "total": N, "page": N, "perPage": N}
- Single resource: flat JSON object
- Errors: {"statusCode": N, "error": "…", "message": "…"}
- Bulk operations return per-item success/failure lists

## Usage

cfg = load_elastic_config(parser)
with ElasticClient(cfg) as client:
    # Elasticsearch
    result = client.es_get("_cluster/health")
    hits = client.es_search(".alerts-security.*", query={"match_all": {}})

    # Kibana
    rules = client.kibana_get("api/detection_engine/rules/_find")

"""

import json
import time
import urllib.parse

import urllib3

from .auth import ElasticAuthManager
from .config import ElasticConfig
from .exceptions import (
    ElasticAPIError,
    ElasticAuthError,
    ElasticConflictError,
    ElasticKibanaError,
    ElasticKibanaNotFoundError,
    ElasticKibanaValidationError,
    ElasticNotFoundError,
    ElasticRateLimitError,
)

_RETRYABLE_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0
_RETRY_BACKOFF = 2.0

# Elasticsearch hard limit for from+size without PIT

ES_MAX_RESULT_WINDOW = 10_000


class ElasticClient:
    """
    urllib3-based HTTP client for Elasticsearch + Kibana Security APIs.

    Parameters
    ----------
    config : ElasticConfig
        Validated connector configuration.
    """

    def __init__(self, config: ElasticConfig) -> None:
        self.config = config
        self._http = self._build_pool_manager()
        self.auth = ElasticAuthManager(config, self._http)

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "ElasticClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        """Release connection pool resources."""
        self._http.clear()

    # ══════════════════════════════════════════════════════════════════════
    # Elasticsearch surface
    # ══════════════════════════════════════════════════════════════════════

    def es_get(
        self,
        path: str,
        params: dict | None = None,
    ) -> dict:
        """
        HTTP GET against the Elasticsearch API.

        Parameters
        ----------
        path : str
            Endpoint path, e.g. ``"_cluster/health"`` or ``"my-index/_doc/1"``.
        params : dict | None
            Query parameters.

        Returns
        -------
        dict
            Parsed JSON response.
        """
        url = self.config.es_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._es_request("GET", url)

    def es_post(
        self,
        path: str,
        body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """HTTP POST against the Elasticsearch API."""
        url = self.config.es_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._es_request("POST", url, body=body)

    def es_put(
        self,
        path: str,
        body: dict | None = None,
    ) -> dict:
        """HTTP PUT against the Elasticsearch API."""
        url = self.config.es_url(path)
        return self._es_request("PUT", url, body=body)

    def es_delete(self, path: str, params: dict | None = None) -> dict:
        """HTTP DELETE against the Elasticsearch API."""
        url = self.config.es_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._es_request("DELETE", url)

    # ── Search helpers ─────────────────────────────────────────────────────

    def es_search(
        self,
        index: str,
        query: dict | None = None,
        size: int = 100,
        from_: int = 0,
        sort: list[dict] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict | None = None,
    ) -> dict:
        """
        Execute an Elasticsearch search query.

        Parameters
        ----------
        index : str
            Index name or pattern.
        query : dict | None
            Query DSL clause. Defaults to match_all.
        size : int
            Number of hits to return (capped at ES_MAX_RESULT_WINDOW).
        from_ : int
            Pagination offset.
        sort : list[dict] | None
            Sort criteria, e.g. ``[{"@timestamp": {"order": "desc"}}]``.
        source : list[str] | bool | None
            Source filtering: list of fields, True (all), False (none).
        aggs : dict | None
            Aggregation definitions.

        Returns
        -------
        dict
            Elasticsearch search response with hits.total, hits.hits, aggregations.
        """
        body: dict = {
            "size": min(size, ES_MAX_RESULT_WINDOW),
            "from": from_,
            "query": query or {"match_all": {}},
        }
        if sort:
            body["sort"] = sort
        if source is not None:
            body["_source"] = source
        if aggs:
            body["aggs"] = aggs

        return self.es_post(f"{index}/_search", body=body)

    def es_search_hits(
        self,
        index: str,
        query: dict | None = None,
        size: int = 100,
        sort: list[dict] | None = None,
        source: list[str] | bool | None = None,
    ) -> list[dict]:
        """
        Execute a search and return only the _source docs from hits.

        Parameters
        ----------
        index : str
            Index name or pattern.
        query : dict | None
            Query DSL.
        size : int
            Max results.
        sort : list[dict] | None
            Sort criteria.
        source : list[str] | bool | None
            Source filtering.

        Returns
        -------
        list[dict]
            List of ``_source`` dicts from matching documents.
        """
        response = self.es_search(index, query=query, size=size, sort=sort, source=source)
        return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]

    def es_count(self, index: str, query: dict | None = None) -> int:
        """
        Count documents matching a query.

        Parameters
        ----------
        index : str
            Index name or pattern.
        query : dict | None
            Query DSL. None = count all documents.

        Returns
        -------
        int
            Document count.
        """
        body = {"query": query or {"match_all": {}}}
        response = self.es_post(f"{index}/_count", body=body)
        return response.get("count", 0)

    def es_paginate(
        self,
        index: str,
        query: dict | None = None,
        page_size: int = 1000,
        sort: list[dict] | None = None,
        source: list[str] | bool | None = None,
    ):
        """
        Generator that paginates through search results using from/size.

        Limited to ES_MAX_RESULT_WINDOW (10,000) total results.
        For deeper pagination use Point-in-Time via es_search directly.

        Parameters
        ----------
        index : str
            Index name or pattern.
        query : dict | None
            Query DSL.
        page_size : int
            Results per page.
        sort : list[dict] | None
            Sort criteria (required for consistent pagination).
        source : list[str] | bool | None
            Source filtering.

        Yields
        ------
        dict
            Individual ``_source`` document dicts.
        """
        offset = 0
        total_yielded = 0
        if sort is None:
            sort = [{"@timestamp": {"order": "desc"}}]

        while True:
            remaining = min(ES_MAX_RESULT_WINDOW - total_yielded, page_size)
            if remaining <= 0:
                break

            response = self.es_search(
                index,
                query=query,
                size=remaining,
                from_=offset,
                sort=sort,
                source=source,
            )
            hits = response.get("hits", {}).get("hits", [])
            for hit in hits:
                yield hit.get("_source", {})
            total_yielded += len(hits)
            offset += len(hits)

            if not hits or len(hits) < page_size:
                break

    # ══════════════════════════════════════════════════════════════════════
    # Kibana surface
    # ══════════════════════════════════════════════════════════════════════

    def kibana_get(
        self,
        path: str,
        params: dict | None = None,
    ) -> dict:
        """
        HTTP GET against the Kibana API.

        Parameters
        ----------
        path : str
            Kibana API path, e.g. ``"api/detection_engine/rules/_find"``.
        params : dict | None
            Query parameters.

        Returns
        -------
        dict
            Parsed JSON response.
        """
        url = self.config.kibana_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._kibana_request("GET", url)

    def kibana_post(
        self,
        path: str,
        body: dict | list | None = None,
        params: dict | None = None,
    ) -> dict:
        """HTTP POST against the Kibana API."""
        url = self.config.kibana_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._kibana_request("POST", url, body=body)

    def kibana_put(
        self,
        path: str,
        body: dict | None = None,
    ) -> dict:
        """HTTP PUT against the Kibana API."""
        url = self.config.kibana_url(path)
        return self._kibana_request("PUT", url, body=body)

    def kibana_patch(
        self,
        path: str,
        body: dict | None = None,
    ) -> dict:
        """HTTP PATCH against the Kibana API."""
        url = self.config.kibana_url(path)
        return self._kibana_request("PATCH", url, body=body)

    def kibana_delete(
        self,
        path: str,
        params: dict | None = None,
    ) -> dict:
        """HTTP DELETE against the Kibana API."""
        url = self.config.kibana_url(path)
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._kibana_request("DELETE", url)

    def kibana_paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int = 100,
        data_key: str = "data",
    ):
        """
        Generator that paginates through Kibana list endpoints.

        Kibana uses ``page`` + ``per_page`` pagination and returns:
          {"data": [...], "total": N, "page": N, "perPage": N}

        Parameters
        ----------
        path : str
            Kibana endpoint path.
        params : dict | None
            Additional query parameters.
        page_size : int
            Items per page.
        data_key : str
            Key in response that contains the items list.

        Yields
        ------
        dict
            Individual item dicts.
        """
        base_params = dict(params or {})
        base_params["per_page"] = page_size
        page = 1
        total: int | None = None

        while True:
            base_params["page"] = page
            response = self.kibana_get(path, params=base_params)
            items = response.get(data_key, [])

            if total is None:
                total = response.get("total", 0)

            yield from items

            if not items or (page * page_size) >= total:
                break
            page += 1

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

    def _es_request(
        self,
        method: str,
        url: str,
        body: dict | None = None,
    ) -> dict:
        """
        Execute an Elasticsearch API request with retry and error mapping.

        Handles:
          401 -> ElasticAuthError (no refresh -- static API key)
          403 -> ElasticAuthError (insufficient privileges)
          404 -> ElasticNotFoundError
          409 -> ElasticConflictError
          429 -> ElasticRateLimitError (with backoff)
          4xx -> ElasticAPIError
          5xx -> retry then ElasticAPIError
        """
        headers = self.auth.get_es_headers()
        encoded = json.dumps(body).encode() if body is not None else None

        delay = _RETRY_BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = self._http.request(
                    method,
                    url,
                    body=encoded,
                    headers=headers,
                )
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise ElasticAPIError(f"Connection error: {exc}", endpoint=url) from exc

            if response.status in (401, 403):
                raise ElasticAuthError(
                    f"Elasticsearch authentication/authorization failed "
                    f"(HTTP {response.status}). Check API key privileges.",
                    status_code=response.status,
                )

            if response.status == 404:
                body_parsed = self._safe_parse(response.data)
                raise ElasticNotFoundError(
                    f"Resource not found: {url}",
                    status_code=404,
                    error_type=body_parsed.get("error", {}).get("type", ""),
                    reason=body_parsed.get("error", {}).get("reason", ""),
                    endpoint=url,
                )

            if response.status == 409:
                body_parsed = self._safe_parse(response.data)
                raise ElasticConflictError(
                    "Elasticsearch conflict (version mismatch or duplicate).",
                    status_code=409,
                    error_type=body_parsed.get("error", {}).get("type", ""),
                    reason=body_parsed.get("error", {}).get("reason", ""),
                    endpoint=url,
                )

            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise ElasticRateLimitError(
                    "Elasticsearch rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            if response.status not in (200, 201):
                body_parsed = self._safe_parse(response.data)
                err = body_parsed.get("error", {})
                raise ElasticAPIError(
                    "Unexpected Elasticsearch response.",
                    status_code=response.status,
                    error_type=err.get("type", ""),
                    reason=err.get("reason", ""),
                    endpoint=url,
                )

            return self._parse_json(response.data, url)

        if last_exc:
            raise ElasticAPIError(str(last_exc), endpoint=url) from last_exc
        raise ElasticAPIError("Request failed after retries.", endpoint=url)

    def _kibana_request(
        self,
        method: str,
        url: str,
        body: dict | list | None = None,
    ) -> dict:
        """
        Execute a Kibana API request with retry and Kibana-specific error mapping.

        Kibana returns 200 for most success, but:
          - Bulk operations may embed per-item errors in 200 responses
          - 404 means the saved object was not found
          - 400 means validation failure
        """
        headers = self.auth.get_kibana_headers(method)
        encoded = json.dumps(body).encode() if body is not None else None

        delay = _RETRY_BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = self._http.request(
                    method,
                    url,
                    body=encoded,
                    headers=headers,
                )
            except urllib3.exceptions.HTTPError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise ElasticKibanaError(f"Kibana connection error: {exc}", endpoint=url) from exc

            if response.status in (401, 403):
                raise ElasticAuthError(
                    f"Kibana authentication failed (HTTP {response.status}). "
                    "Ensure the API key has Kibana Security privileges."
                )

            if response.status == 404:
                body_parsed = self._safe_parse(response.data)
                raise ElasticKibanaNotFoundError(
                    f"Kibana resource not found: {url}",
                    status_code=404,
                    kibana_message=body_parsed.get("message", ""),
                    endpoint=url,
                )

            if response.status == 400:
                body_parsed = self._safe_parse(response.data)
                raise ElasticKibanaValidationError(
                    "Kibana validation error.",
                    status_code=400,
                    kibana_message=body_parsed.get("message", ""),
                    endpoint=url,
                )

            if response.status == 429:
                if attempt < _MAX_RETRIES:
                    time.sleep(delay)
                    delay *= _RETRY_BACKOFF
                    continue
                raise ElasticRateLimitError(
                    "Kibana rate limit exceeded.",
                    status_code=429,
                    endpoint=url,
                )

            if response.status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                time.sleep(delay)
                delay *= _RETRY_BACKOFF
                continue

            if response.status not in (200, 201):
                body_parsed = self._safe_parse(response.data)
                raise ElasticKibanaError(
                    "Unexpected Kibana response.",
                    status_code=response.status,
                    kibana_message=body_parsed.get("message", ""),
                    endpoint=url,
                )

            return self._parse_json(response.data, url)

        if last_exc:
            raise ElasticKibanaError(str(last_exc), endpoint=url) from last_exc
        raise ElasticKibanaError("Kibana request failed after retries.", endpoint=url)

    @staticmethod
    def _parse_json(data: bytes, url: str) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ElasticAPIError(
                f"Failed to parse JSON response from {url}: {exc}",
                endpoint=url,
            ) from exc

    @staticmethod
    def _safe_parse(data: bytes) -> dict:
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}
