"""
gnat.connectors.wazuh.indexer

Wazuh Indexer (OpenSearch) API commands.

The Wazuh Indexer is an OpenSearch cluster that stores:

- wazuh-alerts-*       -- all security alerts
- wazuh-archives-*     -- raw log archives (if enabled)
- wazuh-statistics-*   -- agent/manager statistics
- wazuh-monitoring-*   -- agent status monitoring

This module provides a lightweight OpenSearch query interface
using Wazuh's Basic Auth (admin credentials) against port 9200.

Only enabled when `indexer_enabled = true` in [wazuh] config.

OpenSearch Query DSL is used directly -- a lightweight wrapper
provides convenience methods for common alert queries.

## References

- https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html
- https://opensearch.org/docs/latest/api-reference/
  """

import base64
import json
import urllib3

from .config import WazuhConfig
from .exceptions import WazuhIndexerError

class WazuhIndexerCommands:
    """
    Wazuh Indexer (OpenSearch) query operations.

    Requires ``indexer_enabled = true`` in [wazuh] config.

    Parameters
    ----------
    config : WazuhConfig
        Connector configuration (indexer_* fields used).
    http : urllib3.PoolManager
        Shared connection pool from WazuhClient.
    """

    def __init__(self, config: WazuhConfig, http: urllib3.PoolManager) -> None:
        self._config = config
        self._http = http

    def _require_indexer(self) -> None:
        if not self._config.indexer_enabled:
            raise WazuhIndexerError(
                "Indexer commands require 'indexer_enabled = true' "
                "in [wazuh] config."
            )

    def _auth_header(self) -> dict[str, str]:
        creds = (
            f"{self._config.indexer_username}:{self._config.indexer_password}"
        )
        encoded = base64.b64encode(creds.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def _indexer_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> dict:
        url = self._config.indexer_endpoint(path)
        headers = {**self._auth_header(), "Content-Type": "application/json"}
        encoded = json.dumps(body).encode() if body else None
        try:
            response = self._http.request(
                method,
                url,
                body=encoded,
                headers=headers,
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise WazuhIndexerError(f"Indexer HTTP error: {exc}") from exc

        if response.status not in (200, 201):
            raise WazuhIndexerError(
                f"Indexer returned HTTP {response.status} for {path}."
            )
        try:
            return json.loads(response.data.decode("utf-8"))
        except Exception as exc:
            raise WazuhIndexerError(f"Failed to parse indexer response: {exc}") from exc

    # ── Index management ───────────────────────────────────────────────────

    def list_alert_indices(self) -> list[str]:
        """
        List all wazuh-alerts-* index names.

        Returns
        -------
        list[str]
            Index names.
        """
        self._require_indexer()
        response = self._indexer_request("GET", "_cat/indices/wazuh-alerts-*?format=json")
        return [idx.get("index", "") for idx in response] if isinstance(response, list) else []

    def get_index_stats(self, index: str = "wazuh-alerts-*") -> dict:
        """
        Return document count and storage stats for an index pattern.

        Parameters
        ----------
        index : str
            Index name or pattern.

        Returns
        -------
        dict
            Stats from the _stats endpoint.
        """
        self._require_indexer()
        return self._indexer_request("GET", f"{index}/_stats")

    # ── Alert search ───────────────────────────────────────────────────────

    def search_alerts(
        self,
        query: dict | None = None,
        size: int = 100,
        from_: int = 0,
        sort: list[dict] | None = None,
        index: str = "wazuh-alerts-*",
    ) -> dict:
        """
        Execute an OpenSearch query against wazuh-alerts-*.

        Parameters
        ----------
        query : dict | None
            OpenSearch Query DSL ``query`` clause.
            If None, matches all documents.
        size : int
            Number of results to return.
        from_ : int
            Pagination offset.
        sort : list[dict] | None
            Sort criteria, e.g. ``[{"timestamp": {"order": "desc"}}]``.
        index : str
            Index pattern to search.

        Returns
        -------
        dict
            Raw OpenSearch search response with hits.total and hits.hits.
        """
        self._require_indexer()
        body: dict = {
            "size": min(size, 10000),
            "from": from_,
            "query": query or {"match_all": {}},
        }
        if sort:
            body["sort"] = sort
        return self._indexer_request("POST", f"{index}/_search", body=body)

    def search_alerts_by_agent(
        self,
        agent_id: str,
        min_level: int = 0,
        size: int = 100,
    ) -> list[dict]:
        """
        Search alerts for a specific agent with optional min rule level.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        min_level : int
            Minimum rule.level to include.
        size : int
            Max results.

        Returns
        -------
        list[dict]
            Alert source documents.
        """
        query: dict = {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        }
        response = self.search_alerts(
            query=query,
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        hits = response.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def search_alerts_time_range(
        self,
        start: str,
        end: str,
        min_level: int = 0,
        agent_id: str | None = None,
        size: int = 500,
        index: str = "wazuh-alerts-*",
    ) -> list[dict]:
        """
        Search alerts within a time range.

        Parameters
        ----------
        start : str
            ISO 8601 start timestamp, e.g. '2024-01-01T00:00:00'.
        end : str
            ISO 8601 end timestamp.
        min_level : int
            Minimum rule.level.
        agent_id : str | None
            Optionally restrict to one agent.
        size : int
            Max results.
        index : str
            Index pattern.

        Returns
        -------
        list[dict]
            Alert source documents.
        """
        must_clauses: list[dict] = [
            {"range": {"@timestamp": {"gte": start, "lte": end}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        if agent_id:
            must_clauses.append({"term": {"agent.id": agent_id}})

        query = {"bool": {"must": must_clauses}}
        response = self.search_alerts(
            query=query,
            size=size,
            sort=[{"@timestamp": {"order": "asc"}}],
            index=index,
        )
        hits = response.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def count_alerts(
        self,
        query: dict | None = None,
        index: str = "wazuh-alerts-*",
    ) -> int:
        """
        Count documents matching a query.

        Parameters
        ----------
        query : dict | None
            Query DSL. None = all documents.
        index : str
            Index pattern.

        Returns
        -------
        int
            Document count.
        """
        self._require_indexer()
        body = {"query": query or {"match_all": {}}}
        response = self._indexer_request("POST", f"{index}/_count", body=body)
        return response.get("count", 0)

    def aggregate_alerts(
        self,
        agg_name: str,
        agg_body: dict,
        query: dict | None = None,
        index: str = "wazuh-alerts-*",
    ) -> dict:
        """
        Run an OpenSearch aggregation against alert indices.

        Parameters
        ----------
        agg_name : str
            Aggregation result key name.
        agg_body : dict
            OpenSearch aggregation definition.
            e.g. ``{"terms": {"field": "rule.groups", "size": 10}}``
        query : dict | None
            Optional query to filter documents before aggregation.
        index : str
            Index pattern.

        Returns
        -------
        dict
            Aggregation result buckets.
        """
        self._require_indexer()
        body = {
            "size": 0,
            "query": query or {"match_all": {}},
            "aggs": {agg_name: agg_body},
        }
        response = self._indexer_request("POST", f"{index}/_search", body=body)
        return response.get("aggregations", {}).get(agg_name, {})
