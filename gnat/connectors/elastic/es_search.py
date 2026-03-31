"""
gnat.connectors.elastic.es_search

Elasticsearch index management and search commands.

Covers the Elasticsearch REST API surface (port 9200):

- Cluster / node health and info
- Index management (list, create, delete, stats)
- Document CRUD
- Security-focused search helpers (alerts, FIM events, process events)

All search operations use the Query DSL directly. For threat
intelligence indicator management use ElasticThreatIntelCommands.
For Kibana detection rules and alert management use KibanaRulesCommands
and KibanaAlertsCommands respectively.

## ECS field reference

Key ECS fields used in GNAT security queries:
@timestamp           -- event time
event.kind           -- 'alert', 'event', 'signal'
event.category       -- ['network', 'file', 'process', 'authentication', …]
event.action         -- specific action string
event.severity       -- integer 1-100
agent.name / agent.id -- originating agent
host.name / host.ip  -- host context
source.ip / dest.ip  -- network context
user.name            -- user context
process.name         -- process context
file.path            -- file context
rule.name            -- detection rule name
kibana.alert.rule.*  -- Kibana detection rule alert fields

## References

- https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html
- https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
  """

from .client import ElasticClient


class ElasticSearchCommands:
    """
    Elasticsearch index management and document search operations.

    Parameters
    ----------
    client : ElasticClient
        Authenticated HTTP client.
    """

    def __init__(self, client: ElasticClient) -> None:
        self._client = client

    # ── Cluster / health ───────────────────────────────────────────────────

    def cluster_health(self) -> dict:
        """
        Return Elasticsearch cluster health status.

        Returns
        -------
        dict
            Cluster health including status ('green'/'yellow'/'red'),
            node count, shard counts.
        """
        return self._client.es_get("_cluster/health")

    def cluster_info(self) -> dict:
        """Return basic cluster info including version and cluster_uuid."""
        return self._client.es_get("")

    def node_stats(self) -> dict:
        """Return stats for all nodes in the cluster."""
        return self._client.es_get("_nodes/stats")

    # ── Index management ───────────────────────────────────────────────────

    def list_indices(
        self,
        pattern: str = "*",
        include_hidden: bool = False,
    ) -> list[dict]:
        """
        List indices matching a pattern.

        Parameters
        ----------
        pattern : str
            Index name or wildcard pattern.
        include_hidden : bool
            Include hidden indices (starting with '.').

        Returns
        -------
        list[dict]
            Index metadata records (name, health, status, doc_count, etc.)
        """
        params: dict = {
            "format": "json",
            "h": "index,health,status,pri,rep,docs.count,store.size",
        }
        if include_hidden:
            params["expand_wildcards"] = "all"

        response = self._client.es_get(f"_cat/indices/{pattern}", params=params)
        # _cat returns a list
        return response if isinstance(response, list) else []

    def get_index_mapping(self, index: str) -> dict:
        """
        Return the field mapping for an index.

        Parameters
        ----------
        index : str
            Index name or alias.

        Returns
        -------
        dict
            Mapping definition.
        """
        return self._client.es_get(f"{index}/_mapping")

    def get_index_stats(self, index: str) -> dict:
        """
        Return document count and storage stats for an index.

        Parameters
        ----------
        index : str
            Index name or pattern.

        Returns
        -------
        dict
            Stats response.
        """
        return self._client.es_get(f"{index}/_stats")

    def index_exists(self, index: str) -> bool:
        """
        Check whether an index exists.

        Parameters
        ----------
        index : str
            Index name.

        Returns
        -------
        bool
        """
        try:
            self._client.es_get(f"{index}/_settings")
            return True
        except Exception:
            return False

    def doc_count(self, index: str, query: dict | None = None) -> int:
        """
        Count documents in an index, optionally filtered.

        Parameters
        ----------
        index : str
            Index name or pattern.
        query : dict | None
            Query DSL filter.

        Returns
        -------
        int
            Document count.
        """
        return self._client.es_count(index, query=query)

    # ── Document CRUD ──────────────────────────────────────────────────────

    def get_document(self, index: str, doc_id: str) -> dict | None:
        """
        Retrieve a document by ID.

        Parameters
        ----------
        index : str
            Index name.
        doc_id : str
            Document ID.

        Returns
        -------
        dict | None
            Document ``_source``, or None if not found.
        """
        try:
            response = self._client.es_get(f"{index}/_doc/{doc_id}")
            return response.get("_source")
        except Exception:
            return None

    def index_document(
        self,
        index: str,
        document: dict,
        doc_id: str | None = None,
        refresh: str = "false",
    ) -> dict:
        """
        Index a document.

        Parameters
        ----------
        index : str
            Target index.
        document : dict
            Document to index.
        doc_id : str | None
            Explicit document ID. If None, Elasticsearch generates one.
        refresh : str
            'true', 'false', or 'wait_for'.

        Returns
        -------
        dict
            Index response including _id, result, _version.
        """
        params = {"refresh": refresh}
        if doc_id:
            return self._client.es_put(
                f"{index}/_doc/{doc_id}",
                body=document,
            )
        return self._client.es_post(
            f"{index}/_doc",
            body=document,
            params=params,
        )

    def delete_document(
        self,
        index: str,
        doc_id: str,
        refresh: str = "false",
    ) -> dict:
        """
        Delete a document by ID.

        Parameters
        ----------
        index : str
            Index name.
        doc_id : str
            Document ID.
        refresh : str
            Index refresh after delete.

        Returns
        -------
        dict
            Delete response.
        """
        return self._client.es_delete(
            f"{index}/_doc/{doc_id}",
            params={"refresh": refresh},
        )

    def bulk_index(
        self,
        index: str,
        documents: list[dict],
        batch_size: int = 500,
        refresh: str = "false",
    ) -> list[dict]:
        """
        Bulk index documents using the Elasticsearch _bulk API.

        Parameters
        ----------
        index : str
            Target index.
        documents : list[dict]
            Documents to index.
        batch_size : int
            Documents per bulk request.
        refresh : str
            Index refresh policy.

        Returns
        -------
        list[dict]
            Aggregated responses from all bulk calls.
        """
        responses = []
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            # Build NDJSON body: action line + source line per doc
            lines: list[str] = []
            for doc in batch:
                lines.append('{"index": {}}')
                import json as _json
                lines.append(_json.dumps(doc))
            ndjson = "\n".join(lines) + "\n"

            # Bulk endpoint requires text/plain or application/x-ndjson
            url = self._client.config.es_url(f"{index}/_bulk")
            if refresh != "false":
                url += f"?refresh={refresh}"
            headers = self._client.auth.get_es_headers(
                {"Content-Type": "application/x-ndjson"}
            )
            response = self._client._http.request(
                "POST", url,
                body=ndjson.encode("utf-8"),
                headers=headers,
            )
            import json as _json2
            responses.append(
                _json2.loads(response.data.decode("utf-8"))
                if response.status in (200, 201)
                else {"errors": True, "status": response.status}
            )
        return responses

    # ── Security alert search helpers ──────────────────────────────────────

    def search_alerts(
        self,
        min_severity: int | None = None,
        rule_name: str | None = None,
        host_name: str | None = None,
        user_name: str | None = None,
        time_range: tuple[str, str] | None = None,
        size: int = 100,
        index: str | None = None,
    ) -> list[dict]:
        """
        Search Kibana security alerts in the .alerts-security.* index.

        Parameters
        ----------
        min_severity : int | None
            Minimum kibana.alert.severity_score (0-100).
        rule_name : str | None
            Filter by detection rule name.
        host_name : str | None
            Filter by host.name.
        user_name : str | None
            Filter by user.name.
        time_range : tuple[str, str] | None
            (start, end) ISO 8601 timestamps.
        size : int
            Max results.
        index : str | None
            Override default alert index pattern.

        Returns
        -------
        list[dict]
            Alert ``_source`` documents.
        """
        target_index = index or self._client.config.es_index_alerts
        must: list[dict] = []

        if min_severity is not None:
            must.append({"range": {"kibana.alert.severity_score": {"gte": min_severity}}})
        if rule_name:
            must.append({"term": {"kibana.alert.rule.name": rule_name}})
        if host_name:
            must.append({"term": {"host.name": host_name}})
        if user_name:
            must.append({"term": {"user.name": user_name}})
        if time_range:
            start, end = time_range
            must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        return self._client.es_search_hits(
            target_index,
            query=query,
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
        )

    def search_process_events(
        self,
        process_name: str | None = None,
        host_name: str | None = None,
        time_range: tuple[str, str] | None = None,
        size: int = 100,
    ) -> list[dict]:
        """
        Search process execution events across all logs-* indices.

        Parameters
        ----------
        process_name : str | None
            Filter by process.name.
        host_name : str | None
            Filter by host.name.
        time_range : tuple[str, str] | None
            (start, end) ISO 8601 timestamps.
        size : int
            Max results.

        Returns
        -------
        list[dict]
            Process event documents.
        """
        must: list[dict] = [{"term": {"event.category": "process"}}]
        if process_name:
            must.append({"term": {"process.name": process_name}})
        if host_name:
            must.append({"term": {"host.name": host_name}})
        if time_range:
            start, end = time_range
            must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

        return self._client.es_search_hits(
            "logs-*",
            query={"bool": {"must": must}},
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
        )

    def search_network_events(
        self,
        src_ip: str | None = None,
        dest_ip: str | None = None,
        dest_port: int | None = None,
        time_range: tuple[str, str] | None = None,
        size: int = 100,
    ) -> list[dict]:
        """
        Search network connection events.

        Parameters
        ----------
        src_ip : str | None
            Filter by source.ip.
        dest_ip : str | None
            Filter by destination.ip.
        dest_port : int | None
            Filter by destination.port.
        time_range : tuple[str, str] | None
            (start, end) ISO 8601 timestamps.
        size : int
            Max results.

        Returns
        -------
        list[dict]
            Network event documents.
        """
        must: list[dict] = [{"term": {"event.category": "network"}}]
        if src_ip:
            must.append({"term": {"source.ip": src_ip}})
        if dest_ip:
            must.append({"term": {"destination.ip": dest_ip}})
        if dest_port:
            must.append({"term": {"destination.port": dest_port}})
        if time_range:
            start, end = time_range
            must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

        return self._client.es_search_hits(
            "logs-*",
            query={"bool": {"must": must}},
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
        )

    def aggregate_by_field(
        self,
        index: str,
        field: str,
        query: dict | None = None,
        top_n: int = 10,
    ) -> list[dict]:
        """
        Run a terms aggregation on a field and return top-N buckets.

        Parameters
        ----------
        index : str
            Index name or pattern.
        field : str
            ECS field name to aggregate on.
        query : dict | None
            Optional query filter.
        top_n : int
            Number of top buckets to return.

        Returns
        -------
        list[dict]
            Aggregation buckets with ``key`` and ``doc_count``.
        """
        response = self._client.es_search(
            index,
            query=query,
            size=0,
            aggs={"top_values": {"terms": {"field": field, "size": top_n}}},
        )
        return response.get("aggregations", {}).get("top_values", {}).get("buckets", [])
