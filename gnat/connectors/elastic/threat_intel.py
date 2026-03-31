"""
gnat.connectors.elastic.threat_intel

Threat Intelligence indicator commands for the Elastic Security connector.

Elastic stores TI indicators in data streams under the `logs-ti_*` pattern,
using the ECS `threat.indicator.*` field hierarchy.

## Two ingestion pathways

1. Custom Threat Intelligence Integration (recommended for STIX 2.1)
   ───────────────────────────────────────────────────────────────────
   POST /api/fleet/epm/packages/ti_custom/…
   Configured via Kibana Fleet; ingests STIX 2.1 files or TAXII feeds.
   Results land in `logs-ti_custom.indicator-*`.
1. Direct Elasticsearch index (for programmatic bulk upload)
   ───────────────────────────────────────────────────────────
   POST to `logs-ti_<source>.indicator-<namespace>/_doc`
   Documents must conform to ECS `threat.indicator.*` schema.
   This is what GNAT uses for bulk IOC push from its ORM.

## ECS threat.indicator fields

threat.indicator.type         -- 'ipv4-addr', 'domain-name', 'url', 'file', etc.
threat.indicator.ip           -- IP value
threat.indicator.domain       -- domain value
threat.indicator.url.full     -- URL value
threat.indicator.file.hash.*  -- file hashes
threat.indicator.email.address -- email IOC
threat.indicator.confidence   -- 'High', 'Medium', 'Low', 'Not Specified'
threat.indicator.first_seen   -- ISO 8601 first seen
threat.indicator.last_seen    -- ISO 8601 last seen
threat.indicator.description  -- free text description
threat.indicator.provider     -- source name
threat.indicator.reference    -- source URL
threat.feed.name              -- feed name
threat.feed.dashboard_id      -- linked Kibana dashboard

## STIX 2.1 -> ECS mapping table (for GNAT ORM -> Elastic upload)

ipv4-addr.value           -> threat.indicator.ip
ipv6-addr.value           -> threat.indicator.ip
domain-name.value         -> threat.indicator.domain
url.value                 -> threat.indicator.url.full
file.hashes.MD5           -> threat.indicator.file.hash.md5
file.hashes.SHA-1         -> threat.indicator.file.hash.sha1
file.hashes.SHA-256       -> threat.indicator.file.hash.sha256
file.name                 -> threat.indicator.file.name
email-addr.value          -> threat.indicator.email.address
indicator.name            -> threat.indicator.description
indicator.confidence      -> threat.indicator.confidence (mapped to label)
indicator.valid_from      -> threat.indicator.first_seen
indicator.valid_until     -> threat.indicator.last_seen

## References

- https://www.elastic.co/guide/en/ecs/current/ecs-threat.html
- https://www.elastic.co/guide/en/security/current/es-threat-intel-integrations.html
  """

from collections.abc import Iterator
from datetime import datetime, timezone

from .client import ElasticClient

_DEFAULT_TI_INDEX = "logs-ti_gnat.indicator-default"
_CONFIDENCE_MAP = {
3: "High", 2: "Medium", 1: "Low", 0: "Not Specified",
"high": "High", "medium": "Medium", "low": "Low",
}

class ElasticThreatIntelCommands:
    """
    Threat Intelligence indicator management operations.

    Parameters
    ----------
    client : ElasticClient
        Authenticated HTTP client.
    """

    def __init__(self, client: ElasticClient) -> None:
        self._client = client

    # ── Read indicators ────────────────────────────────────────────────────

    def search_indicators(
        self,
        indicator_type: str | None = None,
        value: str | None = None,
        provider: str | None = None,
        confidence: str | None = None,
        first_seen_after: str | None = None,
        size: int = 100,
        index: str | None = None,
    ) -> list[dict]:
        """
        Search threat intelligence indicators.

        Parameters
        ----------
        indicator_type : str | None
            ECS indicator type: 'ipv4-addr', 'domain-name', 'url', 'file', etc.
        value : str | None
            Indicator value (searched across all value fields).
        provider : str | None
            Filter by threat.indicator.provider.
        confidence : str | None
            'High', 'Medium', 'Low', or 'Not Specified'.
        first_seen_after : str | None
            ISO 8601 timestamp -- only indicators first seen after this.
        size : int
            Max results.
        index : str | None
            Override default TI index pattern.

        Returns
        -------
        list[dict]
            Indicator ``_source`` documents.
        """
        target = index or self._client.config.es_index_ti
        must: list[dict] = []

        if indicator_type:
            must.append({"term": {"threat.indicator.type": indicator_type}})
        if provider:
            must.append({"term": {"threat.indicator.provider": provider}})
        if confidence:
            must.append({"term": {"threat.indicator.confidence": confidence}})
        if first_seen_after:
            must.append({
                "range": {"threat.indicator.first_seen": {"gte": first_seen_after}}
            })

        if value:
            # Value might be in any of several sub-fields
            should: list[dict] = [
                {"term": {"threat.indicator.ip": value}},
                {"term": {"threat.indicator.domain": value}},
                {"term": {"threat.indicator.url.full": value}},
                {"term": {"threat.indicator.email.address": value}},
                {"term": {"threat.indicator.file.hash.md5": value}},
                {"term": {"threat.indicator.file.hash.sha256": value}},
            ]
            must.append({"bool": {"should": should, "minimum_should_match": 1}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        return self._client.es_search_hits(
            target,
            query=query,
            size=size,
            sort=[{"threat.indicator.last_seen": {"order": "desc"}}],
        )

    def iter_all_indicators(
        self,
        indicator_type: str | None = None,
        provider: str | None = None,
        index: str | None = None,
    ) -> Iterator[dict]:
        """
        Generator yielding all indicators, paginating automatically.

        Parameters
        ----------
        indicator_type : str | None
            ECS indicator type filter.
        provider : str | None
            Provider filter.
        index : str | None
            Override index pattern.

        Yields
        ------
        dict
            Indicator source documents.
        """
        target = index or self._client.config.es_index_ti
        must: list[dict] = []
        if indicator_type:
            must.append({"term": {"threat.indicator.type": indicator_type}})
        if provider:
            must.append({"term": {"threat.indicator.provider": provider}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}

        yield from self._client.es_paginate(
            target,
            query=query,
            sort=[{"@timestamp": {"order": "asc"}}],
        )

    def get_indicator_counts_by_type(self, index: str | None = None) -> list[dict]:
        """
        Return indicator counts grouped by type.

        Returns
        -------
        list[dict]
            Aggregation buckets: ``[{"key": "ipv4-addr", "doc_count": N}, ...]``
        """
        target = index or self._client.config.es_index_ti
        from .es_search import ElasticSearchCommands
        searcher = ElasticSearchCommands(self._client)
        return searcher.aggregate_by_field(
            target,
            field="threat.indicator.type",
            top_n=20,
        )

    # ── Write indicators ───────────────────────────────────────────────────

    def index_indicator(
        self,
        indicator_doc: dict,
        index: str | None = None,
        refresh: str = "false",
    ) -> dict:
        """
        Index a single ECS-formatted TI indicator document.

        Parameters
        ----------
        indicator_doc : dict
            ECS-formatted document with ``threat.indicator.*`` fields.
        index : str | None
            Target index. Defaults to _DEFAULT_TI_INDEX.
        refresh : str
            Index refresh policy.

        Returns
        -------
        dict
            Elasticsearch index response.
        """
        target = index or _DEFAULT_TI_INDEX
        # Ensure @timestamp is set
        if "@timestamp" not in indicator_doc:
            indicator_doc["@timestamp"] = _now_iso()
        return self._client.es_post(
            f"{target}/_doc",
            body=indicator_doc,
            params={"refresh": refresh},
        )

    def bulk_index_indicators(
        self,
        indicators: list[dict],
        index: str | None = None,
        batch_size: int = 500,
    ) -> list[dict]:
        """
        Bulk index ECS-formatted TI indicator documents.

        Parameters
        ----------
        indicators : list[dict]
            List of ECS indicator documents.
        index : str | None
            Target index.
        batch_size : int
            Documents per bulk request.

        Returns
        -------
        list[dict]
            Bulk response summaries.
        """
        target = index or _DEFAULT_TI_INDEX
        # Ensure @timestamp on all docs
        for doc in indicators:
            if "@timestamp" not in doc:
                doc["@timestamp"] = _now_iso()

        from .es_search import ElasticSearchCommands
        searcher = ElasticSearchCommands(self._client)
        return searcher.bulk_index(target, indicators, batch_size=batch_size)

    def delete_indicators_by_provider(
        self,
        provider: str,
        index: str | None = None,
    ) -> dict:
        """
        Delete all indicators from a specific provider using delete-by-query.

        Parameters
        ----------
        provider : str
            Provider name (threat.indicator.provider).
        index : str | None
            Target index.

        Returns
        -------
        dict
            Delete-by-query response with deleted count.
        """
        target = index or _DEFAULT_TI_INDEX
        body = {"query": {"term": {"threat.indicator.provider": provider}}}
        return self._client.es_post(f"{target}/_delete_by_query", body=body)

    # ── STIX 2.1 upload via Kibana ─────────────────────────────────────────

    def upload_stix_bundle(
        self,
        bundle: dict,
        source_name: str = "gnat",
        index: str | None = None,
    ) -> dict:
        """
        Convert a STIX 2.1 bundle to ECS and bulk-index into Elastic.

        This converts the bundle using ElasticSTIXMapper then calls
        bulk_index_indicators. For large bundles, prefer uploading via
        the Custom Threat Intelligence Kibana integration.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle dict.
        source_name : str
            Value for threat.indicator.provider and threat.feed.name.
        index : str | None
            Target index override.

        Returns
        -------
        dict
            Summary with indexed_count and any errors.
        """
        from .stix_mapper import ElasticSTIXMapper
        mapper = ElasticSTIXMapper()
        ecs_docs = mapper.stix_bundle_to_ecs_indicators(bundle, provider=source_name)

        if not ecs_docs:
            return {"indexed_count": 0, "errors": []}

        responses = self.bulk_index_indicators(ecs_docs, index=index)
        total_errors = sum(
            1 for r in responses
            if r.get("errors")
        )
        return {
            "indexed_count": len(ecs_docs),
            "batch_responses": len(responses),
            "batches_with_errors": total_errors,
        }

    # ── Normalisation helper ───────────────────────────────────────────────

    @staticmethod
    def normalise_indicator(doc: dict) -> dict:
        """
        Flatten an ECS indicator document to GNAT normalised format.

        Parameters
        ----------
        doc : dict
            ECS threat indicator source document.

        Returns
        -------
        dict
            Normalised indicator dict.
        """
        ti = doc.get("threat", {}).get("indicator", {})
        feed = doc.get("threat", {}).get("feed", {})
        return {
            "type": ti.get("type"),
            "ip": ti.get("ip"),
            "domain": ti.get("domain"),
            "url": ti.get("url", {}).get("full"),
            "email": ti.get("email", {}).get("address"),
            "file_name": ti.get("file", {}).get("name"),
            "file_md5": ti.get("file", {}).get("hash", {}).get("md5"),
            "file_sha1": ti.get("file", {}).get("hash", {}).get("sha1"),
            "file_sha256": ti.get("file", {}).get("hash", {}).get("sha256"),
            "confidence": ti.get("confidence"),
            "description": ti.get("description"),
            "provider": ti.get("provider"),
            "reference": ti.get("reference"),
            "first_seen": ti.get("first_seen"),
            "last_seen": ti.get("last_seen"),
            "feed_name": feed.get("name"),
            "timestamp": doc.get("@timestamp"),
            "_raw": doc,
        }

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
