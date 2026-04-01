"""
gnat.viz.grafana.search_endpoints
====================================

Grafana SimpleJSON endpoints that expose the GNAT Solr search sidecar
as a Grafana data source.

These endpoints are mounted under ``/solr/`` on the main ``GrafanaServer``
application when a ``SearchIndex`` is provided at startup.

Endpoints
---------
``GET  /solr/``              — Health check (pings Solr)
``POST /solr/search``        — Available metric names (Solr-sourced)
``POST /solr/query``         — Table / time-series data from Solr index stats
``POST /solr/tag-keys``      — Ad-hoc filter keys (stix_type, source_platform)
``POST /solr/tag-values``    — Ad-hoc filter values from Solr facets

Query targets (``POST /solr/query``)
-------------------------------------
``stats/type_counts``       → table:  stix_type → doc count
``stats/platform_counts``   → table:  source_platform → doc count
``stats/total``             → single-stat: total indexed document count
``search/<query_string>``   → table:  matching STIX IDs + type + platform
``facet/stix_type``         → bar chart data for type distribution
``facet/source_platform``   → bar chart data for platform distribution
``timeseries/ingest``       → time-series: docs indexed per day (requires
                               ``date_indexed`` pdate field in schema)
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.search.index import SearchIndex

logger = logging.getLogger(__name__)

# FastAPI imports at module level so that `from __future__ import annotations`
# does not prevent FastAPI from resolving Request type hints at route inspection.
# get_type_hints() evaluates annotation strings against the function's __globals__
# (i.e. this module's namespace), so Request must be bound here unconditionally.
try:
    from fastapi import APIRouter, Request  # noqa: F401 — needed for annotation resolution

    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    APIRouter = None  # type: ignore[assignment,misc]
    Request = None  # type: ignore[assignment,misc]
    _FASTAPI_AVAILABLE = False


def _solr_get(base_url: str, path: str, params: dict[str, Any]) -> dict | None:
    """
    Issue a GET request to Solr using stdlib only (no new dep).

    Returns the parsed JSON body, or None on failure.
    """
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # nosec B310  # nosemgrep
            return json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Solr request to %s failed: %s", url, exc)
        return None


def build_search_router(search_index: SearchIndex) -> Any:
    """
    Build and return a FastAPI ``APIRouter`` that exposes Solr index data.

    Parameters
    ----------
    search_index : SearchIndex
        A live ``SolrSearchIndex`` (or ``NullSearchIndex`` for safe no-ops).

    Returns
    -------
    fastapi.APIRouter
    """
    if not _FASTAPI_AVAILABLE:  # pragma: no cover
        raise ImportError("FastAPI is required: pip install 'gnat[serve]'")

    router = APIRouter(prefix="/solr", tags=["solr"])

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _base_url() -> str | None:
        """Extract the raw Solr base URL from the search index."""
        if hasattr(search_index, "base_url"):
            return search_index.base_url  # type: ignore[attr-defined]
        return None

    def _facet_counts(field: str, limit: int = 50) -> list[tuple]:
        """Return ``[(value, count), ...]`` from a Solr facet query."""
        base = _base_url()
        if not base:
            return []
        data = _solr_get(
            base,
            "select",
            {
                "q": "*:*",
                "rows": 0,
                "facet": "true",
                "facet.field": field,
                "facet.limit": limit,
                "facet.mincount": 1,
                "wt": "json",
            },
        )
        if not data:
            return []
        ff = data.get("facet_counts", {}).get("facet_fields", {}).get(field, [])
        # Solr returns flat list: [value, count, value, count, ...]
        pairs = []
        for i in range(0, len(ff) - 1, 2):
            pairs.append((str(ff[i]), int(ff[i + 1])))
        return pairs

    def _total_docs() -> int:
        """Return total number of indexed documents."""
        base = _base_url()
        if not base:
            return 0
        data = _solr_get(base, "select", {"q": "*:*", "rows": 0, "wt": "json"})
        if not data:
            return 0
        return int(data.get("response", {}).get("numFound", 0))

    def _date_facet(
        field: str = "date_indexed",
        gap: str = "+1DAY",
        start: str = "NOW-30DAYS/DAY",
        end: str = "NOW/DAY+1DAY",
    ) -> list[tuple]:
        """Return ``[(iso_date, count), ...]`` from a Solr date range facet."""
        base = _base_url()
        if not base:
            return []
        data = _solr_get(
            base,
            "select",
            {
                "q": "*:*",
                "rows": 0,
                "facet": "true",
                "facet.range": field,
                "facet.range.start": start,
                "facet.range.end": end,
                "facet.range.gap": gap,
                "wt": "json",
            },
        )
        if not data:
            return []
        range_data = data.get("facet_counts", {}).get("facet_ranges", {}).get(field, {})
        counts = range_data.get("counts", [])  # flat: [date, count, ...]
        pairs = []
        for i in range(0, len(counts) - 1, 2):
            pairs.append((str(counts[i]), int(counts[i + 1])))
        return pairs

    def _search_stix(query: str, limit: int = 100) -> list[dict[str, Any]]:
        """Full-text search returning [{id, stix_type, source_platform}]."""
        base = _base_url()
        if not base:
            return []
        data = _solr_get(
            base,
            "select",
            {
                "q": query,
                "defType": "edismax",
                "qf": "text_content",
                "fl": "id,stix_type,source_platform,display_name",
                "rows": limit,
                "wt": "json",
            },
        )
        if not data:
            return []
        return data.get("response", {}).get("docs", [])

    # ── Routes ────────────────────────────────────────────────────────────────

    @router.get("/")
    async def solr_health():
        alive = search_index.ping()
        return {"status": "ok" if alive else "degraded", "solr_reachable": alive}

    @router.post("/search")
    async def solr_search_targets():
        """Return available Solr metric names for Grafana's query editor."""
        targets = [
            "stats/total",
            "stats/type_counts",
            "stats/platform_counts",
            "timeseries/ingest",
            "facet/stix_type",
            "facet/source_platform",
        ]
        # Add per-type search suggestions from current facets
        for value, _ in _facet_counts("stix_type"):
            targets.append(f"search/{value}")
        targets.append("search/*:*")
        return targets

    @router.post("/query")
    async def solr_query(request: Request):
        """
        Handle Grafana query requests backed by Solr.

        Supported targets
        -----------------
        ``stats/total``           → single-value table
        ``stats/type_counts``     → table of (stix_type, count)
        ``stats/platform_counts`` → table of (source_platform, count)
        ``timeseries/ingest``     → time-series of indexed docs per day
        ``facet/<field>``         → bar-chart table of (value, count)
        ``search/<query>``        → table of matching STIX objects
        """
        body = await request.json()
        results = []

        for target_spec in body.get("targets", []):
            target: str = target_spec.get("target", "")

            # ── stats/total ───────────────────────────────────────────────
            if target == "stats/total":
                total = _total_docs()
                results.append(
                    {
                        "columns": [{"text": "Total Documents", "type": "number"}],
                        "rows": [[total]],
                        "type": "table",
                    }
                )

            # ── stats/type_counts ─────────────────────────────────────────
            elif target == "stats/type_counts":
                pairs = _facet_counts("stix_type")
                results.append(
                    {
                        "columns": [
                            {"text": "STIX Type", "type": "string"},
                            {"text": "Doc Count", "type": "number"},
                        ],
                        "rows": [[v, c] for v, c in pairs],
                        "type": "table",
                    }
                )

            # ── stats/platform_counts ─────────────────────────────────────
            elif target == "stats/platform_counts":
                pairs = _facet_counts("source_platform")
                results.append(
                    {
                        "columns": [
                            {"text": "Platform", "type": "string"},
                            {"text": "Doc Count", "type": "number"},
                        ],
                        "rows": [[v, c] for v, c in pairs],
                        "type": "table",
                    }
                )

            # ── timeseries/ingest ─────────────────────────────────────────
            elif target == "timeseries/ingest":
                import datetime

                pairs = _date_facet("date_indexed")
                datapoints = []
                for iso_str, count in pairs:
                    try:
                        dt = datetime.datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
                        datapoints.append([count, int(dt.timestamp() * 1000)])
                    except ValueError:
                        pass
                results.append({"target": "docs/day", "datapoints": datapoints})

            # ── facet/<field> ─────────────────────────────────────────────
            elif target.startswith("facet/"):
                field = target[len("facet/") :]
                pairs = _facet_counts(field)
                results.append(
                    {
                        "columns": [
                            {"text": field, "type": "string"},
                            {"text": "Count", "type": "number"},
                        ],
                        "rows": [[v, c] for v, c in pairs],
                        "type": "table",
                    }
                )

            # ── search/<query> ────────────────────────────────────────────
            elif target.startswith("search/"):
                query = target[len("search/") :]
                docs = _search_stix(query)
                results.append(
                    {
                        "columns": [
                            {"text": "STIX ID", "type": "string"},
                            {"text": "Type", "type": "string"},
                            {"text": "Platform", "type": "string"},
                            {"text": "Display Name", "type": "string"},
                        ],
                        "rows": [
                            [
                                d.get("id", ""),
                                d.get("stix_type", ""),
                                d.get("source_platform", ""),
                                d.get("display_name", ""),
                            ]
                            for d in docs
                        ],
                        "type": "table",
                    }
                )

        return results

    @router.post("/tag-keys")
    async def solr_tag_keys():
        return [
            {"type": "string", "text": "stix_type"},
            {"type": "string", "text": "source_platform"},
        ]

    @router.post("/tag-values")
    async def solr_tag_values(request: Request):
        body = await request.json()
        key = body.get("key", "stix_type")
        if key in ("stix_type", "source_platform"):
            pairs = _facet_counts(key)
            return [{"text": v} for v, _ in pairs]
        return []

    return router
