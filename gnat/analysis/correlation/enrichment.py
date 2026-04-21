"""
gnat.analysis.correlation.enrichment
======================================

:class:`EnrichmentDispatcher` fans out enrichment requests to configured
connectors and merges the results.

Each connector is queried via its best available search method (searched
in priority order):

1. ``search_indicators_by_value(value)``
2. ``search_observables_by_value(value)``
3. ``list_objects("indicator", filters={"query": value})``

Results are collected best-effort: a connector that fails or times out is
skipped and logged at DEBUG level so it never halts the enrichment run.

Usage::

    from gnat.analysis.correlation.enrichment import EnrichmentDispatcher

    dispatcher = EnrichmentDispatcher(
        connectors  = {"threatq": tq_client, "virustotal": vt_client},
        timeout_sec = 10,
    )
    results = dispatcher.enrich("185.220.101.5", ioc_type="ipv4-addr")
    for platform, records in results.items():
        print(platform, len(records), "results")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    """
    Enrichment results from a single platform.

    Parameters
    ----------
    platform : str
        Source platform name.
    value : str
        Queried IOC value.
    ioc_type : str
        IOC type queried.
    records : list of dict
        Raw records returned by the connector.
    error : str, optional
        Error message if the connector failed.
    """

    platform: str
    value: str
    ioc_type: str
    records: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None

    @property
    def count(self) -> int:
        return len(self.records)


class EnrichmentDispatcher:
    """
    Fan out enrichment queries to multiple connectors, collect results
    best-effort.

    Parameters
    ----------
    connectors : dict
        Mapping of platform name → connector instance.
    timeout_sec : int
        Per-connector query timeout in seconds.  Not enforced at this layer
        (connectors use their own HTTP timeout); used only for logging.
    max_results_per_platform : int
        Maximum records to retain per platform per query (default 50).
    """

    def __init__(
        self,
        connectors: dict[str, Any],
        timeout_sec: int = 15,
        max_results_per_platform: int = 50,
    ) -> None:
        self._connectors = connectors
        self._timeout = timeout_sec
        self._max_results = max_results_per_platform

    def enrich(
        self,
        value: str,
        ioc_type: str = "indicator",
        platforms: list[str] | None = None,
    ) -> dict[str, EnrichmentResult]:
        """
        Query all (or selected) connectors for a given IOC value.

        Parameters
        ----------
        value : str
            IOC value to enrich (e.g. ``"185.220.101.5"``).
        ioc_type : str
            IOC type hint passed to connectors that support typed search.
        platforms : list of str, optional
            Restrict enrichment to these platform names.  Default: all.

        Returns
        -------
        dict
            Mapping of platform name → :class:`EnrichmentResult`.
        """
        targets = {k: v for k, v in self._connectors.items() if platforms is None or k in platforms}

        results: dict[str, EnrichmentResult] = {}
        for platform, connector in targets.items():
            results[platform] = self._query_one(platform, connector, value, ioc_type)

        total = sum(r.count for r in results.values())
        logger.info(
            "EnrichmentDispatcher: enriched %r across %d platforms → %d total records",
            value,
            len(targets),
            total,
        )
        return results

    def enrich_batch(
        self,
        values: list[str],
        ioc_type: str = "indicator",
        platforms: list[str] | None = None,
    ) -> dict[str, dict[str, EnrichmentResult]]:
        """
        Enrich multiple IOC values.

        Returns
        -------
        dict
            ``{value: {platform: EnrichmentResult}}``.
        """
        return {v: self.enrich(v, ioc_type=ioc_type, platforms=platforms) for v in values}

    def summary(self, results: dict[str, EnrichmentResult]) -> dict[str, Any]:
        """Return a summary dict for a set of enrichment results."""
        return {
            "platforms_queried": len(results),
            "platforms_succeeded": sum(1 for r in results.values() if r.success),
            "total_records": sum(r.count for r in results.values()),
            "by_platform": {
                p: {"count": r.count, "success": r.success} for p, r in results.items()
            },
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _query_one(
        self,
        platform: str,
        connector: Any,
        value: str,
        ioc_type: str,
    ) -> EnrichmentResult:
        try:
            records = self._search(connector, value, ioc_type)
            return EnrichmentResult(
                platform=platform,
                value=value,
                ioc_type=ioc_type,
                records=records[: self._max_results],
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("EnrichmentDispatcher: %s failed for %r: %s", platform, value, exc)
            return EnrichmentResult(
                platform=platform,
                value=value,
                ioc_type=ioc_type,
                error=str(exc),
            )

    @staticmethod
    def _search(connector: Any, value: str, ioc_type: str) -> list[dict[str, Any]]:
        """Try connector search methods in priority order."""
        if hasattr(connector, "search_indicators_by_value"):
            result = connector.search_indicators_by_value(value)
        elif hasattr(connector, "search_observables_by_value"):
            result = connector.search_observables_by_value(value)
        elif hasattr(connector, "list_objects"):
            result = connector.list_objects("indicator", filters={"query": value})
        else:
            return []

        if result is None:
            return []
        if isinstance(result, dict):
            return [result]
        return list(result)
