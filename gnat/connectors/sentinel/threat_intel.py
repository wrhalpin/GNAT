"""
gnat.connectors.sentinel.threat_intel
==========================================
Threat Intelligence Indicator commands for Microsoft Sentinel.

Sentinel's TI Indicators API maps directly to STIX 2.1 indicator SDOs.
Indicators are stored under the ThreatIntelligence/main workspace resource.

Key indicator fields (map to STIX fields)
------------------------------------------
  displayName         — indicator.name
  pattern             — indicator.pattern (STIX pattern)
  patternType         — indicator.pattern_type ('stix')
  threatIntelligenceTags — indicator.labels
  validFrom           — indicator.valid_from
  validUntil          — indicator.valid_until
  confidence          — indicator.confidence (0–100)
  threatTypes         — indicator.indicator_types
  killChainPhases     — indicator.kill_chain_phases
  externalReferences  — indicator.external_references
  revoked             — indicator.revoked
  source              — creating source name

References
----------
- https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence-indicator
"""

from collections.abc import Iterator

from .client import SentinelClient


class SentinelThreatIntelCommands:
    """Threat Intelligence Indicator management operations."""

    def __init__(self, client: SentinelClient) -> None:
        self._client = client

    def list_indicators(
        self,
        filter_val: str | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List TI indicators.

        Parameters
        ----------
        filter_val : str | None
            OData $filter expression.
        order_by : str | None
            OData $orderby expression.
        limit : int | None
            Max results.

        Returns
        -------
        list[dict]
        """
        params: dict = {}
        if filter_val:
            params["$filter"] = filter_val
        if order_by:
            params["$orderby"] = order_by
        items = []
        for item in self._client.paginate("threatIntelligence/main/indicators", params=params):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def iter_all_indicators(self) -> Iterator[dict]:
        """Generator yielding all TI indicators."""
        yield from self._client.paginate("threatIntelligence/main/indicators")

    def get_indicator(self, indicator_name: str) -> dict:
        """Get a single indicator by its resource name."""
        return self._client.get(f"threatIntelligence/main/indicators/{indicator_name}")

    def create_indicator(self, indicator: dict) -> dict:
        """
        Create a new TI indicator.

        Parameters
        ----------
        indicator : dict
            Indicator properties dict. Required fields:
              displayName, pattern, patternType, source, validFrom.

        Returns
        -------
        dict
            Created indicator resource.
        """
        return self._client.post(
            "threatIntelligence/main/createIndicator",
            body={"properties": indicator},
        )

    def update_indicator(self, indicator_name: str, updates: dict) -> dict:
        """
        Update a TI indicator (replace the properties dict).

        Parameters
        ----------
        indicator_name : str
        updates : dict
            Full properties dict to replace with.

        Returns
        -------
        dict
        """
        return self._client.put(
            f"threatIntelligence/main/indicators/{indicator_name}",
            body={"properties": updates},
        )

    def delete_indicator(self, indicator_name: str) -> dict:
        """Delete a TI indicator."""
        return self._client.delete(f"threatIntelligence/main/indicators/{indicator_name}")

    def bulk_create_indicators(self, indicators: list[dict]) -> list[dict]:
        """
        Create multiple TI indicators.

        Parameters
        ----------
        indicators : list[dict]
            List of indicator properties dicts.

        Returns
        -------
        list[dict]
            Created indicator resources.
        """
        results = []
        for ind in indicators:
            try:
                results.append(self.create_indicator(ind))
            except Exception as exc:
                results.append({"error": str(exc), "input": ind})
        return results

    def query_indicators(self, query: dict) -> list[dict]:
        """
        Query indicators using Sentinel's indicator query endpoint.

        Parameters
        ----------
        query : dict
            Query body with optional keywords, sortBy, pageSize, etc.

        Returns
        -------
        list[dict]
        """
        result = self._client.post(
            "threatIntelligence/main/queryIndicators",
            body=query,
        )
        return result.get("value", [])

    @staticmethod
    def normalise_indicator(indicator: dict) -> dict:
        """Flatten a Sentinel TI indicator to GNAT normalised format."""
        props = indicator.get("properties", {})
        return {
            "id": indicator.get("name"),
            "display_name": props.get("displayName"),
            "pattern": props.get("pattern"),
            "pattern_type": props.get("patternType", "stix"),
            "valid_from": props.get("validFrom"),
            "valid_until": props.get("validUntil"),
            "confidence": props.get("confidence", 0),
            "revoked": props.get("revoked", False),
            "source": props.get("source"),
            "threat_types": props.get("threatTypes", []),
            "tags": props.get("threatIntelligenceTags", []),
            "kill_chain_phases": props.get("killChainPhases", []),
            "external_references": props.get("externalReferences", []),
            "_raw": indicator,
        }
