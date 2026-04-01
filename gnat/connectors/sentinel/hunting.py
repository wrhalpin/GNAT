"""
gnat.connectors.sentinel.hunting
======================================
Hunting query management commands for Microsoft Sentinel.

Hunting queries are saved KQL queries used by analysts to proactively
search for threats. They map to the SavedSearches API in Sentinel.

References
----------
- https://learn.microsoft.com/en-us/rest/api/securityinsights/hunting-queries
"""

from .client import SentinelClient


class SentinelHuntingCommands:
    """Hunting query management operations."""

    def __init__(self, client: SentinelClient) -> None:
        self._client = client

    def list_queries(self, limit: int | None = None) -> list[dict]:
        """
        List saved hunting queries.

        Returns
        -------
        list[dict]
        """
        items = []
        for item in self._client.paginate("savedSearches"):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def get_query(self, query_id: str) -> dict:
        """Get a single hunting query by ID."""
        return self._client.get(f"savedSearches/{query_id}")

    def create_query(
        self,
        display_name: str,
        query: str,
        description: str = "",
        tactics: list[str] | None = None,
        techniques: list[str] | None = None,
    ) -> dict:
        """
        Create a new hunting query.

        Parameters
        ----------
        display_name : str
        query : str
            KQL query string.
        description : str
        tactics : list[str] | None
            MITRE ATT&CK tactic names.
        techniques : list[str] | None
            MITRE ATT&CK technique IDs.

        Returns
        -------
        dict
        """
        import uuid

        query_id = str(uuid.uuid4())
        props: dict = {
            "displayName": display_name,
            "query": query,
            "description": description,
            "category": "Hunting Queries",
        }
        if tactics:
            props["tactics"] = tactics
        if techniques:
            props["techniques"] = techniques
        return self._client.put(
            f"savedSearches/{query_id}",
            body={"properties": props},
        )

    def delete_query(self, query_id: str) -> dict:
        """Delete a hunting query."""
        return self._client.delete(f"savedSearches/{query_id}")

    @staticmethod
    def normalise_query(query: dict) -> dict:
        """Flatten a Sentinel hunting query to GNAT normalised format."""
        props = query.get("properties", {})
        return {
            "id": query.get("name"),
            "display_name": props.get("displayName"),
            "query": props.get("query"),
            "description": props.get("description", ""),
            "tactics": props.get("tactics", []),
            "techniques": props.get("techniques", []),
            "_raw": query,
        }
