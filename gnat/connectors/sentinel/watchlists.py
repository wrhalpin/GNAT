"""
gnat.connectors.sentinel.watchlists
=========================================
Watchlist management commands for Microsoft Sentinel.

Watchlists are CSV-backed lookup tables used in KQL detection rules
and hunting queries. Common uses: known good IPs, VIP users, asset
inventory, threat actor TTPs.

References
----------
- https://learn.microsoft.com/en-us/rest/api/securityinsights/watchlists
"""

from typing import Iterator
from .client import SentinelClient


class SentinelWatchlistCommands:
    """Watchlist management operations."""

    def __init__(self, client: SentinelClient) -> None:
        self._client = client

    def list_watchlists(self) -> list[dict]:
        """List all watchlists in the workspace."""
        return list(self._client.paginate("watchlists"))

    def get_watchlist(self, alias: str) -> dict:
        """
        Get a watchlist by alias.

        Parameters
        ----------
        alias : str
            Watchlist alias (short name used in KQL).
        """
        return self._client.get(f"watchlists/{alias}")

    def create_watchlist(
        self,
        alias: str,
        display_name: str,
        source: str,
        content_type: str = "text/csv",
        description: str = "",
        number_of_lines_to_skip: int = 1,
        items_search_key: str = "",
    ) -> dict:
        """
        Create a new watchlist.

        Parameters
        ----------
        alias : str
            Unique alias (used in KQL: _GetWatchlist('<alias>')).
        display_name : str
            Human-readable name.
        source : str
            CSV file name.
        content_type : str
            'text/csv' or 'text/tsv'.
        description : str
        number_of_lines_to_skip : int
            Header rows to skip in the CSV.
        items_search_key : str
            Column name to use as the primary key.
        """
        return self._client.put(
            f"watchlists/{alias}",
            body={
                "properties": {
                    "watchlistAlias": alias,
                    "displayName": display_name,
                    "source": source,
                    "contentType": content_type,
                    "description": description,
                    "numberOfLinesToSkip": number_of_lines_to_skip,
                    "itemsSearchKey": items_search_key or alias,
                }
            },
        )

    def delete_watchlist(self, alias: str) -> dict:
        """Delete a watchlist by alias."""
        return self._client.delete(f"watchlists/{alias}")

    def list_watchlist_items(self, alias: str) -> list[dict]:
        """List all items in a watchlist."""
        return list(self._client.paginate(f"watchlists/{alias}/watchlistItems"))

    def add_watchlist_item(
        self,
        alias: str,
        item_data: dict,
    ) -> dict:
        """
        Add a single item to a watchlist.

        Parameters
        ----------
        alias : str
            Watchlist alias.
        item_data : dict
            Key/value dict matching watchlist columns.
        """
        import uuid
        item_id = str(uuid.uuid4())
        return self._client.put(
            f"watchlists/{alias}/watchlistItems/{item_id}",
            body={"properties": {"itemsKeyValue": item_data}},
        )

    def bulk_add_items(
        self,
        alias: str,
        items: list[dict],
    ) -> list[dict]:
        """
        Add multiple items to a watchlist.

        Parameters
        ----------
        alias : str
        items : list[dict]
            List of key/value dicts.

        Returns
        -------
        list[dict]
            Created item responses.
        """
        results = []
        for item in items:
            results.append(self.add_watchlist_item(alias, item))
        return results
