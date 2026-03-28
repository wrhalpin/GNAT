"""
gnat.connectors.qradar.assets
===================================
Asset management commands for the QRadar connector.

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-asset-model
"""

from .client import QRadarClient


class QRadarAssetCommands:
    """
    Asset inventory operations.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        self._client = client

    def list_assets(
        self,
        filter: str | None = None,
        fields: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List assets in the QRadar asset database.

        Parameters
        ----------
        filter : str | None
            QRadar filter expression.
        fields : str | None
            Comma-separated fields to return.
        limit : int | None
            Max assets to return.

        Returns
        -------
        list[dict]
            Asset records.
        """
        params: dict = {}
        if filter:
            params["filter"] = filter
        if fields:
            params["fields"] = fields

        items = []
        for item in self._client.paginate("asset_model/assets", params=params):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def get_asset(self, asset_id: int) -> dict:
        """
        Retrieve a single asset by ID.

        Parameters
        ----------
        asset_id : int
            Asset integer ID.

        Returns
        -------
        dict
            Asset record.
        """
        return self._client.get(f"asset_model/assets/{asset_id}")

    def search_by_ip(self, ip: str) -> list[dict]:
        """
        Find assets by IP address.

        Parameters
        ----------
        ip : str
            IPv4 or IPv6 address.

        Returns
        -------
        list[dict]
            Matching asset records.
        """
        return self.list_assets(
            filter=f"interfaces contains (ip_addresses contains (value='{ip}'))"
        )

    def list_properties(self) -> list[dict]:
        """List available asset property definitions."""
        return list(self._client.paginate("asset_model/properties"))

    def list_saved_searches(self) -> list[dict]:
        """List saved asset searches."""
        return list(self._client.paginate("asset_model/saved_searches"))
