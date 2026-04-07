# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.qradar.log_sources
========================================
Log source inventory commands for the QRadar connector.

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-configuration-event-sources
"""

from .client import QRadarClient

_LS_BASE = "config/event_sources/log_source_management"


class QRadarLogSourceCommands:
    """
    Log source inventory operations.

    Parameters
    ----------
    client : QRadarClient
        Authenticated HTTP client.
    """

    def __init__(self, client: QRadarClient) -> None:
        """Initialize QRadarLogSourceCommands."""
        self._client = client

    def list_log_sources(
        self,
        filter_val: str | None = None,
        fields: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List configured log sources.

        Parameters
        ----------
        filter_val : str | None
            Filter expression, e.g. ``"enabled=true"``.
        fields : str | None
            Fields to return.
        limit : int | None
            Max results.

        Returns
        -------
        list[dict]
            Log source records.
        """
        params: dict = {}
        if filter_val:
            params["filter"] = filter_val
        if fields:
            params["fields"] = fields

        items = []
        for item in self._client.paginate(f"{_LS_BASE}/log_sources", params=params):
            items.append(item)
            if limit and len(items) >= limit:
                break
        return items

    def get_log_source(self, log_source_id: int) -> dict:
        """Retrieve a single log source by ID."""
        return self._client.get(f"{_LS_BASE}/log_sources/{log_source_id}")

    def list_log_source_types(self) -> list[dict]:
        """List all log source type definitions (DSM parsers)."""
        return list(self._client.paginate(f"{_LS_BASE}/log_source_types"))

    def get_log_source_count(self, filter_val: str | None = None) -> int:
        """Return the total number of configured log sources."""
        params = {"filter": filter_val} if filter_val else None
        return self._client.get_total_count(f"{_LS_BASE}/log_sources", params=params)
