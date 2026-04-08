# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.feeds
================================
Feed management commands for the MISP connector.

MISP Feeds are configured IOC feed subscriptions. MISP fetches feed
data on a schedule and integrates it into the local event database.
Feeds can be free (CIRCL, Abuse.ch, etc.) or commercial.

References
----------
- https://www.misp-project.org/openapi/#tag/Feeds
"""

from .client import MISPClient


class MISPFeedCommands:
    """Feed management operations."""

    def __init__(self, client: MISPClient) -> None:
        """Initialize MISPFeedCommands."""
        self._client = client

    def list_feeds(self) -> list[dict]:
        """List all configured feeds."""
        response = self._client.get_json("feeds/index")
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return response.get("Feed", [])
        return []

    def get_feed(self, feed_id: int) -> dict:
        """Retrieve a single feed by ID."""
        response = self._client.get_json(f"feeds/view/{feed_id}")
        if isinstance(response, dict):
            return response.get("Feed", response)
        return response

    def enable_feed(self, feed_id: int) -> dict:
        """Enable a feed (start pulling on schedule)."""
        response = self._client.post_json(f"feeds/enable/{feed_id}")
        if isinstance(response, dict):
            return response.get("Feed", response)
        return response

    def disable_feed(self, feed_id: int) -> dict:
        """Disable a feed."""
        response = self._client.post_json(f"feeds/disable/{feed_id}")
        if isinstance(response, dict):
            return response.get("Feed", response)
        return response

    def fetch_feed(self, feed_id: int) -> dict:
        """
        Trigger an immediate fetch of a feed.

        Parameters
        ----------
        feed_id : int
            Feed ID.

        Returns
        -------
        dict
            Job/task response.
        """
        return self._client.get_json(f"feeds/fetchFromFeed/{feed_id}")

    def fetch_all_feeds(self) -> dict:
        """Trigger an immediate fetch of all enabled feeds."""
        return self._client.get_json("feeds/fetchFromAllFeeds")

    def cache_feed(self, feed_id: int) -> dict:
        """Cache a feed locally for overlap detection."""
        return self._client.get_json(f"feeds/cacheFeeds/{feed_id}")
