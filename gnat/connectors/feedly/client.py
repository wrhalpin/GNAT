"""
gnat.connectors.feedly.client
==================================

Feedly Threat Intelligence connector (Feedly AI / Leo API).

Authentication
--------------
Bearer token via ``Authorization: Bearer <token>`` header::

    [feedly]
    host      = https://api.feedly.com
    api_token = <access-token>
    auth_type = token

Feedly access tokens are obtained via the OAuth2 authorization-code flow
in the browser (Feedly Developer portal) and stored as long-lived tokens.
Client-credentials flow is available for Feedly for Teams.

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | Feedly Resource                  |
+====================+==================================+
| indicator          | entity / threat-indicator        |
+--------------------+----------------------------------+
| threat-actor       | entity (threat-actor type)       |
+--------------------+----------------------------------+
| malware            | entity (malware type)            |
+--------------------+----------------------------------+
| attack-pattern     | entity (attack-pattern / TTP)    |
+--------------------+----------------------------------+
| vulnerability      | entity (cve type)                |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``/v3/enterprise/iocFeed``   — deduplicated IOC feed (IPs, domains, hashes)
* ``/v3/enterprise/ttpFeed``   — MITRE ATT&CK TTP feed
* ``/v3/enterprise/cvesFeed``  — CVE / vulnerability feed
* ``/v3/search/feeds``         — search for topic streams
* ``/v3/streams/{id}/contents``— article stream for a feed or board

Notes
-----
* Feedly is **read-only** — IOCs, TTPs, and CVEs are fetched, not written.
* ``iocFeed``, ``ttpFeed``, and ``cvesFeed`` require Feedly for Enterprise.
* The ``newer_than`` parameter is a Unix timestamp in milliseconds.
"""

from __future__ import annotations

import time
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class FeedlyClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Feedly AI / Enterprise REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.feedly.com"``.
    api_token : str
        Feedly access token.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "iocFeed",
        "threat-actor": "ttpFeed",
        "malware": "ttpFeed",
        "attack-pattern": "ttpFeed",
        "vulnerability": "cvesFeed",
    }

    # Feedly entity type → STIX pattern
    _IOC_PATTERN: dict[str, str] = {
        "ip-src": "[ipv4-addr:value = '{v}']",
        "ip-dst": "[ipv4-addr:value = '{v}']",
        "url": "[url:value = '{v}']",
        "domain": "[domain-name:value = '{v}']",
        "md5": "[file:hashes.MD5 = '{v}']",
        "sha1": "[file:hashes.SHA-1 = '{v}']",
        "sha256": "[file:hashes.SHA-256 = '{v}']",
        "email": "[email-addr:value = '{v}']",
    }

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the Feedly Bearer token."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_token}"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the Feedly profile endpoint."""
        self.get("/v3/profile")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a Feedly entity by id.

        Parameters
        ----------
        object_id : str
            Feedly entity id (URL-encoded ``feedly/`` prefix format).
        """
        return self.get(f"/v3/entities/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch from the appropriate Feedly enterprise feed.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:

            * ``newer_than`` — Unix ms timestamp (default: last 24h)
            * ``count``      — overrides *page_size*
            * ``streamId``   — Feedly stream/board id for article streams
        """
        filters = dict(filters or {})
        count = filters.pop("count", page_size)

        if stix_type in ("indicator",):
            return self.get_ioc_feed(
                newer_than=filters.pop("newer_than", None),
                count=count,
            )
        if stix_type in ("threat-actor", "malware", "attack-pattern"):
            return self.get_ttp_feed(
                newer_than=filters.pop("newer_than", None),
                count=count,
            )
        if stix_type == "vulnerability":
            return self.get_cve_feed(
                newer_than=filters.pop("newer_than", None),
                count=count,
            )
        raise GNATClientError(f"Feedly: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Feedly is read-only — object creation is not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Feedly is read-only — object deletion is not supported.")

    # ── Domain-specific operations ────────────────────────────────────────

    def get_ioc_feed(
        self,
        newer_than: int | None = None,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch deduplicated IOC entries from the Feedly Enterprise IOC feed.

        Parameters
        ----------
        newer_than : int, optional
            Unix timestamp in milliseconds.  Defaults to 24 hours ago.
        count : int
            Maximum entries to return.  Default 100.

        Returns
        -------
        list of dict
            Each entry contains ``type``, ``value``, ``sources``,
            ``confidence``, ``first_seen``, ``last_seen``.
        """
        if newer_than is None:
            newer_than = int((time.time() - 86400) * 1000)
        resp = self.get(
            "/v3/enterprise/iocFeed",
            params={"newerThan": newer_than, "count": count},
        )
        return resp.get("indicators", []) if isinstance(resp, dict) else []

    def get_ttp_feed(
        self,
        newer_than: int | None = None,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch MITRE ATT&CK TTP entries from the Feedly Enterprise TTP feed.

        Returns
        -------
        list of dict
            Each entry contains ``type``, ``name``, ``mitre_id``,
            ``description``, ``sources``, ``first_seen``.
        """
        if newer_than is None:
            newer_than = int((time.time() - 86400) * 1000)
        resp = self.get(
            "/v3/enterprise/ttpFeed",
            params={"newerThan": newer_than, "count": count},
        )
        return resp.get("ttps", []) if isinstance(resp, dict) else []

    def get_cve_feed(
        self,
        newer_than: int | None = None,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Fetch CVE entries from the Feedly Enterprise CVE feed.

        Returns
        -------
        list of dict
            Each entry contains ``cve_id``, ``cvss_score``,
            ``description``, ``affected_products``, ``sources``.
        """
        if newer_than is None:
            newer_than = int((time.time() - 86400) * 1000)
        resp = self.get(
            "/v3/enterprise/cvesFeed",
            params={"newerThan": newer_than, "count": count},
        )
        return resp.get("cves", []) if isinstance(resp, dict) else []

    def get_articles(
        self,
        stream_id: str,
        newer_than: int | None = None,
        count: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Fetch articles from a Feedly stream or board.

        Parameters
        ----------
        stream_id : str
            URL-encoded Feedly stream id, e.g.
            ``"feed/https://feeds.feedburner.com/TheHackersNews"``.
        newer_than : int, optional
            Unix ms timestamp to paginate from.
        count : int
            Articles to return.

        Returns
        -------
        list of dict
            Article entries with ``title``, ``summary``, ``published``,
            ``alternate`` (URL), ``entities`` (AI-extracted entities).
        """
        params: dict[str, Any] = {"count": count}
        if newer_than:
            params["newerThan"] = newer_than
        import urllib.parse

        encoded = urllib.parse.quote(stream_id, safe="")
        resp = self.get(f"/v3/streams/{encoded}/contents", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def search_feeds(self, query: str, count: int = 20) -> list[dict[str, Any]]:
        """
        Search for Feedly feeds matching a topic.

        Parameters
        ----------
        query : str
            Search query, e.g. ``"threat intelligence APT"``.
        count : int
            Maximum results.

        Returns
        -------
        list of dict
            Feed descriptors with ``feedId``, ``title``, ``subscribers``.
        """
        resp = self.get(
            "/v3/search/feeds",
            params={"query": query, "count": count},
        )
        return resp.get("results", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Feedly IOC, TTP, or CVE entry to STIX 2.1.

        Dispatches on presence of ``cve_id`` (CVE), ``mitre_id`` (TTP),
        or ``value`` (IOC).
        """
        data = native.get("data", native)

        # CVE entry
        if "cve_id" in data:
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{data.get('id', data.get('cve_id', ''))}",
                "name": data.get("cve_id", ""),
                "description": data.get("description", ""),
                "created": self._ms_to_iso(data.get("first_seen")),
                "modified": self._ms_to_iso(data.get("last_seen")),
                "x_cvss_score": data.get("cvss_score"),
                "x_feedly_sources": [s.get("title", "") for s in data.get("sources", [])],
            }

        # TTP entry
        if "mitre_id" in data or data.get("type") in ("attack-pattern", "threat-actor", "malware"):
            stix_type = data.get("type", "attack-pattern")
            ttp: dict[str, Any] = {
                "type": stix_type,
                "id": f"{stix_type}--{data.get('id', '')}",
                "name": data.get("name", ""),
                "description": data.get("description", ""),
                "created": self._ms_to_iso(data.get("first_seen")),
                "modified": self._ms_to_iso(data.get("last_seen")),
                "x_mitre_id": data.get("mitre_id", ""),
                "x_feedly_sources": [s.get("title", "") for s in data.get("sources", [])],
                "confidence": data.get("confidence", 50),
            }
            # Feedly Enterprise threat-intel entities carry a `sectors` list
            # of industry vertical strings on threat-actor and attack-pattern
            # entries (e.g. ["Healthcare", "Financial Services"]).
            sectors = data.get("sectors", [])
            if isinstance(sectors, list) and sectors:
                ttp["x_target_sectors"] = sectors
            return ttp

        # IOC entry (default)
        ioc_type = data.get("type", "")
        value = data.get("value", "")
        pattern_tmpl = self._IOC_PATTERN.get(ioc_type, "[unknown:value = '{v}']")
        pattern = pattern_tmpl.format(v=value.replace("'", "\\'"))

        return {
            "type": "indicator",
            "id": f"indicator--{data.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": self._ms_to_iso(data.get("first_seen")),
            "modified": self._ms_to_iso(data.get("last_seen")),
            "indicator_types": ["malicious-activity"],
            "confidence": data.get("confidence", 50),
            "x_feedly_type": ioc_type,
            "x_feedly_sources": [s.get("title", "") for s in data.get("sources", [])],
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Feedly is read-only — from_stix returns an informational dict."""
        return {
            "note": "Feedly is read-only. No write API available.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _ms_to_iso(ms: int | None) -> str:
        """Convert Unix milliseconds to ISO 8601 string."""
        if not ms:
            return ""
        from datetime import datetime, timezone

        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()

    # ── User profile & preferences ────────────────────────────────────────────

    def get_profile(self) -> dict[str, Any]:
        """Retrieve the authenticated Feedly user profile."""
        resp = self.get("/v3/profile")
        return resp if isinstance(resp, dict) else {}

    def update_profile(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update user profile fields (locale, country, etc.)."""
        resp = self.post("/v3/profile", json=updates)
        return resp if isinstance(resp, dict) else {}

    # ── Subscriptions ─────────────────────────────────────────────────────────

    def list_subscriptions(self) -> list[dict[str, Any]]:
        """List all feed subscriptions for the authenticated user."""
        resp = self.get("/v3/subscriptions")
        return resp if isinstance(resp, list) else []

    def subscribe_to_feed(
        self,
        feed_id: str,
        title: str = "",
        categories: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Subscribe to a feed.

        Parameters
        ----------
        feed_id : str
            Feedly feed ID, e.g. ``"feed/https://example.com/rss"``.
        title : str, optional
            Custom display title for the subscription.
        categories : list of dict, optional
            Categories to assign, e.g. ``[{"id": "category/...", "label": "Security"}]``.
        """
        payload: dict[str, Any] = {"id": feed_id}
        if title:
            payload["title"] = title
        if categories:
            payload["categories"] = categories
        resp = self.post("/v3/subscriptions", json=payload)
        return resp if isinstance(resp, dict) else {}

    def unsubscribe_from_feed(self, feed_id: str) -> None:
        """Remove a feed subscription."""
        import urllib.parse as _up
        encoded = _up.quote(feed_id, safe="")
        self.delete(f"/v3/subscriptions/{encoded}")

    # ── Boards ────────────────────────────────────────────────────────────────

    def list_boards(self) -> list[dict[str, Any]]:
        """List all boards (collections of saved articles) for the user."""
        resp = self.get("/v3/boards")
        return resp if isinstance(resp, list) else []

    def get_board(self, board_id: str) -> dict[str, Any]:
        """Retrieve a board by ID."""
        import urllib.parse as _up
        encoded = _up.quote(board_id, safe="")
        resp = self.get(f"/v3/boards/{encoded}")
        return resp if isinstance(resp, dict) else {}

    def create_board(self, label: str, description: str = "") -> dict[str, Any]:
        """Create a new board with the given label."""
        payload: dict[str, Any] = {"label": label}
        if description:
            payload["description"] = description
        resp = self.post("/v3/boards", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_board(self, board_id: str) -> None:
        """Delete a board by ID."""
        import urllib.parse as _up
        encoded = _up.quote(board_id, safe="")
        self.delete(f"/v3/boards/{encoded}")

    def get_board_contents(
        self,
        board_id: str,
        count: int = 20,
        newer_than: int | None = None,
        continuation: str = "",
    ) -> dict[str, Any]:
        """
        Fetch articles saved to a board.

        Returns a dict with ``items`` (list) and optional ``continuation`` cursor.
        """
        import urllib.parse as _up
        encoded = _up.quote(board_id, safe="")
        params: dict[str, Any] = {"count": count}
        if newer_than:
            params["newerThan"] = newer_than
        if continuation:
            params["continuation"] = continuation
        resp = self.get(f"/v3/boards/{encoded}/contents", params=params)
        return resp if isinstance(resp, dict) else {}

    def save_article_to_board(self, board_id: str, entry_id: str) -> None:
        """Save an article (entry) to a board."""
        import urllib.parse as _up
        encoded = _up.quote(board_id, safe="")
        self.put(f"/v3/boards/{encoded}/entries/{entry_id}")

    def remove_article_from_board(self, board_id: str, entry_id: str) -> None:
        """Remove an article from a board."""
        import urllib.parse as _up
        encoded = _up.quote(board_id, safe="")
        self.delete(f"/v3/boards/{encoded}/entries/{entry_id}")

    # ── Streams ───────────────────────────────────────────────────────────────

    def get_stream_contents(
        self,
        stream_id: str,
        count: int = 20,
        newer_than: int | None = None,
        continuation: str = "",
        ranked: str = "newest",
        unread_only: bool = False,
    ) -> dict[str, Any]:
        """
        Fetch contents of a stream (feed, board, category, or enterprise feed).

        Returns a dict with ``items`` and optional ``continuation`` pagination cursor.

        Parameters
        ----------
        stream_id : str
            URL-encoded Feedly stream ID.
        ranked : str
            Sort order: ``"newest"`` (default) or ``"oldest"``.
        unread_only : bool
            Filter to unread articles only.
        """
        import urllib.parse as _up
        encoded = _up.quote(stream_id, safe="")
        params: dict[str, Any] = {"count": count, "ranked": ranked}
        if newer_than:
            params["newerThan"] = newer_than
        if continuation:
            params["continuation"] = continuation
        if unread_only:
            params["unreadOnly"] = "true"
        resp = self.get(f"/v3/streams/{encoded}/contents", params=params)
        return resp if isinstance(resp, dict) else {}

    def get_stream_ids(
        self,
        stream_id: str,
        count: int = 20,
        newer_than: int | None = None,
        continuation: str = "",
        unread_only: bool = False,
    ) -> dict[str, Any]:
        """Fetch only article IDs from a stream (lightweight, no content)."""
        import urllib.parse as _up
        encoded = _up.quote(stream_id, safe="")
        params: dict[str, Any] = {"count": count}
        if newer_than:
            params["newerThan"] = newer_than
        if continuation:
            params["continuation"] = continuation
        if unread_only:
            params["unreadOnly"] = "true"
        resp = self.get(f"/v3/streams/{encoded}/ids", params=params)
        return resp if isinstance(resp, dict) else {}

    # ── Individual articles ───────────────────────────────────────────────────

    def get_article(self, entry_id: str) -> dict[str, Any]:
        """Fetch a single article by Feedly entry ID."""
        import urllib.parse as _up
        encoded = _up.quote(entry_id, safe="")
        resp = self.get(f"/v3/entries/{encoded}")
        return resp if isinstance(resp, dict) else {}

    def get_articles_batch(self, entry_ids: list[str]) -> list[dict[str, Any]]:
        """Fetch multiple articles by ID in one request (max 1000)."""
        resp = self.post("/v3/entries/.mget", json=entry_ids[:1000])
        return resp if isinstance(resp, list) else []

    def mark_articles_as_read(
        self, entry_ids: list[str] | None = None, feed_ids: list[str] | None = None
    ) -> None:
        """Mark articles as read by entry ID list or feed ID list."""
        payload: dict[str, Any] = {"action": "markAsRead"}
        if entry_ids:
            payload["entryIds"] = entry_ids
        if feed_ids:
            payload["feedIds"] = feed_ids
        self.post("/v3/markers", json=payload)

    # ── Tags ──────────────────────────────────────────────────────────────────

    def list_tags(self) -> list[dict[str, Any]]:
        """List all tags (user-defined labels) for the authenticated user."""
        resp = self.get("/v3/tags")
        return resp if isinstance(resp, list) else []

    def tag_entries(self, tag_id: str, entry_ids: list[str]) -> None:
        """Apply a tag to one or more entries."""
        import urllib.parse as _up
        encoded = _up.quote(tag_id, safe="")
        self.put(f"/v3/tags/{encoded}", json={"entryIds": entry_ids})

    def untag_entry(self, tag_id: str, entry_id: str) -> None:
        """Remove a tag from an entry."""
        import urllib.parse as _up
        t_enc = _up.quote(tag_id, safe="")
        e_enc = _up.quote(entry_id, safe="")
        self.delete(f"/v3/tags/{t_enc}/{e_enc}")

    def delete_tag(self, tag_id: str) -> None:
        """Delete a tag entirely."""
        import urllib.parse as _up
        encoded = _up.quote(tag_id, safe="")
        self.delete(f"/v3/tags/{encoded}")

    # ── AI entity search ──────────────────────────────────────────────────────

    def search_entities(
        self,
        query: str,
        entity_type: str = "",
        count: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search Feedly's AI-extracted entity catalogue.

        Parameters
        ----------
        query : str
            Entity name or keyword.
        entity_type : str, optional
            Filter by entity type: ``"IP"``, ``"FileHash"``, ``"Malware"``,
            ``"AttackPattern"``, ``"Vulnerability"``, etc.
        """
        params: dict[str, Any] = {"query": query, "count": count}
        if entity_type:
            params["type"] = entity_type
        resp = self.get("/v3/search/entities", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def get_entity(self, entity_id: str) -> dict[str, Any]:
        """
        Retrieve full metadata for a specific Feedly entity.

        ``entity_id`` is the URL-encoded Feedly entity identifier,
        e.g. ``"nlp/f/entity/nlp%2Ff%2Fentity%2FKEXzSA..."``.
        """
        import urllib.parse as _up
        encoded = _up.quote(entity_id, safe="")
        resp = self.get(f"/v3/entities/{encoded}")
        return resp if isinstance(resp, dict) else {}

    def get_entity_articles(
        self,
        entity_id: str,
        count: int = 20,
        newer_than: int | None = None,
    ) -> list[dict[str, Any]]:
        """List articles mentioning a specific Feedly AI entity."""
        import urllib.parse as _up
        encoded = _up.quote(entity_id, safe="")
        params: dict[str, Any] = {"count": count}
        if newer_than:
            params["newerThan"] = newer_than
        resp = self.get(f"/v3/entities/{encoded}/articles", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    # ── Leo (AI) alerts ───────────────────────────────────────────────────────

    def get_ai_alerts(
        self,
        newer_than: int | None = None,
        count: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Retrieve AI-generated threat intelligence alerts from Feedly Leo.

        Requires Feedly for Enterprise.  Returns alert summaries with
        related articles, entities, and confidence scores.
        """
        if newer_than is None:
            newer_than = int((time.time() - 86400) * 1000)
        resp = self.get(
            "/v3/enterprise/alerts",
            params={"newerThan": newer_than, "count": count},
        )
        return resp.get("alerts", []) if isinstance(resp, dict) else []

    def get_threat_landscape(self) -> dict[str, Any]:
        """
        Retrieve the Feedly Enterprise threat landscape digest.

        Returns a summary of trending TTPs, adversaries, and vulnerabilities
        seen across monitored sources over the past 7 days.
        """
        resp = self.get("/v3/enterprise/threatLandscape")
        return resp if isinstance(resp, dict) else {}

    # ── OPML export ───────────────────────────────────────────────────────────

    def export_opml(self) -> str:
        """
        Export all subscriptions as an OPML document.

        Returns the raw OPML XML string.
        """
        resp = self.get("/v3/opml")
        return str(resp) if resp else ""
