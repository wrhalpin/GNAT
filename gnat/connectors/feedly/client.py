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
        "indicator":      "iocFeed",
        "threat-actor":   "ttpFeed",
        "malware":        "ttpFeed",
        "attack-pattern": "ttpFeed",
        "vulnerability":  "cvesFeed",
    }

    # Feedly entity type → STIX pattern
    _IOC_PATTERN: dict[str, str] = {
        "ip-src":  "[ipv4-addr:value = '{v}']",
        "ip-dst":  "[ipv4-addr:value = '{v}']",
        "url":     "[url:value = '{v}']",
        "domain":  "[domain-name:value = '{v}']",
        "md5":     "[file:hashes.MD5 = '{v}']",
        "sha1":    "[file:hashes.SHA-1 = '{v}']",
        "sha256":  "[file:hashes.SHA-256 = '{v}']",
        "email":   "[email-addr:value = '{v}']",
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
        count   = filters.pop("count", page_size)

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
        raise GNATClientError(
            "Feedly is read-only — object creation is not supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError(
            "Feedly is read-only — object deletion is not supported."
        )

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
        resp    = self.get(f"/v3/streams/{encoded}/contents", params=params)
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
                "type":            "vulnerability",
                "id":              f"vulnerability--{data.get('id', data.get('cve_id', ''))}",
                "name":            data.get("cve_id", ""),
                "description":     data.get("description", ""),
                "created":         self._ms_to_iso(data.get("first_seen")),
                "modified":        self._ms_to_iso(data.get("last_seen")),
                "x_cvss_score":    data.get("cvss_score"),
                "x_feedly_sources": [s.get("title", "") for s in data.get("sources", [])],
            }

        # TTP entry
        if "mitre_id" in data or data.get("type") in (
            "attack-pattern", "threat-actor", "malware"
        ):
            stix_type = data.get("type", "attack-pattern")
            ttp: dict[str, Any] = {
                "type":         stix_type,
                "id":           f"{stix_type}--{data.get('id', '')}",
                "name":         data.get("name", ""),
                "description":  data.get("description", ""),
                "created":      self._ms_to_iso(data.get("first_seen")),
                "modified":     self._ms_to_iso(data.get("last_seen")),
                "x_mitre_id":   data.get("mitre_id", ""),
                "x_feedly_sources": [s.get("title", "") for s in data.get("sources", [])],
                "confidence":   data.get("confidence", 50),
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
        value    = data.get("value", "")
        pattern_tmpl = self._IOC_PATTERN.get(
            ioc_type, "[unknown:value = '{v}']"
        )
        pattern = pattern_tmpl.format(v=value.replace("'", "\\'"))

        return {
            "type":            "indicator",
            "id":              f"indicator--{data.get('id', '')}",
            "name":            value,
            "pattern":         pattern,
            "pattern_type":    "stix",
            "created":         self._ms_to_iso(data.get("first_seen")),
            "modified":        self._ms_to_iso(data.get("last_seen")),
            "indicator_types": ["malicious-activity"],
            "confidence":      data.get("confidence", 50),
            "x_feedly_type":   ioc_type,
            "x_feedly_sources": [
                s.get("title", "") for s in data.get("sources", [])
            ],
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
