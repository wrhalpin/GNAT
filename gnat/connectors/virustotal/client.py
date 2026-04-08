# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.virustotal.client
======================================

VirusTotal API v3 connector — read-only threat intelligence.

Provides access to file/URL/domain/IP reputation data, malware families,
threat actor attributions, and relationships between entities.

INI config::

    [virustotal]
    host      = https://www.virustotal.com
    api_key   = <vt-api-key>
    auth_type = token

Supported STIX types
--------------------
- ``indicator``    — IPs, domains, URLs, file hashes
- ``malware``      — malware families from engine detections
- ``threat-actor`` — attributed actors from VT relationships

Rate limiting
-------------
VT public API: 4 requests/minute, 500/day.
VT Premium: higher limits; set ``rate_limit_per_minute`` in INI.
The connector respects the ``Retry-After`` header on 429 responses.

References
----------
https://docs.virustotal.com/reference/overview
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class VirusTotalClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the VirusTotal API v3.

    Read-only — VT does not accept writes from the API in standard tiers.

    Parameters
    ----------
    host : str
        API base URL.  Default ``https://www.virustotal.com``.
    api_key : str
        VirusTotal API key.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "files",
        "malware": "collections",
        "threat-actor": "threat_actors",
        "vulnerability": "files",
    }

    # Mapping VT entity type → STIX pattern template
    _PATTERN_MAP: dict[str, str] = {
        "ip_address": "[ipv4-addr:value = '{v}']",
        "domain": "[domain-name:value = '{v}']",
        "url": "[url:value = '{v}']",
        "file": "[file:hashes.'SHA-256' = '{v}']",
    }

    def __init__(self, host: str = "https://www.virustotal.com", api_key: str = "", **kwargs: Any):
        """Initialize VirusTotalClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    def authenticate(self) -> None:
        """Inject the VT API key header."""
        self._auth_headers["x-apikey"] = self._api_key

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        resp = self.get("/api/v3/domains/google.com", params={"fields": "id,type"})
        return isinstance(resp, dict) and "data" in resp

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Retrieve one VT entity.

        ``object_id`` is the raw VT identifier — a hash, domain, IP, or URL.
        For URLs, pass the URL-safe base64-encoded form or the raw URL
        (the connector handles encoding).
        """
        vt_type = self._stix_to_vt_type(stix_type, object_id)
        if vt_type == "urls":
            import base64

            encoded = base64.urlsafe_b64encode(object_id.encode()).decode().rstrip("=")
            resp = self.get(f"/api/v3/urls/{encoded}")
        else:
            resp = self.get(f"/api/v3/{vt_type}/{object_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 40,
    ) -> list[dict[str, Any]]:
        """
        Search VT entities by STIX type.

        ``filters`` supports:
        - ``query`` (str): VT Intelligence search query
          e.g. ``"type:peexe tag:ransomware"``
        - ``cursor`` (str): pagination cursor from previous response
        """
        query = (filters or {}).get("query", "")
        cursor = (filters or {}).get("cursor", "")
        params: dict[str, Any] = {"limit": min(page_size, 300)}
        if query:
            params["query"] = query
        if cursor:
            params["cursor"] = cursor

        # Map STIX type to VT collection endpoint
        endpoint_map = {
            "indicator": "/api/v3/intelligence/search",
            "malware": "/api/v3/collections",
            "threat-actor": "/api/v3/threat_actors",
        }
        endpoint = endpoint_map.get(stix_type, "/api/v3/intelligence/search")
        resp = self.get(endpoint, params=params)

        if not isinstance(resp, dict):
            return []
        data = resp.get("data", [])
        return data if isinstance(data, list) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError(
            "VirusTotal API is read-only — upsert not supported. "
            "Use VT Intelligence to submit files: "
            "https://docs.virustotal.com/reference/files"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("VirusTotal API is read-only — delete not supported.")

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a VT API ``data`` object to a STIX dict.

        Handles files, domains, IPs, URLs, and collections (malware families).
        """
        attrs = native.get("attributes", {})
        vt_id = native.get("id", "")
        vt_type = native.get("type", "file")

        if vt_type in ("domain", "ip_address", "url", "file"):
            return self._entity_to_indicator(native, attrs, vt_id, vt_type)
        if vt_type in ("collection", "threat_actor"):
            return self._collection_to_malware(native, attrs, vt_id)
        # Fallback: generic indicator
        return self._entity_to_indicator(native, attrs, vt_id, "file")

    def _entity_to_indicator(
        self,
        native: dict[str, Any],
        attrs: dict[str, Any],
        vt_id: str,
        vt_type: str,
    ) -> dict[str, Any]:
        """Build an Indicator STIX dict from a VT file/domain/IP/URL."""
        # Determine IOC value and pattern
        if vt_type == "file":
            sha256 = attrs.get("sha256", vt_id)
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
            name = attrs.get("meaningful_name") or sha256[:16]
        elif vt_type == "domain":
            pattern = f"[domain-name:value = '{vt_id}']"
            name = vt_id
        elif vt_type == "ip_address":
            pattern = f"[ipv4-addr:value = '{vt_id}']"
            name = vt_id
        elif vt_type == "url":
            import urllib.parse

            decoded = urllib.parse.unquote(vt_id)
            pattern = f"[url:value = '{decoded}']"
            name = decoded[:80]
        else:
            pattern = f"[domain-name:value = '{vt_id}']"
            name = vt_id

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        confidence = min(100, int((malicious / max(total, 1)) * 100))

        # Target sectors from popular threat categories
        categories = attrs.get("popular_threat_category", {})
        sectors = list({v for v in categories.values() if v}) if categories else []

        return {
            "type": "indicator",
            "id": f"indicator--vt-{vt_id[:36]}",
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": attrs.get("first_submission_date", ""),
            "modified": attrs.get("last_modification_date", ""),
            "confidence": confidence,
            "indicator_types": ["malicious-activity"] if malicious > 0 else ["unknown"],
            "x_source_platform": "virustotal",
            "x_vt_malicious": malicious,
            "x_vt_total": total,
            "x_vt_type": vt_type,
            "x_vt_tags": attrs.get("tags", [])[:10],
            "x_target_sectors": sectors,  # canonical sector field
        }

    def _collection_to_malware(
        self,
        native: dict[str, Any],
        attrs: dict[str, Any],
        vt_id: str,
    ) -> dict[str, Any]:
        """Build a Malware STIX dict from a VT collection/threat_actor."""
        return {
            "type": "malware",
            "id": f"malware--vt-{vt_id[:36]}",
            "name": attrs.get("name", vt_id),
            "description": attrs.get("description", "")[:500],
            "is_family": True,
            "created": attrs.get("creation_date", ""),
            "modified": attrs.get("modification_date", ""),
            "x_source_platform": "virustotal",
            "x_vt_collection_id": vt_id,
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract a VT-queryable identifier from a STIX dict."""
        name = stix_dict.get("name", "")
        pattern = stix_dict.get("pattern", "")
        # Extract hash or domain value from pattern
        import re

        m = re.search(r"= '([^']+)'", pattern)
        return {"id": m.group(1) if m else name}

    @staticmethod
    def _stix_to_vt_type(stix_type: str, object_id: str) -> str:
        """Heuristically map a STIX type + id to a VT endpoint collection."""
        if stix_type == "malware":
            return "collections"
        if stix_type == "threat-actor":
            return "threat_actors"
        # Indicator — infer from id format
        if len(object_id) in (32, 40, 64):
            return "files"  # hash length
        if object_id.startswith(("http://", "https://")):
            return "urls"
        import re

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", object_id):
            return "ip_addresses"
        return "domains"

    # ── Typed entity lookups ──────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up reputation and metadata for an IP address."""
        resp = self.get(f"/api/v3/ip_addresses/{ip}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Look up reputation and metadata for a domain."""
        resp = self.get(f"/api/v3/domains/{domain}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """
        Look up a file by hash (MD5, SHA-1, or SHA-256).

        Returns full file analysis attributes including scan results.
        """
        resp = self.get(f"/api/v3/files/{file_hash}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_url(self, url: str) -> dict[str, Any]:
        """
        Look up a URL.

        Accepts a raw URL; the connector handles URL-safe base64 encoding.
        """
        import base64
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = self.get(f"/api/v3/urls/{encoded}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── File analysis ─────────────────────────────────────────────────────────────

    def get_file_behaviors(self, file_hash: str) -> list[dict[str, Any]]:
        """
        Retrieve sandbox behaviour reports for a file.

        Returns a list of behaviour summary objects, one per sandbox.
        """
        resp = self.get(f"/api/v3/files/{file_hash}/behaviours")
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    def get_file_sigma_analysis(self, file_hash: str) -> dict[str, Any]:
        """Get Sigma rule analysis results for a file."""
        resp = self.get(f"/api/v3/files/{file_hash}/sigma_analysis")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def rescan_file(self, file_hash: str) -> dict[str, Any]:
        """
        Request a rescan of an already-submitted file.

        Queues the file for re-analysis by all VT engines.
        """
        resp = self.post(f"/api/v3/files/{file_hash}/analyse")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── Entity relationships ──────────────────────────────────────────────────────

    def get_entity_relationships(
        self,
        entity_type: str,
        entity_id: str,
        relationship: str,
        limit: int = 40,
        cursor: str = "",
    ) -> list[dict[str, Any]]:
        """
        Fetch related objects for a VT entity.

        Parameters
        ----------
        entity_type : str
            VT collection name: ``"files"``, ``"domains"``, ``"ip_addresses"``, ``"urls"``.
        entity_id : str
            VT entity identifier (hash, domain, IP, or URL-safe base64 URL).
        relationship : str
            Relationship name, e.g. ``"contacted_ips"``, ``"communicating_files"``,
            ``"resolutions"``, ``"related_threat_actors"``.
        """
        params: dict[str, Any] = {"limit": min(limit, 40)}
        if cursor:
            params["cursor"] = cursor
        resp = self.get(f"/api/v3/{entity_type}/{entity_id}/{relationship}", params=params)
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    def get_ip_resolutions(self, ip: str, limit: int = 40) -> list[dict[str, Any]]:
        """List passive DNS resolutions for an IP address."""
        return self.get_entity_relationships("ip_addresses", ip, "resolutions", limit=limit)

    def get_domain_resolutions(self, domain: str, limit: int = 40) -> list[dict[str, Any]]:
        """List passive DNS resolutions for a domain."""
        return self.get_entity_relationships("domains", domain, "resolutions", limit=limit)

    def get_domain_subdomains(self, domain: str, limit: int = 40) -> list[dict[str, Any]]:
        """List known subdomains of a domain."""
        return self.get_entity_relationships("domains", domain, "subdomains", limit=limit)

    def get_file_contacted_ips(self, file_hash: str, limit: int = 40) -> list[dict[str, Any]]:
        """List IPs contacted by a file during sandbox execution."""
        return self.get_entity_relationships("files", file_hash, "contacted_ips", limit=limit)

    def get_file_contacted_domains(self, file_hash: str, limit: int = 40) -> list[dict[str, Any]]:
        """List domains contacted by a file during sandbox execution."""
        return self.get_entity_relationships("files", file_hash, "contacted_domains", limit=limit)

    def get_file_dropped_files(self, file_hash: str, limit: int = 40) -> list[dict[str, Any]]:
        """List files dropped by a file during sandbox execution."""
        return self.get_entity_relationships("files", file_hash, "dropped_files", limit=limit)

    # ── Intelligence search ───────────────────────────────────────────────────────

    def search_intelligence(
        self,
        query: str,
        limit: int = 20,
        cursor: str = "",
        order: str = "",
    ) -> list[dict[str, Any]]:
        """
        Search VT Intelligence (requires premium subscription).

        Uses the VT query language, e.g.::

            "type:peexe tag:ransomware fs:2024-01-01+ size:1MB-"

        Returns a list of file data objects.
        """
        params: dict[str, Any] = {"query": query, "limit": min(limit, 300)}
        if cursor:
            params["cursor"] = cursor
        if order:
            params["order"] = order
        resp = self.get("/api/v3/intelligence/search", params=params)
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    # ── Comments ──────────────────────────────────────────────────────────────────

    def get_comments(
        self,
        entity_type: str,
        entity_id: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Get community comments on a VT entity.

        ``entity_type`` is one of ``"files"``, ``"urls"``, ``"domains"``,
        ``"ip_addresses"``.
        """
        resp = self.get(f"/api/v3/{entity_type}/{entity_id}/comments", params={"limit": limit})
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    def add_comment(
        self,
        entity_type: str,
        entity_id: str,
        comment_text: str,
    ) -> dict[str, Any]:
        """Post a community comment on a VT entity."""
        resp = self.post(
            f"/api/v3/{entity_type}/{entity_id}/comments",
            json={"data": {"type": "comment", "attributes": {"text": comment_text}}},
        )
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── Votes ─────────────────────────────────────────────────────────────────────

    def add_vote(
        self,
        entity_type: str,
        entity_id: str,
        verdict: str,
    ) -> dict[str, Any]:
        """
        Add a vote on a VT entity.

        ``verdict`` must be ``"malicious"`` or ``"harmless"``.
        ``entity_type`` is one of ``"files"``, ``"urls"``, ``"domains"``,
        ``"ip_addresses"``.
        """
        resp = self.post(
            f"/api/v3/{entity_type}/{entity_id}/votes",
            json={"data": {"type": "vote", "attributes": {"verdict": verdict}}},
        )
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── Hunting rulesets ──────────────────────────────────────────────────────────

    def list_hunting_rulesets(self, limit: int = 20) -> list[dict[str, Any]]:
        """List YARA hunting rulesets (requires VT Premium)."""
        resp = self.get("/api/v3/intelligence/hunting_rulesets", params={"limit": limit})
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    def get_hunting_ruleset(self, ruleset_id: str) -> dict[str, Any]:
        """Retrieve a single hunting ruleset by ID."""
        resp = self.get(f"/api/v3/intelligence/hunting_rulesets/{ruleset_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def create_hunting_ruleset(
        self,
        name: str,
        rules: str,
        enabled: bool = True,
        notification_emails: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new YARA hunting ruleset.

        ``rules`` is a raw YARA rule string.
        """
        attrs: dict[str, Any] = {"name": name, "rules": rules, "enabled": enabled}
        if notification_emails:
            attrs["notification_emails"] = notification_emails
        resp = self.post(
            "/api/v3/intelligence/hunting_rulesets",
            json={"data": {"type": "hunting_ruleset", "attributes": attrs}},
        )
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def delete_hunting_ruleset(self, ruleset_id: str) -> None:
        """Delete a hunting ruleset by ID."""
        self.delete(f"/api/v3/intelligence/hunting_rulesets/{ruleset_id}")

    # ── Collections (malware families) ───────────────────────────────────────────

    def get_collection(self, collection_id: str) -> dict[str, Any]:
        """Retrieve a VT collection (malware family) by ID."""
        resp = self.get(f"/api/v3/collections/{collection_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def get_collection_files(self, collection_id: str, limit: int = 40) -> list[dict[str, Any]]:
        """List files associated with a VT collection."""
        return self.get_entity_relationships("collections", collection_id, "files", limit=limit)

    # ── Threat actors ─────────────────────────────────────────────────────────────

    def get_threat_actor(self, actor_id: str) -> dict[str, Any]:
        """Retrieve a VT threat actor profile."""
        resp = self.get(f"/api/v3/threat_actors/{actor_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_threat_actors(self, limit: int = 20, cursor: str = "") -> list[dict[str, Any]]:
        """List VT threat actor profiles."""
        params: dict[str, Any] = {"limit": min(limit, 20)}
        if cursor:
            params["cursor"] = cursor
        resp = self.get("/api/v3/threat_actors", params=params)
        data = resp.get("data", []) if isinstance(resp, dict) else []
        return data if isinstance(data, list) else []

    def get_threat_actor_relationships(
        self,
        actor_id: str,
        relationship: str = "related_threat_actors",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List relationships for a threat actor (e.g. related_malware_families, related_files)."""
        return self.get_entity_relationships("threat_actors", actor_id, relationship, limit=limit)
