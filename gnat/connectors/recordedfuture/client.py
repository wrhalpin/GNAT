# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.recordedfuture.client
==========================================

Recorded Future Connect API connector.

INI config::

    [recordedfuture]
    host      = https://api.recordedfuture.com
    api_token = <token>
    auth_type = token
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class RecordedFutureClient(BaseClient, ConnectorMixin):
    """HTTP client for the Recorded Future Connect API v2."""

    stix_type_map: dict[str, str] = {
        "indicator": "ip",
        "malware": "malware",
        "threat-actor": "threat-actor",
        "vulnerability": "vulnerability",
    }

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        """Initialize RecordedFutureClient."""
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    def authenticate(self) -> None:
        """Inject the RF API token header."""
        self._auth_headers["X-RFToken"] = self._api_token

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        self.get("/v2/ip/search", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        resource = self.stix_type_map.get(stix_type, stix_type)
        resp = self.get(
            f"/v2/{resource}/{object_id}",
            params={"fields": "entity,risk,timestamps,relatedEntities"},
        )
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        resource = self.stix_type_map.get(stix_type, stix_type)
        params: dict[str, Any] = {"limit": page_size, "from": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = self.get(f"/v2/{resource}/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Recorded Future API is read-only -- upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Recorded Future API is read-only -- delete not supported.")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert this object to STIX format."""
        entity = native.get("entity", {})
        risk = native.get("risk", {})
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{entity.get('id', '')}",
            "name": entity.get("name", ""),
            "pattern": f"[ipv4-addr:value = '{entity.get('name', '')}']",
            "pattern_type": "stix",
            "created": native.get("timestamps", {}).get("firstSeen", ""),
            "modified": native.get("timestamps", {}).get("lastSeen", ""),
            "x_rf_risk_score": risk.get("score", 0),
            "x_rf_criticality": risk.get("criticalityLabel", ""),
        }
        # Targeted industries from relatedEntities (type == "Industry")
        # Returned when ?fields=...relatedEntities is included in the request.
        sectors = [
            r.get("entity", {}).get("name", "")
            for r in native.get("relatedEntities", [])
            if r.get("type") == "Industry"
        ]
        sectors = [s for s in sectors if s]
        if sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {"entity": stix_dict.get("name", "")}

    # ── Entity intelligence lookups ────────────────────────────────────────

    def lookup_ip(
        self,
        ip_address: str,
        fields: str = "entity,risk,timestamps,relatedEntities,intelCard",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for an IP address.

        Calls ``GET /v2/ip/{ip_address}``.

        Parameters
        ----------
        ip_address : str
            IPv4 or IPv6 address to look up.
        fields : str
            Comma-separated list of RF fields to include in the response.
        """
        resp = self.get(f"/v2/ip/{ip_address}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_domain(
        self,
        domain: str,
        fields: str = "entity,risk,timestamps,relatedEntities,intelCard",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a domain name.

        Calls ``GET /v2/domain/{domain}``.

        Parameters
        ----------
        domain : str
            Fully-qualified domain name to look up.
        fields : str
            Comma-separated list of RF fields to include.
        """
        resp = self.get(f"/v2/domain/{domain}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_hash(
        self,
        hash_value: str,
        fields: str = "entity,risk,timestamps,relatedEntities,intelCard",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a file hash.

        Calls ``GET /v2/hash/{hash_value}``.

        Accepts MD5, SHA-1, and SHA-256 hashes; RF normalises the format
        internally.

        Parameters
        ----------
        hash_value : str
            File hash (MD5 / SHA-1 / SHA-256).
        fields : str
            Comma-separated list of RF fields to include.
        """
        resp = self.get(f"/v2/hash/{hash_value}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_url(
        self,
        url: str,
        fields: str = "entity,risk,timestamps,relatedEntities",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a URL.

        Calls ``GET /v2/url/{url}`` (URL-encoded by the HTTP layer).

        Parameters
        ----------
        url : str
            Full URL to look up.
        fields : str
            Comma-separated list of RF fields to include.
        """
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        resp = self.get(f"/v2/url/{encoded}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_vulnerability(
        self,
        cve_id: str,
        fields: str = "entity,risk,timestamps,relatedEntities,cpe",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a CVE.

        Calls ``GET /v2/vulnerability/{cve_id}``.

        Parameters
        ----------
        cve_id : str
            CVE identifier, e.g. ``"CVE-2021-44228"``.
        fields : str
            Comma-separated list of RF fields to include.
        """
        resp = self.get(f"/v2/vulnerability/{cve_id}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_malware(
        self,
        malware_id: str,
        fields: str = "entity,risk,timestamps,relatedEntities",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a malware family.

        Calls ``GET /v2/malware/{malware_id}``.

        Parameters
        ----------
        malware_id : str
            Recorded Future malware entity ID.
        fields : str
            Comma-separated list of RF fields to include.
        """
        resp = self.get(f"/v2/malware/{malware_id}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def lookup_threat_actor(
        self,
        actor_id: str,
        fields: str = "entity,risk,timestamps,relatedEntities",
    ) -> dict[str, Any]:
        """
        Retrieve Recorded Future intelligence for a threat actor.

        Calls ``GET /v2/threat-actor/{actor_id}``.

        Parameters
        ----------
        actor_id : str
            Recorded Future threat-actor entity ID.
        fields : str
            Comma-separated list of RF fields to include.
        """
        resp = self.get(f"/v2/threat-actor/{actor_id}", params={"fields": fields})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── Entity search helpers ──────────────────────────────────────────────

    def search_ips(
        self,
        query: str = "",
        limit: int = 100,
        fields: str = "entity,risk",
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future IP intelligence.

        Calls ``GET /v2/ip/search``.

        Parameters
        ----------
        query : str
            Free-text or structured RF query (e.g. ``"risk.score:[70 TO *]"``).
        limit : int
            Maximum results.  Default ``100``.
        fields : str
            Comma-separated list of RF fields to include.
        """
        params: dict[str, Any] = {"limit": limit, "fields": fields}
        if query:
            params["freetext"] = query
        resp = self.get("/v2/ip/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def search_domains(
        self,
        query: str = "",
        limit: int = 100,
        fields: str = "entity,risk",
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future domain intelligence.

        Calls ``GET /v2/domain/search``.

        Parameters
        ----------
        query : str
            Free-text or structured RF query.
        limit : int
            Maximum results.  Default ``100``.
        fields : str
            Comma-separated list of RF fields to include.
        """
        params: dict[str, Any] = {"limit": limit, "fields": fields}
        if query:
            params["freetext"] = query
        resp = self.get("/v2/domain/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def search_hashes(
        self,
        query: str = "",
        limit: int = 100,
        fields: str = "entity,risk",
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future file-hash intelligence.

        Calls ``GET /v2/hash/search``.

        Parameters
        ----------
        query : str
            Free-text or structured RF query.
        limit : int
            Maximum results.  Default ``100``.
        fields : str
            Comma-separated list of RF fields to include.
        """
        params: dict[str, Any] = {"limit": limit, "fields": fields}
        if query:
            params["freetext"] = query
        resp = self.get("/v2/hash/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def search_vulnerabilities(
        self,
        query: str = "",
        limit: int = 100,
        fields: str = "entity,risk,cpe",
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future vulnerability intelligence.

        Calls ``GET /v2/vulnerability/search``.

        Parameters
        ----------
        query : str
            Free-text or structured RF query (e.g. ``"cpe:apache"``).
        limit : int
            Maximum results.  Default ``100``.
        fields : str
            Comma-separated list of RF fields to include.
        """
        params: dict[str, Any] = {"limit": limit, "fields": fields}
        if query:
            params["freetext"] = query
        resp = self.get("/v2/vulnerability/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    # ── Risk alerts ────────────────────────────────────────────────────────

    def list_risk_alerts(
        self,
        triggered_after: str = "",
        rule_id: str = "",
        status: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future risk alerts.

        Calls ``POST /v2/alert/search`` with optional filters.

        Parameters
        ----------
        triggered_after : str, optional
            ISO-8601 datetime; return only alerts triggered after this time.
        rule_id : str, optional
            Filter by alert rule ID.
        status : str, optional
            Alert status filter: ``"unread"``, ``"read"``, ``"dismissed"``.
        limit : int
            Maximum results.  Default ``100``.
        """
        payload: dict[str, Any] = {"limit": limit}
        if triggered_after:
            payload["triggered"] = {"gte": triggered_after}
        if rule_id:
            payload["alertRule"] = rule_id
        if status:
            payload["status"] = status
        resp = self.post("/v2/alert/search", json=payload)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def get_risk_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Recorded Future risk alert by ID.

        Calls ``GET /v2/alert/{alert_id}``.

        Parameters
        ----------
        alert_id : str
            Recorded Future alert ID.
        """
        resp = self.get(f"/v2/alert/{alert_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        note: str = "",
    ) -> dict[str, Any]:
        """
        Update the status of a Recorded Future risk alert.

        Calls ``POST /v2/alert/{alert_id}/update``.

        Parameters
        ----------
        alert_id : str
            Recorded Future alert ID.
        status : str
            New status: ``"read"``, ``"unread"``, or ``"dismissed"``.
        note : str, optional
            Optional analyst note to attach to the status change.
        """
        payload: dict[str, Any] = {"status": status}
        if note:
            payload["note"] = note
        resp = self.post(f"/v2/alert/{alert_id}/update", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Playbook alerts ────────────────────────────────────────────────────

    def list_playbook_alerts(
        self,
        category: str = "",
        status: str = "",
        priority: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future Playbook Alerts.

        Calls ``POST /v2/playbook-alert/search``.

        Parameters
        ----------
        category : str, optional
            Playbook alert category (e.g. ``"domain_abuse"``,
            ``"cyber_vulnerability"``, ``"data_leakage"``).
        status : str, optional
            Alert status filter: ``"new"``, ``"in-progress"``, ``"dismissed"``,
            ``"resolved"``.
        priority : str, optional
            Priority filter: ``"high"``, ``"moderate"``, ``"informational"``.
        limit : int
            Maximum results.  Default ``100``.
        """
        payload: dict[str, Any] = {"limit": limit}
        if category:
            payload["category"] = [category]
        if status:
            payload["status"] = [status]
        if priority:
            payload["priority"] = [priority]
        resp = self.post("/v2/playbook-alert/search", json=payload)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def get_playbook_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Recorded Future Playbook Alert.

        Calls ``GET /v2/playbook-alert/{alert_id}``.

        Parameters
        ----------
        alert_id : str
            Playbook Alert ID.
        """
        resp = self.get(f"/v2/playbook-alert/{alert_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def update_playbook_alert(
        self,
        alert_id: str,
        status: str = "",
        assignee: str = "",
        priority: str = "",
    ) -> dict[str, Any]:
        """
        Update a Recorded Future Playbook Alert.

        Calls ``PUT /v2/playbook-alert/{alert_id}``.

        Parameters
        ----------
        alert_id : str
            Playbook Alert ID.
        status : str, optional
            New status value.
        assignee : str, optional
            Assignee username or ID.
        priority : str, optional
            New priority value.
        """
        payload: dict[str, Any] = {}
        if status:
            payload["status"] = status
        if assignee:
            payload["assignee"] = assignee
        if priority:
            payload["priority"] = priority
        resp = self.put(f"/v2/playbook-alert/{alert_id}", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Analyst notes ──────────────────────────────────────────────────────

    def search_analyst_notes(
        self,
        query: str = "",
        topic: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Recorded Future analyst notes.

        Calls ``POST /v2/analyst-note/search``.

        Parameters
        ----------
        query : str, optional
            Free-text search query.
        topic : str, optional
            Filter by topic / entity type (e.g. ``"IpAddress"``,
            ``"MalwareCategory"``).
        limit : int
            Maximum results.  Default ``100``.
        """
        payload: dict[str, Any] = {"limit": limit}
        if query:
            payload["freetext"] = query
        if topic:
            payload["topic"] = topic
        resp = self.post("/v2/analyst-note/search", json=payload)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def get_analyst_note(self, note_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Recorded Future analyst note.

        Calls ``GET /v2/analyst-note/{note_id}``.

        Parameters
        ----------
        note_id : str
            Analyst note ID.
        """
        resp = self.get(f"/v2/analyst-note/{note_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    # ── Related entities ───────────────────────────────────────────────────

    def get_related_entities(
        self,
        entity_id: str,
        entity_type: str,
        relation_types: list[str] | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """
        Retrieve entities related to a given Recorded Future entity.

        Calls ``POST /v2/links/search``.

        Parameters
        ----------
        entity_id : str
            Recorded Future entity ID.
        entity_type : str
            Entity type string (e.g. ``"IpAddress"``, ``"Domain"``,
            ``"Hash"``, ``"MalwareCategory"``).
        relation_types : list of str, optional
            Filter related entities by relationship type.  If omitted,
            all relation types are returned.
        limit : int
            Maximum related entities per type.  Default ``25``.
        """
        payload: dict[str, Any] = {
            "entity": {"id": entity_id, "type": entity_type},
            "limit":  limit,
        }
        if relation_types:
            payload["relationTypes"] = relation_types
        resp = self.post("/v2/links/search", json=payload)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    # ── Risk lists ─────────────────────────────────────────────────────────

    def download_risk_list(
        self,
        entity_type: str,
        risk_threshold: int = 65,
        output_format: str = "csv/splunk",
    ) -> bytes:
        """
        Download a Recorded Future bulk risk list.

        Calls ``GET /v2/{entity_type}/risklist`` and returns the raw
        response body.

        Parameters
        ----------
        entity_type : str
            Entity type for the risk list: ``"ip"``, ``"domain"``,
            ``"hash"``, ``"url"``, or ``"vulnerability"``.
        risk_threshold : int
            Minimum risk score (0–99) for inclusion.  Default ``65``.
        output_format : str
            Output format: ``"csv/splunk"``, ``"csv/stix"``,
            ``"xml/stix"``.  Default ``"csv/splunk"``.
        """
        resp = self.get(
            f"/v2/{entity_type}/risklist",
            params={"format": output_format, "threshold": risk_threshold},
        )
        if isinstance(resp, bytes):
            return resp
        if isinstance(resp, str):
            return resp.encode()
        return b""

    def get_risk_rules(self, entity_type: str) -> list[dict[str, Any]]:
        """
        Return the available risk rules for an entity type.

        Calls ``GET /v2/{entity_type}/riskrules``.

        Parameters
        ----------
        entity_type : str
            Entity type: ``"ip"``, ``"domain"``, ``"hash"``,
            ``"vulnerability"``.
        """
        resp = self.get(f"/v2/{entity_type}/riskrules")
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    # ── Fusion / custom feeds ──────────────────────────────────────────────

    def list_fusion_files(self) -> list[dict[str, Any]]:
        """
        List files available in the Recorded Future Fusion intelligence feed.

        Calls ``GET /v2/fusion/files``.
        """
        resp = self.get("/v2/fusion/files")
        return resp.get("data", {}).get("files", []) if isinstance(resp, dict) else []

    def download_fusion_file(self, path: str) -> bytes:
        """
        Download a specific Recorded Future Fusion file by path.

        Calls ``GET /v2/fusion/files/{path}`` and returns the raw bytes.

        Parameters
        ----------
        path : str
            Fusion file path as returned by :meth:`list_fusion_files`.
        """
        import urllib.parse
        encoded_path = urllib.parse.quote(path, safe="")
        resp = self.get(f"/v2/fusion/files/{encoded_path}")
        if isinstance(resp, bytes):
            return resp
        if isinstance(resp, str):
            return resp.encode()
        return b""
