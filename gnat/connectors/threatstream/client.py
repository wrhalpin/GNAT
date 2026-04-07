# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.threatstream.client
======================================
Anomali ThreatStream OPTIC API v2 connector.

Authentication uses an API key combined with a username as HTTP query
parameters on every request (``api_key=`` and ``username=``).

INI config::

    [threatstream]
    host      = https://api.threatstream.com
    username  = your@email.com
    api_key   = YOUR_THREATSTREAM_API_KEY
    auth_type = api_key

References
----------
https://api.threatstream.com/optic/v2/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_API = "/optic/v2"


class ThreatStreamClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Anomali ThreatStream OPTIC API v2.

    Parameters
    ----------
    host : str
        ThreatStream base URL.  Default ``https://api.threatstream.com``.
    username : str
        ThreatStream account email address.
    api_key : str
        ThreatStream API key.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "intelligence",
        "threat-actor": "actor",
        "malware": "malware",
        "campaign": "campaign",
        "vulnerability": "vulnerability",
    }

    def __init__(
        self,
        host: str = "https://api.threatstream.com",
        username: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._api_key = api_key

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        ThreatStream embeds credentials as query parameters on every request.

        This method stores the credential pair on the instance so
        :meth:`_auth_params` can inject them into every call.
        """
        # Credentials are injected as query params, not headers
        # Store them for use in _auth_params()
        self._ts_auth = {
            "username": self._username,
            "api_key": self._api_key,
        }

    def health_check(self) -> bool:
        """Ping the intelligence feed with a minimal query."""
        resp = self.get(
            f"{_API}/intelligence/",
            params={**self._ts_auth, "limit": 1},
        )
        return isinstance(resp, dict) and "objects" in resp

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a single ThreatStream object by numeric ID."""
        resource = self.stix_type_map.get(stix_type, "intelligence")
        resp = self.get(
            f"{_API}/{resource}/{object_id}/",
            params=self._ts_auth,
        )
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List ThreatStream intelligence objects.

        ``filters`` may include any OPTIC API filter parameter, e.g.:

        * ``type``: IOC type (``"ip"``, ``"domain"``, ``"md5"``, etc.)
        * ``status``: ``"active"`` | ``"inactive"``
        * ``confidence__gte``: minimum confidence score
        * ``modified_ts__gte``: ISO-8601 modified-after filter
        """
        resource = self.stix_type_map.get(stix_type, "intelligence")
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(page_size, 1000),
            "offset": (page - 1) * page_size,
            "format": "json",
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/{resource}/", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("objects", [])

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Import an indicator into ThreatStream.

        Uses ``POST /optic/v2/intelligence/`` for new objects and
        ``PATCH /optic/v2/intelligence/{id}/`` for updates.
        """
        resource = self.stix_type_map.get(stix_type, "intelligence")
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.patch(
                f"{_API}/{resource}/{obj_id}/",
                params=self._ts_auth,
                json=payload,
            )
        else:
            resp = self.post(
                f"{_API}/{resource}/",
                params=self._ts_auth,
                json={"objects": [payload]},
            )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an intelligence object by ID."""
        resource = self.stix_type_map.get(stix_type, "intelligence")
        self.delete(
            f"{_API}/{resource}/{object_id}/",
            params=self._ts_auth,
        )

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a ThreatStream intelligence object to a STIX Indicator SDO."""
        ts_type = native.get("type", "")
        value = native.get("value", native.get("ip", native.get("domain", "")))
        pattern = self._make_pattern(ts_type, value)
        conf = native.get("confidence", 0)
        return {
            "type": "indicator",
            "id": f"indicator--ts-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("created_ts", ""),
            "modified": native.get("modified_ts", ""),
            "confidence": conf,
            "indicator_types": ["malicious-activity"] if conf >= 50 else ["unknown"],
            "x_source_platform": "threatstream",
            "x_ts_id": native.get("id", ""),
            "x_ts_type": ts_type,
            "x_ts_status": native.get("status", ""),
            "x_ts_feed_id": native.get("feed_id", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a ThreatStream intelligence import payload from a STIX dict."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "value": value,
            "type": self._stix_to_ts_type(pattern),
            "confidence": stix_dict.get("confidence", 50),
            "status": "active",
            "source": "gnat",
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @property
    def _ts_auth(self) -> dict[str, str]:
        return {"username": self._username, "api_key": self._api_key}

    @_ts_auth.setter
    def _ts_auth(self, value: dict[str, str]) -> None:
        # Setter exists so authenticate() can assign; values already stored
        pass

    @staticmethod
    def _make_pattern(ts_type: str, value: str) -> str:
        t = (ts_type or "").lower()
        if t in ("ip", "ipv4", "srcip"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6",):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain", "hostname"):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("md5",):
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("sha1",):
            return f"[file:hashes.'SHA-1' = '{value}']"
        if t in ("sha256",):
            return f"[file:hashes.'SHA-256' = '{value}']"
        if t in ("email",):
            return f"[email-message:from_ref.value = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_ts_type(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ip"
        if "ipv6-addr" in pattern:
            return "ipv6"
        if "domain-name" in pattern:
            return "domain"
        if "url:" in pattern:
            return "url"
        if "MD5" in pattern:
            return "md5"
        if "SHA-1" in pattern:
            return "sha1"
        if "SHA-256" in pattern:
            return "sha256"
        if "email" in pattern:
            return "email"
        return "domain"

    # ── Intelligence (typed indicator operations) ─────────────────────────────

    def list_intelligence(
        self,
        ioc_type: str = "",
        status: str = "active",
        confidence_gte: int = 0,
        modified_after: str = "",
        tags: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List threat intelligence indicators with typed filters.

        Parameters
        ----------
        ioc_type : str
            IOC type filter: ``"ip"``, ``"domain"``, ``"url"``, ``"md5"``,
            ``"sha1"``, ``"sha256"``, ``"email"``, ``"cidr"``.
        status : str
            ``"active"`` (default), ``"inactive"``, or ``"falsepos"``.
        confidence_gte : int
            Minimum confidence score (0–100).
        modified_after : str
            ISO-8601 modified-after filter, e.g. ``"2024-01-01T00:00:00"``.
        tags : str
            Comma-separated tag names to filter by.
        """
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
            "format": "json",
        }
        if ioc_type:
            params["type"] = ioc_type
        if status:
            params["status"] = status
        if confidence_gte:
            params["confidence__gte"] = confidence_gte
        if modified_after:
            params["modified_ts__gte"] = modified_after
        if tags:
            params["tags__name__in"] = tags
        resp = self.get(f"{_API}/intelligence/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def import_indicators(
        self,
        indicators: list[dict[str, Any]],
        trusted_circles: list[int] | None = None,
        tags: list[str] | None = None,
        source: str = "gnat",
    ) -> dict[str, Any]:
        """
        Bulk import indicators into ThreatStream.

        Each item in ``indicators`` needs at minimum ``"type"`` and ``"value"``.
        ``trusted_circles`` — list of trusted circle IDs to share with.
        """
        payload: dict[str, Any] = {
            "objects": [
                {**ind, "source": ind.get("source", source)}
                for ind in indicators
            ],
            "meta": {"allow_unresolved": True},
        }
        if trusted_circles:
            payload["meta"]["circles"] = trusted_circles
        if tags:
            for obj in payload["objects"]:
                obj.setdefault("tags", []).extend(tags)
        resp = self.post(
            f"{_API}/intelligence/",
            params=self._ts_auth,
            json=payload,
        )
        return resp if isinstance(resp, dict) else {}

    def update_indicator_status(
        self, ioc_id: int | str, status: str
    ) -> dict[str, Any]:
        """
        Update the status of a single indicator.

        ``status`` options: ``"active"``, ``"inactive"``, ``"falsepos"``.
        """
        resp = self.patch(
            f"{_API}/intelligence/{ioc_id}/",
            params=self._ts_auth,
            json={"status": status},
        )
        return resp if isinstance(resp, dict) else {}

    def tag_indicators(
        self, ioc_ids: list[int | str], tags: list[str]
    ) -> dict[str, Any]:
        """Apply a list of tags to multiple indicators."""
        resp = self.post(
            f"{_API}/intelligence/bulk_tag/",
            params=self._ts_auth,
            json={"ids": ioc_ids, "tags": tags},
        )
        return resp if isinstance(resp, dict) else {}

    def export_indicators(
        self,
        ioc_type: str = "",
        export_format: str = "json",
        status: str = "active",
        limit: int = 1000,
    ) -> dict[str, Any]:
        """
        Export indicators in JSON or CSV format.

        Returns a dict with a ``"download_url"`` key or inline data.
        """
        params: dict[str, Any] = {
            **self._ts_auth,
            "format": export_format,
            "status": status,
            "limit": limit,
        }
        if ioc_type:
            params["type"] = ioc_type
        resp = self.get(f"{_API}/intelligence/export/", params=params)
        return resp if isinstance(resp, dict) else {}

    # ── Threat actors ─────────────────────────────────────────────────────────

    def list_actors(
        self,
        limit: int = 100,
        offset: int = 0,
        name: str = "",
    ) -> list[dict[str, Any]]:
        """List threat actor profiles."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if name:
            params["name__icontains"] = name
        resp = self.get(f"{_API}/actor/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_actor(self, actor_id: int | str) -> dict[str, Any]:
        """Retrieve a specific threat actor by ID."""
        resp = self.get(f"{_API}/actor/{actor_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def list_actor_indicators(
        self, actor_id: int | str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List intelligence indicators associated with a threat actor."""
        params: dict[str, Any] = {**self._ts_auth, "limit": limit}
        resp = self.get(f"{_API}/actor/{actor_id}/intelligence/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def create_actor(
        self, name: str, description: str = "", **kwargs: Any
    ) -> dict[str, Any]:
        """Create a new threat actor entity."""
        payload: dict[str, Any] = {"name": name, "description": description, **kwargs}
        resp = self.post(f"{_API}/actor/", params=self._ts_auth, json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Malware families ──────────────────────────────────────────────────────

    def list_malware(
        self,
        limit: int = 100,
        offset: int = 0,
        name: str = "",
    ) -> list[dict[str, Any]]:
        """List malware family profiles."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if name:
            params["name__icontains"] = name
        resp = self.get(f"{_API}/malware/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_malware_family(self, malware_id: int | str) -> dict[str, Any]:
        """Retrieve a specific malware family by ID."""
        resp = self.get(f"{_API}/malware/{malware_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def list_malware_indicators(
        self, malware_id: int | str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List intelligence indicators associated with a malware family."""
        params: dict[str, Any] = {**self._ts_auth, "limit": limit}
        resp = self.get(f"{_API}/malware/{malware_id}/intelligence/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    # ── Campaigns ─────────────────────────────────────────────────────────────

    def list_campaigns(
        self,
        limit: int = 100,
        offset: int = 0,
        name: str = "",
    ) -> list[dict[str, Any]]:
        """List campaign profiles."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if name:
            params["name__icontains"] = name
        resp = self.get(f"{_API}/campaign/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_campaign(self, campaign_id: int | str) -> dict[str, Any]:
        """Retrieve a specific campaign by ID."""
        resp = self.get(f"{_API}/campaign/{campaign_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def list_campaign_indicators(
        self, campaign_id: int | str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List intelligence indicators associated with a campaign."""
        params: dict[str, Any] = {**self._ts_auth, "limit": limit}
        resp = self.get(f"{_API}/campaign/{campaign_id}/intelligence/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    # ── Vulnerabilities ───────────────────────────────────────────────────────

    def list_vulnerabilities(
        self,
        limit: int = 100,
        offset: int = 0,
        cve_id: str = "",
    ) -> list[dict[str, Any]]:
        """List vulnerability profiles."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if cve_id:
            params["name__icontains"] = cve_id
        resp = self.get(f"{_API}/vulnerability/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_vulnerability(self, vuln_id: int | str) -> dict[str, Any]:
        """Retrieve a specific vulnerability by ThreatStream ID."""
        resp = self.get(f"{_API}/vulnerability/{vuln_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    # ── Incidents ─────────────────────────────────────────────────────────────

    def list_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        status: str = "",
        name: str = "",
    ) -> list[dict[str, Any]]:
        """List ThreatStream incidents."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if status:
            params["status"] = status
        if name:
            params["name__icontains"] = name
        resp = self.get(f"{_API}/incident/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_incident(self, incident_id: int | str) -> dict[str, Any]:
        """Retrieve a specific incident by ID."""
        resp = self.get(f"{_API}/incident/{incident_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def create_incident(
        self,
        name: str,
        status: str = "open",
        description: str = "",
        severity: str = "medium",
        ioc_ids: list[int | str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new ThreatStream incident.

        ``status`` options: ``"open"``, ``"closed"``, ``"contained"``.
        ``severity`` options: ``"low"``, ``"medium"``, ``"high"``, ``"very-high"``.
        """
        payload: dict[str, Any] = {
            "name": name,
            "status": status,
            "description": description,
            "severity": severity,
        }
        if ioc_ids:
            payload["intelligence"] = [{"id": i} for i in ioc_ids]
        resp = self.post(f"{_API}/incident/", params=self._ts_auth, json=payload)
        return resp if isinstance(resp, dict) else {}

    def update_incident(
        self, incident_id: int | str, updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an existing incident (status, severity, description, etc.)."""
        resp = self.patch(
            f"{_API}/incident/{incident_id}/",
            params=self._ts_auth,
            json=updates,
        )
        return resp if isinstance(resp, dict) else {}

    def add_incident_indicators(
        self, incident_id: int | str, ioc_ids: list[int | str]
    ) -> dict[str, Any]:
        """Associate intelligence indicators with an incident."""
        resp = self.post(
            f"{_API}/incident/{incident_id}/intelligence/",
            params=self._ts_auth,
            json=[{"id": i} for i in ioc_ids],
        )
        return resp if isinstance(resp, dict) else {}

    # ── Trusted circles ───────────────────────────────────────────────────────

    def list_trusted_circles(self, limit: int = 100) -> list[dict[str, Any]]:
        """List trusted sharing circles the organisation belongs to."""
        resp = self.get(
            f"{_API}/trustedcircle/",
            params={**self._ts_auth, "limit": limit},
        )
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_trusted_circle(self, circle_id: int | str) -> dict[str, Any]:
        """Retrieve details for a specific trusted circle."""
        resp = self.get(f"{_API}/trustedcircle/{circle_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def list_circle_indicators(
        self, circle_id: int | str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List indicators shared within a trusted circle."""
        params: dict[str, Any] = {
            **self._ts_auth,
            "limit": limit,
            "circles": circle_id,
        }
        resp = self.get(f"{_API}/intelligence/", params=params)
        return resp.get("objects", []) if isinstance(resp, dict) else []

    # ── Feeds ─────────────────────────────────────────────────────────────────

    def list_feeds(self, limit: int = 100) -> list[dict[str, Any]]:
        """List configured threat intelligence feeds."""
        resp = self.get(
            f"{_API}/feed/",
            params={**self._ts_auth, "limit": limit},
        )
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_feed(self, feed_id: int | str) -> dict[str, Any]:
        """Retrieve details for a specific feed configuration."""
        resp = self.get(f"{_API}/feed/{feed_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}

    def run_feed(self, feed_id: int | str) -> dict[str, Any]:
        """Trigger an immediate import run for a feed."""
        resp = self.post(
            f"{_API}/feed/{feed_id}/import/",
            params=self._ts_auth,
            json={},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Rule sets ─────────────────────────────────────────────────────────────

    def list_rules(self, limit: int = 100) -> list[dict[str, Any]]:
        """List observable matching rules configured in ThreatStream."""
        resp = self.get(
            f"{_API}/rule/",
            params={**self._ts_auth, "limit": limit},
        )
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def create_rule(
        self,
        name: str,
        keywords: list[str],
        match_type: str = "exact",
        notify_me: bool = True,
    ) -> dict[str, Any]:
        """
        Create an observable matching rule.

        ``match_type`` options: ``"exact"``, ``"contains"``, ``"regex"``.
        """
        resp = self.post(
            f"{_API}/rule/",
            params=self._ts_auth,
            json={
                "name": name,
                "keywords": keywords,
                "match_type": match_type,
                "notify_me": notify_me,
            },
        )
        return resp if isinstance(resp, dict) else {}

    # ── Reports ───────────────────────────────────────────────────────────────

    def list_reports(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List threat intelligence reports in ThreatStream."""
        resp = self.get(
            f"{_API}/report/",
            params={**self._ts_auth, "limit": limit, "offset": offset},
        )
        return resp.get("objects", []) if isinstance(resp, dict) else []

    def get_report(self, report_id: int | str) -> dict[str, Any]:
        """Retrieve a specific report by ID."""
        resp = self.get(f"{_API}/report/{report_id}/", params=self._ts_auth)
        return resp if isinstance(resp, dict) else {}
