# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.socradar.client
=================================
SOCRadar Cyber Threat Intelligence + Attack Surface Management connector.

Uses an API key passed in the ``Authorization`` header.

INI config::

    [socradar]
    host    = https://platform.socradar.com
    api_key = YOUR_SOCRADAR_API_KEY
    auth_type = token

References
----------
https://docs.socradar.io/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_API = "/api"


class SOCRadarClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the SOCRadar Threat Intelligence API.

    Parameters
    ----------
    host : str
        SOCRadar API base URL.  Default ``https://platform.socradar.com``.
    api_key : str
        SOCRadar API key.
    company_id : str, optional
        SOCRadar company / tenant ID (required for attack-surface endpoints).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "indicator": "ioc",
        "threat-actor": "threat_actor",
        "malware": "malware",
        "vulnerability": "vulnerability",
        "campaign": "campaign",
    }

    def __init__(
        self,
        host: str = "https://platform.socradar.com",
        api_key: str = "",
        company_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SOCRadarClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._company_id = company_id

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Inject the SOCRadar API key header."""
        self._auth_headers["Authorization"] = self._api_key
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Ping the IOC feed with a minimal query."""
        resp = self.get(f"{_API}/cti/ioc/", params={"limit": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a single SOCRadar object by ID."""
        resource = self.stix_type_map.get(stix_type, "ioc")
        resp = self.get(f"{_API}/cti/{resource}/{object_id}/")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List SOCRadar CTI objects.

        ``filters`` may include:

        * ``ioc_type``: ``"ip"``, ``"domain"``, ``"url"``, ``"hash"``
        * ``severity``: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``
        * ``from_date`` / ``to_date``: ISO-8601 date strings
        * ``search``: keyword search string
        """
        resource = self.stix_type_map.get(stix_type, "ioc")
        params: dict[str, Any] = {
            "limit": min(page_size, 500),
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/cti/{resource}/", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("data", resp.get("results", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """SOCRadar TI API is read-only — raises :class:`GNATClientError`."""
        raise GNATClientError(
            "SOCRadar TI API is read-only. Use the SOCRadar portal to manage IOCs."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("SOCRadar TI API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # Domain-specific helpers
    # ------------------------------------------------------------------

    def search_iocs(
        self,
        value: str = "",
        ioc_type: str = "",
        confidence_min: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search SOCRadar IOC database."""
        params: dict[str, Any] = {"limit": int(limit)}
        if value:
            params["value"] = value
        if ioc_type:
            params["type"] = ioc_type
        if confidence_min is not None:
            params["confidence__gte"] = int(confidence_min)
        resp = self.get(f"{_API}/cti/ioc/", params=params)
        return _extract_socradar_list(resp)

    def list_threat_actors(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return SOCRadar threat-actor catalog."""
        resp = self.get(
            f"{_API}/cti/threat_actor/", params={"limit": int(limit)}
        )
        return _extract_socradar_list(resp)

    def get_threat_actor(self, actor_id: str) -> dict[str, Any]:
        """Fetch a single threat actor by id."""
        resp = self.get(f"{_API}/cti/threat_actor/{actor_id}/")
        return resp if isinstance(resp, dict) else {}

    def list_malware_families(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return SOCRadar malware family catalog."""
        resp = self.get(
            f"{_API}/cti/malware/", params={"limit": int(limit)}
        )
        return _extract_socradar_list(resp)

    def get_malware(self, malware_id: str) -> dict[str, Any]:
        """Fetch a single malware family by id."""
        resp = self.get(f"{_API}/cti/malware/{malware_id}/")
        return resp if isinstance(resp, dict) else {}

    def list_dark_web_findings(
        self, since: str = "", limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return SOCRadar dark-web monitoring hits."""
        params: dict[str, Any] = {"limit": int(limit)}
        if since:
            params["created_at__gte"] = since
        resp = self.get(f"{_API}/dark_web/findings/", params=params)
        return _extract_socradar_list(resp)

    def list_brand_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return brand-protection / digital-risk alerts."""
        resp = self.get(
            f"{_API}/drps/alerts/", params={"limit": int(limit)}
        )
        return _extract_socradar_list(resp)

    def list_attack_surface_alerts(
        self, severity: str = "", limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return external attack-surface management alerts."""
        params: dict[str, Any] = {"limit": int(limit)}
        if severity:
            params["severity"] = severity
        resp = self.get(f"{_API}/asm/alerts/", params=params)
        return _extract_socradar_list(resp)

    def list_industry_threats(
        self, industry: str = "", limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return SOCRadar industry-specific threat reports."""
        params: dict[str, Any] = {"limit": int(limit)}
        if industry:
            params["industry"] = industry
        resp = self.get(f"{_API}/cti/industry_threats/", params=params)
        return _extract_socradar_list(resp)

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a SOCRadar IOC/actor/malware dict to a STIX dict."""
        obj_type = native.get("type", native.get("ioc_type", ""))
        if obj_type in ("threat_actor", "actor"):
            return self._actor_to_stix(native)
        if obj_type in ("malware",):
            return self._malware_to_stix(native)
        return self._ioc_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a SOCRadar IOC search payload from a STIX dict."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "value": value,
            "ioc_type": self._stix_to_sr_type(pattern),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ioc_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for ioc to stix."""
        sr_type = native.get("ioc_type", native.get("type", ""))
        value = native.get("value", native.get("indicator", ""))
        pattern = self._make_pattern(sr_type, value)
        severity = native.get("severity", "medium")
        conf = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(
            severity.lower() if isinstance(severity, str) else "medium", 50
        )
        return {
            "type": "indicator",
            "id": f"indicator--sr-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("created_at", native.get("date", "")),
            "modified": native.get("updated_at", ""),
            "confidence": conf,
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "socradar",
            "x_sr_id": native.get("id", ""),
            "x_sr_severity": severity,
            "x_sr_ioc_type": sr_type,
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for actor to stix."""
        return {
            "type": "threat-actor",
            "id": f"threat-actor--sr-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "aliases": native.get("aliases", []),
            "created": native.get("created_at", ""),
            "modified": native.get("updated_at", ""),
            "x_source_platform": "socradar",
        }

    def _malware_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for malware to stix."""
        return {
            "type": "malware",
            "id": f"malware--sr-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "is_family": True,
            "created": native.get("created_at", ""),
            "modified": native.get("updated_at", ""),
            "x_source_platform": "socradar",
        }

    @staticmethod
    def _make_pattern(sr_type: str, value: str) -> str:
        """Internal helper for make pattern."""
        t = (sr_type or "").lower()
        if t in ("ip", "ipv4"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6",):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain", "hostname"):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("hash", "md5"):
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("sha1",):
            return f"[file:hashes.'SHA-1' = '{value}']"
        if t in ("sha256",):
            return f"[file:hashes.'SHA-256' = '{value}']"
        if t in ("email",):
            return f"[email-message:from_ref.value = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_sr_type(pattern: str) -> str:
        """Internal helper for stix to sr type."""
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
        return "domain"


def _extract_socradar_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a SOCRadar response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
