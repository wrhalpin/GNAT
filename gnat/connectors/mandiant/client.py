# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.mandiant.client
=================================
Mandiant Advantage API connector.

Uses OAuth2 ``client_credentials`` grant.  The API key acts as the OAuth
``client_id`` and the API secret as ``client_secret``; credentials are sent
as HTTP Basic auth to the token endpoint.

INI config::

    [mandiant]
    host       = https://api.intelligence.mandiant.com
    api_key    = YOUR_MANDIANT_API_KEY
    api_secret = YOUR_MANDIANT_API_SECRET
    auth_type  = oauth2
"""

import base64
from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_TOKEN_PATH = "/token"
_V4 = "/v4"

# Map STIX types → Mandiant collection names
_STIX_TO_ENDPOINT: dict[str, str] = {
    "indicator": "indicator",
    "threat-actor": "actor",
    "malware": "malware",
    "report": "report",
    "vulnerability": "vulnerability",
}


class MandiantClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Mandiant Advantage Threat Intelligence API v4.

    Parameters
    ----------
    host : str
        API base URL.  Default ``https://api.intelligence.mandiant.com``.
    api_key : str
        Mandiant API key (used as OAuth2 ``client_id``).
    api_secret : str
        Mandiant API secret (used as OAuth2 ``client_secret``).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v4"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = _STIX_TO_ENDPOINT

    def __init__(
        self,
        host: str = "https://api.intelligence.mandiant.com",
        api_key: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize MandiantClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_secret = api_secret

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 Bearer token via ``client_credentials`` grant.

        Credentials are sent as HTTP Basic auth
        (``Authorization: Basic base64(api_key:api_secret)``).
        """
        creds = base64.b64encode(f"{self._api_key}:{self._api_secret}".encode()).decode()
        # Temporarily set Basic auth header for the token request
        saved = dict(self._auth_headers)
        self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["X-App-Name"] = "gnat"
        try:
            resp = self.post(
                _TOKEN_PATH,
                data={"grant_type": "client_credentials"},
            )
        finally:
            self._auth_headers.clear()
            self._auth_headers.update(saved)

        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("Mandiant: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["X-App-Name"] = "gnat"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Check API reachability via a lightweight indicator query."""
        resp = self.get(f"{_V4}/indicator", params={"limit": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a single Mandiant object by type and ID/value."""
        collection = _STIX_TO_ENDPOINT.get(stix_type, "indicator")
        resp = self.get(f"{_V4}/{collection}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Mandiant objects.

        ``filters`` may include:

        * ``start_epoch`` / ``end_epoch``: Unix epoch bounds
        * ``gte_mscore``: minimum Mandiant confidence score (0–100)
        * ``type``: indicator type filter (``"ipv4"``, ``"domain"``, etc.)
        """
        collection = _STIX_TO_ENDPOINT.get(stix_type, "indicator")
        params: dict[str, Any] = {
            "limit": min(page_size, 1000),
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update({k: v for k, v in filters.items() if v is not None})

        resp = self.get(f"{_V4}/{collection}", params=params)
        if not isinstance(resp, dict):
            return []
        # Mandiant wraps results in a key matching the collection name
        items = resp.get(collection, resp.get("indicators", resp.get("objects", [])))
        return items if isinstance(items, list) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Mandiant Advantage API is read-only for most tiers.

        Raises :class:`~gnat.clients.base.GNATClientError` — submit indicators
        via the Mandiant portal or SubmitSuspected API if licensed.
        """
        raise GNATClientError(
            "Mandiant Advantage API is read-only for standard subscriptions. "
            "Use the Mandiant portal to submit indicators."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Mandiant Advantage API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Mandiant API object to a STIX dict.

        Handles indicators, actors, malware families, and vulnerabilities.
        """
        obj_type = native.get("type", "")
        if obj_type in ("Actor", "threat-actor"):
            return self._actor_to_stix(native)
        if obj_type in ("Malware", "malware"):
            return self._malware_to_stix(native)
        if obj_type in ("Vulnerability", "vulnerability"):
            return self._vuln_to_stix(native)
        return self._indicator_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a Mandiant-compatible query dict derived from a STIX object."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {"value": value, "type": self._stix_to_mandiant_type(pattern)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _indicator_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for indicator to stix."""
        value = native.get("value", native.get("name", ""))
        mi_type = native.get("type", "")
        pattern = self._make_pattern(mi_type, value)
        mscore = native.get("mscore", 0)
        return {
            "type": "indicator",
            "id": f"indicator--mti-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("first_seen", ""),
            "modified": native.get("last_seen", ""),
            "confidence": mscore,
            "indicator_types": ["malicious-activity"] if mscore >= 50 else ["unknown"],
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
            "x_mandiant_type": mi_type,
            "x_mandiant_mscore": mscore,
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for actor to stix."""
        return {
            "type": "threat-actor",
            "id": f"threat-actor--mti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "aliases": [a.get("name", "") for a in native.get("aliases", [])],
            "created": native.get("last_updated", ""),
            "modified": native.get("last_updated", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
        }

    def _malware_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for malware to stix."""
        return {
            "type": "malware",
            "id": f"malware--mti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "is_family": True,
            "aliases": [a.get("name", "") for a in native.get("aliases", [])],
            "created": native.get("last_updated", ""),
            "modified": native.get("last_updated", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
        }

    def _vuln_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for vuln to stix."""
        return {
            "type": "vulnerability",
            "id": f"vulnerability--mti-{native.get('id', '')}",
            "name": native.get("cve_id", native.get("name", "")),
            "description": native.get("description", "")[:500],
            "created": native.get("publish_date", ""),
            "modified": native.get("last_update_date", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
            "x_cvss_score": native.get("common_vulnerability_scores", {})
            .get("v3.1", {})
            .get("base_score", 0),
        }

    @staticmethod
    def _make_pattern(mi_type: str, value: str) -> str:
        """Internal helper for make pattern."""
        t = (mi_type or "").lower()
        if t in ("ipv4", "ipv4-addr", "ip"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6", "ipv6-addr"):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain", "fqdn"):
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
    def _stix_to_mandiant_type(pattern: str) -> str:
        """Internal helper for stix to mandiant type."""
        if "ipv4-addr" in pattern:
            return "ipv4"
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

    # ── Actor relationships ───────────────────────────────────────────────────

    def get_actor_indicators(
        self,
        actor_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List indicators attributed to a specific threat actor."""
        resp = self.get(
            f"{_V4}/actor/{actor_id}/indicators",
            params={"limit": min(limit, 1000), "offset": offset},
        )
        return resp.get("indicators", []) if isinstance(resp, dict) else []

    def get_actor_malware(self, actor_id: str) -> list[dict[str, Any]]:
        """List malware families associated with a threat actor."""
        resp = self.get(f"{_V4}/actor/{actor_id}/malware")
        return resp.get("malware", []) if isinstance(resp, dict) else []

    def get_actor_attack_patterns(self, actor_id: str) -> list[dict[str, Any]]:
        """List MITRE ATT&CK techniques used by a threat actor."""
        resp = self.get(f"{_V4}/actor/{actor_id}/attack-pattern")
        return (
            resp.get("attack-patterns", resp.get("attack_patterns", []))
            if isinstance(resp, dict)
            else []
        )

    def get_actor_vulnerabilities(self, actor_id: str) -> list[dict[str, Any]]:
        """List CVEs exploited by a specific threat actor."""
        resp = self.get(f"{_V4}/actor/{actor_id}/vulnerability")
        return resp.get("vulnerabilities", []) if isinstance(resp, dict) else []

    def get_actor_campaigns(self, actor_id: str) -> list[dict[str, Any]]:
        """List campaigns associated with a threat actor."""
        resp = self.get(f"{_V4}/actor/{actor_id}/campaigns")
        return resp.get("campaigns", []) if isinstance(resp, dict) else []

    # ── Malware relationships ─────────────────────────────────────────────────

    def get_malware_indicators(
        self,
        malware_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List indicators associated with a malware family."""
        resp = self.get(
            f"{_V4}/malware/{malware_id}/indicators",
            params={"limit": min(limit, 1000), "offset": offset},
        )
        return resp.get("indicators", []) if isinstance(resp, dict) else []

    def get_malware_actors(self, malware_id: str) -> list[dict[str, Any]]:
        """List threat actors that use a specific malware family."""
        resp = self.get(f"{_V4}/malware/{malware_id}/actors")
        return resp.get("actors", []) if isinstance(resp, dict) else []

    def get_malware_attack_patterns(self, malware_id: str) -> list[dict[str, Any]]:
        """List ATT&CK techniques used by a malware family."""
        resp = self.get(f"{_V4}/malware/{malware_id}/attack-pattern")
        return (
            resp.get("attack-patterns", resp.get("attack_patterns", []))
            if isinstance(resp, dict)
            else []
        )

    def get_malware_campaigns(self, malware_id: str) -> list[dict[str, Any]]:
        """List campaigns that have used a specific malware family."""
        resp = self.get(f"{_V4}/malware/{malware_id}/campaigns")
        return resp.get("campaigns", []) if isinstance(resp, dict) else []

    # ── Vulnerability / CVE ───────────────────────────────────────────────────

    def get_vulnerability(self, cve_id: str) -> dict[str, Any]:
        """
        Retrieve full vulnerability details by CVE ID.

        ``cve_id`` format: ``"CVE-2024-12345"``.
        """
        resp = self.get(f"{_V4}/vulnerability/{cve_id}")
        return resp if isinstance(resp, dict) else {}

    def get_vulnerability_actors(self, cve_id: str) -> list[dict[str, Any]]:
        """List threat actors known to exploit a CVE."""
        resp = self.get(f"{_V4}/vulnerability/{cve_id}/actors")
        return resp.get("actors", []) if isinstance(resp, dict) else []

    def get_vulnerability_malware(self, cve_id: str) -> list[dict[str, Any]]:
        """List malware families that exploit a CVE."""
        resp = self.get(f"{_V4}/vulnerability/{cve_id}/malware")
        return resp.get("malware", []) if isinstance(resp, dict) else []

    def get_vulnerability_epss(self, cve_id: str) -> dict[str, Any]:
        """
        Retrieve EPSS (Exploit Prediction Scoring System) score for a CVE.

        Returns a dict with ``epss_score`` and ``percentile``.
        """
        resp = self.get(f"{_V4}/vulnerability/{cve_id}/epss")
        return resp if isinstance(resp, dict) else {}

    # ── Reports ───────────────────────────────────────────────────────────────

    def list_reports(
        self,
        limit: int = 100,
        offset: int = 0,
        start_epoch: int | None = None,
        end_epoch: int | None = None,
        report_type: str = "",
    ) -> list[dict[str, Any]]:
        """
        List Mandiant Advantage intelligence reports.

        ``report_type`` options: ``"Actor Profile"``, ``"Threat Activity Alert"``,
        ``"Malware Profile"``, ``"Vulnerability Report"``, etc.
        """
        params: dict[str, Any] = {
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if start_epoch is not None:
            params["start_epoch"] = start_epoch
        if end_epoch is not None:
            params["end_epoch"] = end_epoch
        if report_type:
            params["report_type"] = report_type
        resp = self.get(f"{_V4}/report", params=params)
        return resp.get("reports", resp.get("objects", [])) if isinstance(resp, dict) else []

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Retrieve a full intelligence report by ID."""
        resp = self.get(f"{_V4}/report/{report_id}")
        return resp if isinstance(resp, dict) else {}

    def get_report_stix(self, report_id: str) -> dict[str, Any]:
        """
        Retrieve a report in STIX 2.1 bundle format.

        Returns a STIX bundle dict if the report has STIX content.
        """
        resp = self.get(
            f"{_V4}/report/{report_id}",
            params={"format": "stix2.1"},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Campaigns ─────────────────────────────────────────────────────────────

    def list_campaigns(
        self,
        limit: int = 100,
        offset: int = 0,
        start_epoch: int | None = None,
        end_epoch: int | None = None,
    ) -> list[dict[str, Any]]:
        """List Mandiant intelligence campaigns."""
        params: dict[str, Any] = {
            "limit": min(limit, 1000),
            "offset": offset,
        }
        if start_epoch is not None:
            params["start_epoch"] = start_epoch
        if end_epoch is not None:
            params["end_epoch"] = end_epoch
        resp = self.get(f"{_V4}/campaign", params=params)
        return resp.get("campaigns", resp.get("objects", [])) if isinstance(resp, dict) else []

    def get_campaign(self, campaign_id: str) -> dict[str, Any]:
        """Retrieve a single campaign by ID."""
        resp = self.get(f"{_V4}/campaign/{campaign_id}")
        return resp if isinstance(resp, dict) else {}

    def get_campaign_actors(self, campaign_id: str) -> list[dict[str, Any]]:
        """List threat actors associated with a campaign."""
        resp = self.get(f"{_V4}/campaign/{campaign_id}/actors")
        return resp.get("actors", []) if isinstance(resp, dict) else []

    def get_campaign_malware(self, campaign_id: str) -> list[dict[str, Any]]:
        """List malware families used in a campaign."""
        resp = self.get(f"{_V4}/campaign/{campaign_id}/malware")
        return resp.get("malware", []) if isinstance(resp, dict) else []

    def get_campaign_indicators(self, campaign_id: str) -> list[dict[str, Any]]:
        """List indicators associated with a campaign."""
        resp = self.get(f"{_V4}/campaign/{campaign_id}/indicators")
        return resp.get("indicators", []) if isinstance(resp, dict) else []

    # ── Indicators (enriched lookups) ─────────────────────────────────────────

    def lookup_indicator(
        self,
        value: str,
        indicator_type: str = "",
    ) -> dict[str, Any]:
        """
        Direct indicator lookup by value.

        ``indicator_type`` options: ``"ipv4"``, ``"domain"``, ``"url"``,
        ``"md5"``, ``"sha256"``, ``"sha1"``.
        """
        params: dict[str, Any] = {"value": value}
        if indicator_type:
            params["type"] = indicator_type
        resp = self.get(f"{_V4}/indicator", params=params)
        indicators = resp.get("indicators", []) if isinstance(resp, dict) else []
        return indicators[0] if indicators else {}

    def get_indicator_actors(self, indicator_value: str) -> list[dict[str, Any]]:
        """List threat actors associated with an indicator value."""
        resp = self.get(
            f"{_V4}/indicator", params={"value": indicator_value, "with_actors": "true"}
        )
        data = resp.get("indicators", [{}])[0] if isinstance(resp, dict) else {}
        return data.get("actors", [])

    def get_indicator_malware(self, indicator_value: str) -> list[dict[str, Any]]:
        """List malware families associated with an indicator value."""
        resp = self.get(
            f"{_V4}/indicator", params={"value": indicator_value, "with_malware": "true"}
        )
        data = resp.get("indicators", [{}])[0] if isinstance(resp, dict) else {}
        return data.get("malware", [])

    # ── Attack patterns / MITRE ATT&CK ───────────────────────────────────────

    def list_attack_patterns(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List Mandiant ATT&CK technique mappings."""
        resp = self.get(
            f"{_V4}/attack-pattern",
            params={"limit": min(limit, 1000), "offset": offset},
        )
        return (
            resp.get("attack-patterns", resp.get("objects", [])) if isinstance(resp, dict) else []
        )

    def get_attack_pattern(self, attack_pattern_id: str) -> dict[str, Any]:
        """Retrieve a single ATT&CK technique by Mandiant ID."""
        resp = self.get(f"{_V4}/attack-pattern/{attack_pattern_id}")
        return resp if isinstance(resp, dict) else {}
