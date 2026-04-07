# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.pulsedive.client
==================================
PulseDive community threat intelligence API v1 connector.

The API key is passed as a query parameter (``key=``) on every request.
PulseDive is a community-driven TI platform with IOC enrichment, feeds,
and threat intelligence links.

INI config::

    [pulsedive]
    host    = https://pulsedive.com
    api_key = YOUR_PULSEDIVE_API_KEY
    auth_type = token

References
----------
https://pulsedive.com/api/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_API = "/api"

# PulseDive risk labels
_RISK_CONF = {"none": 0, "unknown": 10, "low": 30, "medium": 55, "high": 75, "critical": 95}


class PulseDiveClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the PulseDive Threat Intelligence API v1.

    Parameters
    ----------
    host : str
        PulseDive base URL.  Default ``https://pulsedive.com``.
    api_key : str
        PulseDive API key (anonymous requests are rate-limited).
    """

    stix_type_map: dict[str, str] = {
        "indicator": "indicator",
        "threat-actor": "threat",
        "malware": "threat",
    }

    def __init__(
        self,
        host: str = "https://pulsedive.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """PulseDive authenticates via ``key=`` query param; no headers needed."""
        # Key is injected into params at request time via _pd_params()

    def health_check(self) -> bool:
        """Verify API reachability with a simple info lookup."""
        resp = self.get(f"{_API}/info.php", params={**self._pd_params, "pretty": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Retrieve a PulseDive indicator or threat by ID.

        ``object_id`` is the PulseDive numeric ``iid`` (indicator ID) or
        ``tid`` (threat ID).
        """
        if stix_type in ("threat-actor", "malware"):
            resp = self.get(
                f"{_API}/info.php",
                params={**self._pd_params, "tid": object_id, "get": "threat"},
            )
        else:
            resp = self.get(
                f"{_API}/info.php",
                params={**self._pd_params, "iid": object_id, "get": "indicator"},
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
        Search PulseDive indicators or threats.

        ``filters`` may include:

        * ``indicator``: IOC value to look up directly
        * ``type``: ``"ip"``, ``"domain"``, ``"url"``, ``"hash"``
        * ``risk``: ``"low"``, ``"medium"``, ``"high"``, ``"critical"``
        """
        get_type = "threat" if stix_type in ("threat-actor", "malware") else "indicator"
        params: dict[str, Any] = {
            **self._pd_params,
            "get": get_type,
            "limit": min(page_size, 1000),
            "page": page,
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/browse.php", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("results", [])

    def enrich(self, indicator_value: str) -> dict[str, Any]:
        """
        Enrich a single IOC value via the ``/api/info.php`` endpoint.

        Returns the full PulseDive indicator record including risk score,
        linked threats, feeds, and attributes.
        """
        resp = self.get(
            f"{_API}/info.php",
            params={**self._pd_params, "indicator": indicator_value, "get": "indicator"},
        )
        return resp if isinstance(resp, dict) else {}

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Submit an indicator for community enrichment.

        Uses ``POST /api/info.php`` to add or update an indicator.
        """
        resp = self.post(
            f"{_API}/info.php",
            params=self._pd_params,
            json={
                "indicator": payload.get("value", payload.get("indicator", "")),
                "type": payload.get("type", "domain"),
            },
        )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("PulseDive API does not support delete operations.")

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a PulseDive indicator/threat to a STIX dict."""
        pd_type = native.get("type", "")
        if pd_type == "threat":
            return self._threat_to_stix(native)
        return self._indicator_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a PulseDive lookup payload from a STIX dict."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {"indicator": value, "type": self._stix_to_pd_type(pattern)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @property
    def _pd_params(self) -> dict[str, str]:
        if self._api_key:
            return {"key": self._api_key}
        return {}

    def _indicator_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        pd_type = native.get("type", "domain")
        value = native.get("indicator", "")
        pattern = self._make_pattern(pd_type, value)
        risk = native.get("risk", "unknown")
        conf = _RISK_CONF.get(risk.lower() if isinstance(risk, str) else "unknown", 10)
        threats = [t.get("name", "") for t in native.get("threats", []) if t.get("name")]
        return {
            "type": "indicator",
            "id": f"indicator--pd-{native.get('iid', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("stamp_added", ""),
            "modified": native.get("stamp_updated", ""),
            "confidence": conf,
            "indicator_types": ["malicious-activity"] if conf >= 50 else ["unknown"],
            "x_source_platform": "pulsedive",
            "x_pd_iid": native.get("iid", ""),
            "x_pd_risk": risk,
            "x_pd_type": pd_type,
            "x_pd_threats": threats,
        }

    def _threat_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "threat-actor",
            "id": f"threat-actor--pd-{native.get('tid', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "aliases": native.get("aliases", []),
            "created": native.get("stamp_added", ""),
            "modified": native.get("stamp_updated", ""),
            "x_source_platform": "pulsedive",
            "x_pd_tid": native.get("tid", ""),
            "x_pd_risk": native.get("risk", ""),
        }

    @staticmethod
    def _make_pattern(pd_type: str, value: str) -> str:
        t = (pd_type or "").lower()
        if t in ("ip",):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6",):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain",):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("hash",):
            if len(value) == 64:
                return f"[file:hashes.'SHA-256' = '{value}']"
            if len(value) == 40:
                return f"[file:hashes.'SHA-1' = '{value}']"
            return f"[file:hashes.'MD5' = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_pd_type(pattern: str) -> str:
        if "ipv4-addr" in pattern or "ipv6-addr" in pattern:
            return "ip"
        if "domain-name" in pattern:
            return "domain"
        if "url:" in pattern:
            return "url"
        if "file:hashes" in pattern:
            return "hash"
        return "domain"
