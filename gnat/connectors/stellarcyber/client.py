# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.stellarcyber.client
=======================================
Stellar Cyber Open XDR (Starlight) connector.

Uses JWT-based API key authentication.  The API key and username are
exchanged for a JWT token via ``POST /connect/api/v1/access_token``.

INI config::

    [stellarcyber]
    host      = https://your-tenant.stellarcyber.ai
    username  = admin
    api_key   = YOUR_STELLARCYBER_API_KEY
    auth_type = token

References
----------
https://stellarcyber.ai/docs/api/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_AUTH_PATH = "/connect/api/v1/access_token"
_API = "/connect/api/v1"


class StellarCyberClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Stellar Cyber Starlight XDR API.

    Parameters
    ----------
    host : str
        Stellar Cyber tenant base URL,
        e.g. ``https://your-tenant.stellarcyber.ai``.
    username : str
        Starlight admin username.
    api_key : str
        Starlight API key (generated under Settings → API Keys).
    """

    stix_type_map: dict[str, str] = {
        "indicator": "threat_intel",
        "observed-data": "alerts",
        "malware": "threat_intel",
        "threat-actor": "threat_intel",
    }

    def __init__(
        self,
        host: str,
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
        Exchange API key for a JWT Bearer token.

        Posts ``{"username": ..., "api_key": ...}`` to the token endpoint.
        """
        resp = self.post(
            _AUTH_PATH,
            json={"username": self._username, "api_key": self._api_key},
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("StellarCyber: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    def health_check(self) -> bool:
        """Check connectivity via a minimal alert query."""
        resp = self.get(f"{_API}/alerts", params={"size": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a Stellar Cyber alert or threat-intel record by ID."""
        resource = self.stix_type_map.get(stix_type, "alerts")
        resp = self.get(f"{_API}/{resource}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Stellar Cyber alerts or threat-intel indicators.

        ``filters`` may include:

        * ``query``: Lucene/DSL query string
        * ``from_time`` / ``to_time``: Unix epoch milliseconds
        * ``severity``: ``1``–``5``
        * ``status``: ``"new"``, ``"investigating"``, ``"closed"``
        """
        resource = self.stix_type_map.get(stix_type, "alerts")
        params: dict[str, Any] = {
            "from": (page - 1) * page_size,
            "size": min(page_size, 1000),
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/{resource}", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("data", resp.get("hits", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Submit threat-intel indicators to Stellar Cyber.

        Uses ``POST /api/v1/threat_intel`` for new records.
        """
        resource = self.stix_type_map.get(stix_type, "threat_intel")
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.put(f"{_API}/{resource}/{obj_id}", json=payload)
        else:
            resp = self.post(f"{_API}/{resource}", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a threat-intel record by ID."""
        resource = self.stix_type_map.get(stix_type, "threat_intel")
        self.delete(f"{_API}/{resource}/{object_id}")

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Stellar Cyber alert or TI record to a STIX dict."""
        # Distinguish alert from TI record by presence of typical alert fields
        if "srcip" in native or "dstip" in native or "alert_name" in native:
            return self._alert_to_stix(native)
        return self._ti_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a Stellar Cyber TI indicator payload from a STIX dict."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "indicator_value": value,
            "indicator_type": self._stix_to_sc_type(pattern),
            "confidence": stix_dict.get("confidence", 50),
            "source": "gnat",
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _alert_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        src_ip = native.get("srcip", "")
        dst_ip = native.get("dstip", "")
        pattern = f"[ipv4-addr:value = '{src_ip}']" if src_ip else "[domain-name:value = 'unknown']"
        severity = native.get("severity", 3)
        conf = min(100, int(severity / 5 * 100)) if isinstance(severity, (int, float)) else 50
        return {
            "type": "observed-data",
            "id": f"observed-data--sc-{native.get('_id', '')}",
            "name": native.get("alert_name", "Stellar Cyber Alert"),
            "description": native.get("msg", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "first_observed": native.get("timestamp", ""),
            "last_observed": native.get("timestamp", ""),
            "number_observed": 1,
            "created": native.get("timestamp", ""),
            "modified": native.get("timestamp", ""),
            "confidence": conf,
            "x_source_platform": "stellarcyber",
            "x_sc_id": native.get("_id", ""),
            "x_sc_src_ip": src_ip,
            "x_sc_dst_ip": dst_ip,
            "x_sc_severity": severity,
        }

    def _ti_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        ioc_type = native.get("indicator_type", native.get("type", ""))
        value = native.get("indicator_value", native.get("value", ""))
        pattern = self._make_pattern(ioc_type, value)
        conf = native.get("confidence", 50)
        return {
            "type": "indicator",
            "id": f"indicator--sc-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("created_at", ""),
            "modified": native.get("updated_at", ""),
            "confidence": conf,
            "indicator_types": ["malicious-activity"] if conf >= 50 else ["unknown"],
            "x_source_platform": "stellarcyber",
            "x_sc_type": ioc_type,
        }

    @staticmethod
    def _make_pattern(ioc_type: str, value: str) -> str:
        t = (ioc_type or "").lower()
        if t in ("ip", "ipv4", "srcip", "dstip"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("domain", "hostname"):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("md5",):
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("sha256",):
            return f"[file:hashes.'SHA-256' = '{value}']"
        if t in ("email",):
            return f"[email-message:from_ref.value = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_sc_type(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ip"
        if "domain-name" in pattern:
            return "domain"
        if "url:" in pattern:
            return "url"
        if "MD5" in pattern:
            return "md5"
        if "SHA-256" in pattern:
            return "sha256"
        return "domain"
