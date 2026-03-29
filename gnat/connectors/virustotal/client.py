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

from typing import Any, Dict, List, Optional
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

    stix_type_map: Dict[str, str] = {
        "indicator":    "files",
        "malware":      "collections",
        "threat-actor": "threat_actors",
        "vulnerability": "files",
    }

    # Mapping VT entity type → STIX pattern template
    _PATTERN_MAP: Dict[str, str] = {
        "ip_address":    "[ipv4-addr:value = '{v}']",
        "domain":        "[domain-name:value = '{v}']",
        "url":           "[url:value = '{v}']",
        "file":          "[file:hashes.'SHA-256' = '{v}']",
    }

    def __init__(self, host: str = "https://www.virustotal.com",
                 api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    def authenticate(self) -> None:
        """Inject the VT API key header."""
        self._auth_headers["x-apikey"] = self._api_key

    def health_check(self) -> bool:
        resp = self.get("/api/v3/domains/google.com",
                        params={"fields": "id,type"})
        return isinstance(resp, dict) and "data" in resp

    def get_object(self, stix_type: str,
                   object_id: str) -> Dict[str, Any]:
        """
        Retrieve one VT entity.

        ``object_id`` is the raw VT identifier — a hash, domain, IP, or URL.
        For URLs, pass the URL-safe base64-encoded form or the raw URL
        (the connector handles encoding).
        """
        vt_type = self._stix_to_vt_type(stix_type, object_id)
        if vt_type == "urls":
            import base64
            encoded = base64.urlsafe_b64encode(
                object_id.encode()
            ).decode().rstrip("=")
            resp = self.get(f"/api/v3/urls/{encoded}")
        else:
            resp = self.get(f"/api/v3/{vt_type}/{object_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(self, stix_type: str,
                     filters: Optional[Dict[str, Any]] = None,
                     page: int = 1,
                     page_size: int = 40) -> List[Dict[str, Any]]:
        """
        Search VT entities by STIX type.

        ``filters`` supports:
        - ``query`` (str): VT Intelligence search query
          e.g. ``"type:peexe tag:ransomware"``
        - ``cursor`` (str): pagination cursor from previous response
        """
        query  = (filters or {}).get("query", "")
        cursor = (filters or {}).get("cursor", "")
        params: Dict[str, Any] = {"limit": min(page_size, 300)}
        if query:
            params["query"] = query
        if cursor:
            params["cursor"] = cursor

        # Map STIX type to VT collection endpoint
        endpoint_map = {
            "indicator":    "/api/v3/intelligence/search",
            "malware":      "/api/v3/collections",
            "threat-actor": "/api/v3/threat_actors",
        }
        endpoint = endpoint_map.get(stix_type, "/api/v3/intelligence/search")
        resp     = self.get(endpoint, params=params)

        if not isinstance(resp, dict):
            return []
        data = resp.get("data", [])
        return data if isinstance(data, list) else []

    def upsert_object(self, stix_type: str,
                      payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError(
            "VirusTotal API is read-only — upsert not supported. "
            "Use VT Intelligence to submit files: "
            "https://docs.virustotal.com/reference/files"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError(
            "VirusTotal API is read-only — delete not supported."
        )

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a VT API ``data`` object to a STIX dict.

        Handles files, domains, IPs, URLs, and collections (malware families).
        """
        attrs    = native.get("attributes", {})
        vt_id    = native.get("id", "")
        vt_type  = native.get("type", "file")

        if vt_type in ("domain", "ip_address", "url", "file"):
            return self._entity_to_indicator(native, attrs, vt_id, vt_type)
        if vt_type in ("collection", "threat_actor"):
            return self._collection_to_malware(native, attrs, vt_id)
        # Fallback: generic indicator
        return self._entity_to_indicator(native, attrs, vt_id, "file")

    def _entity_to_indicator(
        self,
        native: Dict[str, Any],
        attrs:  Dict[str, Any],
        vt_id:  str,
        vt_type: str,
    ) -> Dict[str, Any]:
        """Build an Indicator STIX dict from a VT file/domain/IP/URL."""
        # Determine IOC value and pattern
        if vt_type == "file":
            sha256  = attrs.get("sha256", vt_id)
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
            name    = attrs.get("meaningful_name") or sha256[:16]
        elif vt_type == "domain":
            pattern = f"[domain-name:value = '{vt_id}']"
            name    = vt_id
        elif vt_type == "ip_address":
            pattern = f"[ipv4-addr:value = '{vt_id}']"
            name    = vt_id
        elif vt_type == "url":
            import urllib.parse
            decoded = urllib.parse.unquote(vt_id)
            pattern = f"[url:value = '{decoded}']"
            name    = decoded[:80]
        else:
            pattern = f"[domain-name:value = '{vt_id}']"
            name    = vt_id

        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        total      = sum(stats.values()) if stats else 0
        confidence = min(100, int((malicious / max(total, 1)) * 100))

        # Target sectors from popular threat categories
        categories = attrs.get("popular_threat_category", {})
        sectors    = list({v for v in categories.values() if v}) if categories else []

        return {
            "type":             "indicator",
            "id":               f"indicator--vt-{vt_id[:36]}",
            "name":             name,
            "pattern":          pattern,
            "pattern_type":     "stix",
            "created":          attrs.get("first_submission_date", ""),
            "modified":         attrs.get("last_modification_date", ""),
            "confidence":       confidence,
            "indicator_types":  ["malicious-activity"] if malicious > 0 else ["unknown"],
            "x_source_platform":"virustotal",
            "x_vt_malicious":   malicious,
            "x_vt_total":       total,
            "x_vt_type":        vt_type,
            "x_vt_tags":        attrs.get("tags", [])[:10],
            "x_target_sectors": sectors,   # canonical sector field
        }

    def _collection_to_malware(
        self,
        native: Dict[str, Any],
        attrs:  Dict[str, Any],
        vt_id:  str,
    ) -> Dict[str, Any]:
        """Build a Malware STIX dict from a VT collection/threat_actor."""
        return {
            "type":             "malware",
            "id":               f"malware--vt-{vt_id[:36]}",
            "name":             attrs.get("name", vt_id),
            "description":      attrs.get("description", "")[:500],
            "is_family":        True,
            "created":          attrs.get("creation_date", ""),
            "modified":         attrs.get("modification_date", ""),
            "x_source_platform":"virustotal",
            "x_vt_collection_id": vt_id,
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a VT-queryable identifier from a STIX dict."""
        name    = stix_dict.get("name", "")
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
            return "files"       # hash length
        if object_id.startswith(("http://", "https://")):
            return "urls"
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", object_id):
            return "ip_addresses"
        return "domains"
