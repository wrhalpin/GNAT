"""
gnat.connectors.greynoise.client
================================

GreyNoise connector for IP reputation, noise classification, and RIOT intelligence.

Authentication
--------------
API key via `key` query parameter or `key` header (both supported; header preferred for v3)::

    [greynoise]
    host    = https://api.greynoise.io
    api_key = <your-greynoise-api-key>

Get your free Community or paid Enterprise API key at https://viz.greynoise.io/account/api-key.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | GreyNoise Resource               |
+================+==================================+
| observed-data  | IP context / noise lookup        |
+----------------+----------------------------------+
| indicator      | Malicious or scanning IPs        |
+----------------+----------------------------------+
| report         | RIOT business service data       |
+----------------+----------------------------------+

Key Endpoints (v3 API)
----------------------
* ``GET /v3/ip/{ip}`` or ``/v3/community/{ip}`` — Unified IP context (noise + RIOT)
* GNQL search support via query parameters (Enterprise)
* Community tier: limited free lookups; Enterprise: full context + GNQL

Notes
-----
* **Primarily read-only** — excellent for enrichment and triage (classify "noise" vs. real threats).
* Supports both Community (free) and Enterprise APIs via the same client.
* `list_objects()` and helpers support single/bulk IP lookups and basic GNQL queries.
* `to_stix()` maps responses to `observed-data` with rich `x_greynoise` extension (classification, tags, RIOT, etc.).
* Great for filtering false positives from SIEM/EDR alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GreyNoiseClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the GreyNoise v3 API (IP context, noise classification, RIOT).

    Parameters
    ----------
    host : str
        Base URL, default ``"https://api.greynoise.io"``.
    api_key : str
        GreyNoise API key (Community or Enterprise).
    """

    stix_type_map: Dict[str, str] = {
        "observed-data": "ip",
        "indicator": "ip",
        "report": "riot",
    }

    def __init__(self, host: str = "https://api.greynoise.io", api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject GreyNoise API key (header + query param fallback) and JSON headers."""
        self._auth_headers["key"] = self._api_key  # Header supported
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight connectivity check via a known endpoint (e.g., community IP or metadata)."""
        # Use a safe test IP or community endpoint
        self.get("/v3/community/8.8.8.8", params={"key": self._api_key})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch IP context by IP address (most common use case)."""
        if stix_type in ("observed-data", "indicator"):
            return self.ip_lookup(object_id)
        raise GNATClientError(f"get_object primarily supports IP lookups in GreyNoise")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Perform IP lookups or basic GNQL queries (Enterprise).

        Filters example: {"query": "classification:malicious port:445"}
        """
        filters = dict(filters or {})

        if stix_type in ("observed-data", "indicator"):
            if "query" in filters:
                # GNQL search (Enterprise)
                return self.gnql_query(filters["query"], limit=page_size)
            # Single or bulk IP context
            ips = filters.get("ips", [])
            if ips:
                return self.multi_ip_lookup(ips)
            return []  # Fallback

        raise GNATClientError(f"list_objects supports IP context or GNQL for GreyNoise")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError("GreyNoise is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("GreyNoise is read-only — no deletion supported.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Get full context for a single IP (noise + RIOT)."""
        params = {"key": self._api_key}
        return self.get(f"/v3/ip/{ip}", params=params)

    def community_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Community tier lookup (limited free usage)."""
        params = {"key": self._api_key}
        return self.get(f"/v3/community/{ip}", params=params)

    def multi_ip_lookup(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Bulk lookup (Enterprise; adapt payload as needed for v3)."""
        # v3 may use query params or POST; adjust based on exact docs
        params = {"key": self._api_key}
        # For simplicity, loop single lookups or use supported bulk if available
        results = []
        for ip in ips[:50]:  # Rate limit aware
            try:
                results.append(self.ip_lookup(ip))
            except Exception:
                pass
        return results

    def gnql_query(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """GNQL search query (Enterprise tier)."""
        params = {"query": query, "limit": limit, "key": self._api_key}
        resp = self.get("/v3/gnql", params=params)  # Adjust exact path if needed
        return resp.get("data", []) if isinstance(resp, dict) else []

    def riot_lookup(self, ip: str) -> Dict[str, Any]:
        """RIOT business service intelligence (benign services)."""
        params = {"key": self._api_key}
        return self.get(f"/v3/riot/{ip}", params=params)  # If separate; often included in /v3/ip

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate GreyNoise IP context to STIX 2.1 observed-data or indicator.

        Includes classification (noise/malicious/benign), tags, RIOT, and raw context.
        """
        now = _now_ts()
        ip = native.get("ip", "")

        # Determine classification
        classification = native.get("classification", "unknown")
        if classification == "malicious" or native.get("seen", False):
            stix_type = "indicator"
        else:
            stix_type = "observed-data"

        return {
            "type": stix_type,
            "id": f"{stix_type}--greynoise-{ip.replace('.', '-')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"GreyNoise Context for {ip}",
            "description": f"Classification: {classification}",
            "x_greynoise": {
                "ip": ip,
                "classification": classification,
                "tags": native.get("tags", []),
                "riot": native.get("riot", {}),
                "actor": native.get("actor"),
                "vpn": native.get("vpn"),
                "bot": native.get("bot"),
                "last_seen": native.get("last_seen"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """GreyNoise is read-only. Returns enrichment guidance."""
        return {
            "note": "GreyNoise connector is read-only. Use ip_lookup or gnql_query helpers for enrichment.",
            "stix_id": stix_dict.get("id", ""),
        }