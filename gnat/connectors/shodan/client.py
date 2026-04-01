"""
gnat.connectors.shodan.client
=============================

Shodan connector for host lookups, searches, and exploit/vulnerability intelligence.

Authentication
--------------
API key as query parameter (`key=...`) or `X-API-Key` header::

    [shodan]
    host    = https://api.shodan.io
    api_key = <your-shodan-api-key>

Get your free/paid API key at https://account.shodan.io/.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Shodan Resource                  |
+================+==================================+
| observed-data  | Host details (open ports, banners)|
+----------------+----------------------------------+
| indicator      | IP, domain, vulnerability data   |
+----------------+----------------------------------+
| vulnerability  | CVEs and exploits                |
+----------------+----------------------------------+
| report         | Search summaries / aggregates    |
+----------------+----------------------------------+

Key Endpoints (base: https://api.shodan.io)
-------------------------------------------
* ``GET /shodan/host/{ip}``               — Detailed host information (ports, banners, vulns)
* ``GET /shodan/host/search``             — Search hosts (query, facets, pagination)
* ``GET /shodan/host/count``              — Count results without full data
* ``GET /shodan/exploits/search``         — Search exploits (via exploits.shodan.io)
* ``GET /shodan/ports`` / ``/shodan/protocols`` — Utility lookups

Notes
-----
* **Read-only** — Shodan provides discovery/intel, no write operations.
* `list_objects()` dispatches by STIX type with rich domain helpers (`host_lookup`, `search_hosts`).
* `to_stix()` maps host data to `observed-data` (with services) or `vulnerability` objects.
* Excellent complement to Censys for external attack surface management and threat hunting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ShodanClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Shodan REST API (host search + exploit intelligence).

    Parameters
    ----------
    host : str
        Base URL, default ``"https://api.shodan.io"``.
    api_key : str
        Shodan API key.
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "host",
        "indicator": "host",
        "vulnerability": "exploit",
        "report": "search",
    }

    def __init__(self, host: str = "https://api.shodan.io", api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Shodan API key as query parameter (preferred) and JSON headers."""
        # Many Shodan endpoints expect ?key=...
        # BaseClient can append it via params; we also set header for flexibility
        self._auth_headers["X-API-Key"] = self._api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via account info or a lightweight endpoint."""
        # /api-info is a good lightweight check
        self.get("/api-info")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single host by IP (most common use case)."""
        if stix_type in ("observed-data", "indicator"):
            return self.host_lookup(object_id)
        raise GNATClientError(
            f"get_object limited for {stix_type} in Shodan (use host_lookup helper)"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search hosts or exploits.

        Common filters for hosts:
            query (Shodan search syntax), facets, minify
        """
        filters = dict(filters or {})

        if stix_type in ("observed-data", "indicator", "report"):
            return self.search_hosts(
                query=filters.get("query", ""),
                page=page,
                limit=page_size,
                **{k: v for k, v in filters.items() if k != "query"},
            )

        if stix_type == "vulnerability":
            # Use exploits search (separate base if needed)
            return self.search_exploits(query=filters.get("query", ""), page=page, limit=page_size)

        raise GNATClientError(f"list_objects not implemented for STIX type {stix_type} in Shodan")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Shodan is read-only — no object creation or updates supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Shodan is read-only — no deletion supported.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def host_lookup(self, ip: str) -> dict[str, Any]:
        """Get detailed information about a single IP/host."""
        return self.get(f"/shodan/host/{ip}", params={"key": self._api_key})

    def search_hosts(
        self,
        query: str = "",
        page: int = 1,
        limit: int = 100,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Search Shodan for hosts matching a query (Shodan search syntax)."""
        params = {
            "query": query,
            "page": page,
            "limit": limit,
            "key": self._api_key,
            **kwargs,
        }
        resp = self.get("/shodan/host/search", params=params)
        return resp.get("matches", []) if isinstance(resp, dict) else []

    def search_exploits(
        self,
        query: str = "",
        page: int = 1,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search the Shodan Exploits database (uses exploits.shodan.io)."""
        # Note: exploits API has its own base URL in some cases
        params = {"query": query, "page": page, "key": self._api_key}
        # Switch to exploits base if needed; for simplicity we can override or use full URL
        resp = self.get("https://exploits.shodan.io/api/search", params=params)
        return resp.get("matches", []) if isinstance(resp, dict) else []

    def count_hosts(self, query: str = "") -> dict[str, Any]:
        """Get count of matching hosts without returning full results."""
        params = {"query": query, "key": self._api_key}
        return self.get("/shodan/host/count", params=params)

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate Shodan host, match, or exploit to STIX 2.1.

        Dispatches based on presence of 'ip_str', 'port', or CVE data.
        """
        now = _now_ts()

        if "ip_str" in native or "ports" in native:
            return self._host_to_stix(native, now)
        if "cve" in native or "exploit" in str(native).lower():
            return self._exploit_to_stix(native, now)
        # Generic fallback
        return {
            "type": "report",
            "id": f"report--shodan-{hash(str(native)) % 10**12}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Shodan Intelligence",
            "x_shodan": native,
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Shodan is read-only. Returns informational dict."""
        return {
            "note": "Shodan connector is read-only. Use host_lookup or search_hosts helpers.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _host_to_stix(self, host: dict[str, Any], now: str) -> dict[str, Any]:
        """Map Shodan host record to STIX observed-data with services."""
        ip = host.get("ip_str", "")
        host_id = f"observed-data--shodan-{ip.replace('.', '-')}"
        return {
            "type": "observed-data",
            "id": host_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": host.get("timestamp"),
            "last_observed": host.get("timestamp"),
            "number_observed": 1,
            "x_shodan_host": {
                "ip": ip,
                "hostname": host.get("hostnames", []),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "vulns": host.get("vulns", {}),
                "tags": host.get("tags", []),
                "raw": host,
            },
        }

    def _exploit_to_stix(self, exploit: dict[str, Any], now: str) -> dict[str, Any]:
        """Map Shodan exploit data to STIX vulnerability."""
        cve = exploit.get("cve", exploit.get("id", ""))
        return {
            "type": "vulnerability",
            "id": f"vulnerability--shodan-{cve}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": cve or "Shodan Exploit",
            "description": exploit.get("description", ""),
            "x_shodan_exploit": exploit,
        }
