"""
gnat.connectors.censys.client
================================

Censys Internet Intelligence / Attack Surface Management connector.

Authentication
--------------
API ID + Secret pair (Basic auth)::

    [censys]
    host      = https://search.censys.io
    api_id    = <censys-api-id>
    api_secret = <censys-api-secret>

STIX Type Mapping
-----------------
+------------------+----------------------------------+
| STIX Type        | Censys Resource                  |
+==================+==================================+
| observed-data    | Host search results              |
+------------------+----------------------------------+
| vulnerability    | CVE exposures on hosts           |
+------------------+----------------------------------+

Key Endpoints (Censys Search v2)
---------------------------------
* /api/v2/hosts/search          — Host search with cursor pagination
* /api/v2/hosts/{ip}            — Single host detail
* /api/v2/hosts/{ip}/comments   — Analyst comments on a host
* /api/v2/certificates/search   — Certificate search
* /api/v1/data/universal_internet_dataset_v2/ — Legacy datasets
"""

from __future__ import annotations

import base64
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a7b8c9d0-e1f2-3456-0123-789012345678")


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CensysClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Censys Search v2 and ASM APIs.

    Parameters
    ----------
    host : str
        Censys API base URL (``"https://search.censys.io"`` for search,
        ``"https://app.censys.io"`` for ASM).
    api_id : str
        Censys API ID (used for Basic auth).
    api_secret : str
        Censys API secret.
    """

    stix_type_map: Dict[str, str] = {
        "observed-data": "hosts",
        "vulnerability": "hosts",
    }

    def __init__(
        self,
        host: str = "https://search.censys.io",
        api_id: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_id     = api_id
        self._api_secret = api_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject HTTP Basic auth header (API ID + secret)."""
        if not self._api_id or not self._api_secret:
            raise GNATClientError("Censys: api_id and api_secret are required")
        creds = base64.b64encode(
            f"{self._api_id}:{self._api_secret}".encode()
        ).decode()
        self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify API access via a minimal host search."""
        self.post("/api/v2/hosts/search", json={"q": "services.port=443", "per_page": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """
        Fetch details for a single IP host.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` or ``"vulnerability"``.
        object_id : str
            IPv4 or IPv6 address.
        """
        resp = self.get(f"/api/v2/hosts/{object_id}")
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str = "observed-data",
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search hosts using Censys Search Language (CSL).

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` or ``"vulnerability"``.
        filters : dict, optional
            Censys search parameters.  Must include ``"q"`` (CSL query string).
        page_size : int
            Results per page (max 100).
        """
        query = (filters or {}).get("q", "services.port=443")
        cursor = (filters or {}).get("cursor")
        payload: Dict[str, Any] = {"q": query, "per_page": page_size}
        if cursor:
            payload["cursor"] = cursor
        resp = self.post("/api/v2/hosts/search", json=payload)
        return resp.get("result", {}).get("hits", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Censys Search is read-only; upsert not supported."""
        raise GNATClientError("Censys Search connector is read-only — no write API available.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Censys Search is read-only; delete not supported."""
        raise GNATClientError("Censys Search connector is read-only — no delete API available.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def search_hosts(
        self,
        query: str,
        per_page: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a Censys Search Language host search.

        Parameters
        ----------
        query : str
            CSL query string (e.g. ``"services.port=22 and location.country=US"``).
        per_page : int
            Results per page (max 100).
        cursor : str, optional
            Pagination cursor from a previous response.

        Returns
        -------
        dict
            Full Censys response including ``result.hits`` and ``result.links``.
        """
        payload: Dict[str, Any] = {"q": query, "per_page": per_page}
        if cursor:
            payload["cursor"] = cursor
        resp = self.post("/api/v2/hosts/search", json=payload)
        return resp if isinstance(resp, dict) else {}

    def get_host(self, ip_address: str) -> Dict[str, Any]:
        """
        Fetch the full current scan data for an IP address.

        Parameters
        ----------
        ip_address : str
            IPv4 or IPv6 address to look up.
        """
        resp = self.get(f"/api/v2/hosts/{ip_address}")
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def get_host_history(self, ip_address: str, per_page: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve historical scan records for an IP address.

        Parameters
        ----------
        ip_address : str
            Target IP address.
        per_page : int
            Records per page.
        """
        resp = self.get(f"/api/v2/hosts/{ip_address}/history",
                        params={"per_page": per_page})
        return resp.get("result", {}).get("hits", []) if isinstance(resp, dict) else []

    def search_certificates(self, query: str, per_page: int = 100) -> List[Dict[str, Any]]:
        """
        Search TLS/SSL certificates in Censys.

        Parameters
        ----------
        query : str
            CSL query against the certificate index
            (e.g. ``"parsed.subject_dn:*.evil.com"``).
        per_page : int
            Results per page.
        """
        resp = self.post("/api/v2/certificates/search",
                         json={"q": query, "per_page": per_page})
        return resp.get("result", {}).get("hits", []) if isinstance(resp, dict) else []

    def get_bulk_hosts(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Fetch current host data for multiple IP addresses in one call.

        Parameters
        ----------
        ip_addresses : list of str
            List of IPv4/IPv6 addresses (max 100 per request).
        """
        resp = self.post("/api/v2/hosts/bulk", json={"ips": ip_addresses[:100]})
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Censys host record to a STIX 2.1 ``observed-data`` object."""
        ip = native.get("ip", "")
        now = _now_ts()
        last_updated = native.get("last_updated_at", now)
        services = native.get("services", [])
        vuln_cves: List[str] = []
        for svc in services:
            for vuln in svc.get("vulnerabilities", []):
                cve_id = vuln.get("cve_id", "")
                if cve_id:
                    vuln_cves.append(cve_id)
        stix: Dict[str, Any] = {
            "type":            "observed-data",
            "id":              f"observed-data--{_uuid.uuid5(_STIX_NS, f'censys:{ip}')}",
            "spec_version":    "2.1",
            "created":         last_updated,
            "modified":        last_updated,
            "first_observed":  last_updated,
            "last_observed":   last_updated,
            "number_observed": 1,
            "object_refs":     [],
            "x_censys": {
                "ip":           ip,
                "country":      native.get("location", {}).get("country"),
                "asn":          native.get("autonomous_system", {}).get("asn"),
                "org":          native.get("autonomous_system", {}).get("name"),
                "services":     [
                    {"port": s.get("port"), "transport_protocol": s.get("transport_protocol"),
                     "service_name": s.get("service_name")}
                    for s in services
                ],
                "open_ports":   [s.get("port") for s in services if s.get("port")],
            },
        }
        if vuln_cves:
            stix["x_censys"]["exposed_cves"] = list(set(vuln_cves))
        return stix

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Return a Censys host lookup reference from a STIX object."""
        return {
            "note":      "Censys Search is read-only.",
            "stix_id":   stix_dict.get("id", ""),
            "stix_type": stix_dict.get("type", ""),
        }
