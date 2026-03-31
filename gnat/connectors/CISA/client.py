"""
gnat.connectors.cisa.client
===========================

CISA connector for the Known Exploited Vulnerabilities (KEV) Catalog and related public feeds.

Authentication
--------------
No authentication required — public JSON feed.

Configuration::

    [cisa]
    host = https://www.cisa.gov
    # No api_key or credentials needed

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | CISA Resource                    |
+================+==================================+
| vulnerability  | KEV Catalog entries              |
+----------------+----------------------------------+
| report         | Catalog metadata / advisories    |
+----------------+----------------------------------+

Key Endpoints / Feeds
---------------------
* ``/sites/default/files/feeds/known_exploited_vulnerabilities.json`` — Full KEV Catalog (recommended primary source)
* CSV version also available but JSON is preferred for structured parsing
* Cybersecurity Advisories / ICS Advisories (RSS or HTML scraping possible as future extension)

Notes
-----
* **Read-only** public data source — no write operations.
* The KEV Catalog lists vulnerabilities with confirmed active exploitation (high prioritization value).
* Each entry includes CVE ID, vendor/project, product, date added, short description, required action, and due date.
* Ideal for vulnerability enrichment, prioritization, and threat hunting.
* `list_objects()` returns the full or filtered catalog; `to_stix()` maps directly to STIX `vulnerability` objects with rich `x_cisa_kev` extension.
* Lightweight and always up-to-date via direct fetch from cisa.gov.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CISAClient(BaseClient, ConnectorMixin):
    """
    HTTP client for CISA public feeds, primarily the Known Exploited Vulnerabilities (KEV) Catalog.

    Parameters
    ----------
    host : str
        Base URL, default ``"https://www.cisa.gov"``.
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "kev",
        "report": "catalog",
    }

    def __init__(self, host: str = "https://www.cisa.gov", **kwargs: Any):
        super().__init__(host=host, **kwargs)

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No authentication required for public CISA feeds."""
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity by fetching a small portion of the KEV catalog."""
        self.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json", params={"_": "1"})  # cache-buster if needed
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch the full catalog and filter for a specific CVE (object_id = CVE-ID)."""
        if stix_type == "vulnerability":
            catalog = self.list_objects("vulnerability")
            for entry in catalog:
                if entry.get("cveID") == object_id:
                    return entry
            raise GNATClientError(f"CVE {object_id} not found in CISA KEV catalog")
        raise GNATClientError(f"get_object limited to vulnerability/CVE lookup in CISA")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 1000,  # KEV catalog is small (~1000-2000 entries)
    ) -> List[Dict[str, Any]]:
        """
        Fetch the KEV Catalog (full list or filtered).

        Filters example: {"vendorProject": "Microsoft", "dateAdded__gte": "2025-01-01"}
        """
        if stix_type not in ("vulnerability", "report"):
            raise GNATClientError(f"list_objects supports vulnerability/report for CISA KEV")

        resp = self.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        catalog = resp.get("vulnerabilities", []) if isinstance(resp, dict) else []

        # Simple in-memory filtering (catalog is small)
        filters = dict(filters or {})
        if filters:
            filtered = []
            for entry in catalog:
                match = True
                for key, value in filters.items():
                    if key == "cveID" and entry.get("cveID") != value:
                        match = False
                    elif key.endswith("__gte") and entry.get(key.replace("__gte", "")) < value:
                        match = False
                    # Add more simple filters as needed
                if match:
                    filtered.append(entry)
            catalog = filtered

        # Basic pagination support
        start = (page - 1) * page_size
        return catalog[start : start + page_size]

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError("CISA connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("CISA connector is read-only — no deletion supported.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def get_kev_catalog(self) -> Dict[str, Any]:
        """Fetch the full raw KEV catalog with metadata."""
        return self.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    def get_kev_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Convenience: Find a specific KEV entry by CVE ID."""
        catalog = self.list_objects("vulnerability")
        for entry in catalog:
            if entry.get("cveID") == cve_id:
                return entry
        return None

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate a CISA KEV entry to STIX 2.1 vulnerability object.

        Includes required action, due date, and full context in x_cisa_kev extension.
        """
        now = _now_ts()
        cve = native.get("cveID", "")
        if not cve:
            # Fallback for catalog metadata
            return {
                "type": "report",
                "id": f"report--cisa-kev-catalog-{now.replace(':', '')}",
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": "CISA Known Exploited Vulnerabilities Catalog",
                "x_cisa": native,
            }

        return {
            "type": "vulnerability",
            "id": f"vulnerability--{cve.lower()}",
            "spec_version": "2.1",
            "created": native.get("dateAdded") or now,
            "modified": now,
            "name": cve,
            "description": native.get("shortDescription", ""),
            "external_references": [
                {
                    "source_name": "cisa-kev",
                    "external_id": cve,
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={cve}",
                }
            ],
            "x_cisa_kev": {
                "cve_id": cve,
                "vendor_project": native.get("vendorProject"),
                "product": native.get("product"),
                "date_added": native.get("dateAdded"),
                "required_action": native.get("requiredAction"),
                "due_date": native.get("dueDate"),
                "known_ransomware_campaign_use": native.get("knownRansomwareCampaignUse"),
                "notes": native.get("notes"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """CISA is read-only. Returns informational dict."""
        return {
            "note": "CISA connector is read-only. Use get_kev_by_cve or list_objects for KEV enrichment.",
            "stix_id": stix_dict.get("id", ""),
        }