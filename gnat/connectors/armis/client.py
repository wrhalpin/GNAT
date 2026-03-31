"""
gnat.connectors.armis.client
============================

Armis Centrix (Cyber Exposure Management for IT/OT/IoT) connector — full client.

Authentication
--------------
API Secret Key via ``x-api-key`` header::

    [armis]
    host     = https://ic.armis.com          # or your tenant subdomain (e.g. https://yourcompany.armis.com)
    api_key  = <your-armis-api-secret-key>

Generate the key in Armis Centrix UI → Settings → API Management → Create Secret Key.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Armis Resource                   |
+================+==================================+
| report         | Devices / Assets                 |
+----------------+----------------------------------+
| vulnerability  | CVEs / Vulnerabilities           |
+----------------+----------------------------------+

Key Endpoints (API v1/v3)
-------------------------
* /api/v1/device/_search          — Search devices/assets
* /api/v1/cve/_search             — Search vulnerabilities/CVEs
* /api/v1/device/{id}             — Single device details

Notes
-----
* Strong on unmanaged/IoT/OT asset visibility and risk context.
* Supports search with filters (category, risk, etc.).
* Complements your Axonius (unified assets), CyCognito/Xpanse (external), and Greenbone (scanning) connectors.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d5e6f7a8-b9c0-1d2e-3f4a-5b6c7d8e9f0a")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ArmisClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Armis Centrix API.

    Parameters
    ----------
    host : str
        Base URL (e.g. "https://ic.armis.com" or "https://yourcompany.armis.com").
    api_key : str
        Armis API secret key.
    """

    stix_type_map: dict[str, str] = {
        "report":        "devices",
        "vulnerability": "cves",
    }

    def __init__(self, host: str = "https://ic.armis.com", api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject x-api-key header."""
        self._auth_headers["x-api-key"] = self._api_key
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via device search."""
        self.get("/api/v1/device/_search", params={"length": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "report":
            return self.get(f"/api/v1/device/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/api/v1/cve/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Armis: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        params: dict[str, Any] = {"length": page_size, "from": (page - 1) * page_size}
        params.update(filters)

        if stix_type == "vulnerability":
            resp = self.get("/api/v1/cve/_search", params=params)
            return resp.get("results", []) if isinstance(resp, dict) else []
        # Default: devices/assets
        resp = self.get("/api/v1/device/_search", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Armis connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_devices(
        self,
        limit: int = 50,
        category: str | None = None,  # e.g. "Computers", "IoT", "OT"
        risk_level: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch devices/assets with optional filters."""
        params: dict[str, Any] = {"length": limit}
        if category:
            params["category"] = category
        if risk_level:
            params["risk_level"] = risk_level
        resp = self.get("/api/v1/device/_search", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def fetch_vulnerabilities(
        self,
        limit: int = 50,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch CVE/vulnerability data."""
        params: dict[str, Any] = {"length": limit}
        if category:
            params["category"] = category
        resp = self.get("/api/v1/cve/_search", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch device (report) vs. CVE (vulnerability)."""
        if "cve" in str(native).lower() or "vulnerability" in str(native).lower():
            return self._vuln_to_stix(native)
        return self._device_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "Armis is read-only for asset and vulnerability exposure data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _device_to_stix(self, device: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        did = device.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'armis:{did}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"Armis Device: {device.get('name', did)}",
            "description": f"Unmanaged or managed asset of type {device.get('type', 'unknown')}",
            "report_types": ["asset-inventory"],
            "x_armis": {
                "device_id": did,
                "type": device.get("type"),
                "risk_level": device.get("risk_level"),
                "category": device.get("category"),
                "ip": device.get("ip"),
            },
        }

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        vid = vuln.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'armis:{vid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": vuln.get("title", "Armis CVE"),
            "description": vuln.get("description", ""),
            "external_references": [{"source_name": "armis", "external_id": vid}],
            "x_armis": {
                "vuln_id": vid,
                "cve_id": vuln.get("cve_id"),
                "severity": vuln.get("severity"),
                "affected_devices": vuln.get("affected_devices_count", 0),
            },
        }
