# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.axonius.client
==============================

Axonius (Cybersecurity Asset Management) connector — full client.

Authentication
--------------
API Key + API Secret via Basic Auth (or Bearer in some setups)::

    [axonius]
    host       = https://your-axonius-instance.com
    api_key    = <your-axonius-api-key>
    api_secret = <your-axonius-api-secret>

Generate keys in Axonius UI (Settings → API Keys).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Axonius Resource                 |
+================+==================================+
| report         | Assets (unified inventory)       |
+----------------+----------------------------------+
| vulnerability  | Vulnerabilities / exposures      |
+----------------+----------------------------------+

Key Endpoints (API v2)
----------------------
* /api/v2/assets              — Unified asset inventory (600+ adapters)
* /api/v2/vulnerabilities     — Vulnerability findings
* /api/v2/devices             — Device-specific data
* /api/v2/queries             — Saved queries and correlations

Notes
-----
* Extremely strong on asset correlation and normalization.
* Supports complex filters and saved queries.
* Complements your CyCognito, Orca, Wiz, and Greenbone connectors by providing a unified asset view.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c5d6e7f8-9a0b-1c2d-3e4f-5a6b7c8d9e0f")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AxoniusClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Axonius API v2.

    Parameters
    ----------
    host : str
        Base URL of your Axonius instance.
    api_key : str
        Axonius API key.
    api_secret : str
        Axonius API secret.
    """

    stix_type_map: dict[str, str] = {
        "report": "assets",
        "vulnerability": "vulnerabilities",
    }

    def __init__(self, host: str, api_key: str = "", api_secret: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_secret = api_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Basic Auth with API key + secret."""
        self._auth_headers["Authorization"] = self._basic_auth(self._api_key, self._api_secret)
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via assets endpoint."""
        self.get("/api/v2/assets", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "report":
            return self.get(f"/api/v2/assets/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/api/v2/vulnerabilities/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Axonius: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size, "page": page}
        params.update(filters)

        if stix_type == "vulnerability":
            resp = self.get("/api/v2/vulnerabilities", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: unified assets
        resp = self.get("/api/v2/assets", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Axonius connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_assets(
        self,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch unified asset inventory with optional filters."""
        params: dict[str, Any] = {"limit": limit, **(filters or {})}
        resp = self.get("/api/v2/assets", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_vulnerabilities(
        self,
        limit: int = 100,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch correlated vulnerabilities."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        resp = self.get("/api/v2/vulnerabilities", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def run_query(self, query_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Execute a saved Axonius query."""
        resp = self.get(f"/api/v2/queries/{query_id}/run", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch asset vs. vulnerability."""
        if "vulnerabilities" in native or "severity" in native and "cve" in str(native).lower():
            return self._vuln_to_stix(native)
        return self._asset_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "Axonius is read-only for asset and vulnerability data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _asset_to_stix(self, asset: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        aid = asset.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'axonius:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"Axonius Asset: {asset.get('name', aid)}",
            "description": "Unified asset record from Axonius",
            "report_types": ["asset-inventory"],
            "x_axonius": {
                "asset_id": aid,
                "adapters": asset.get("adapters", []),
                "hostname": asset.get("hostname"),
                "ip_addresses": asset.get("ip_addresses", []),
                "risk_score": asset.get("risk_score"),
            },
        }

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        vid = vuln.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'axonius:{vid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": vuln.get("title", "Axonius Vulnerability"),
            "description": vuln.get("description", ""),
            "external_references": [{"source_name": "axonius", "external_id": vid}],
            "x_axonius": {
                "vuln_id": vid,
                "severity": vuln.get("severity"),
                "cve_id": vuln.get("cve_id"),
                "asset_count": vuln.get("asset_count"),
            },
        }
