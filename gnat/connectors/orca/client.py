# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.orca.client
===========================

Orca Security (Agentless Cloud CNAPP) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [orca]
    host      = https://api.orcasecurity.io          # or region-specific (e.g. app.us.orcasecurity.io)
    api_token = <your-orca-api-token>

Generate token in Orca UI → Settings → API & Integrations (or Users & Permissions → API).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Orca Resource                    |
+================+==================================+
| vulnerability  | Vulnerabilities / findings       |
+----------------+----------------------------------+
| report         | Assets, misconfigurations, API risks |
+----------------+----------------------------------+

Key Endpoints (2026 Orca API)
-----------------------------
* /v1/assets                         — Cloud assets inventory
* /v1/findings                       — Security findings / risks
* /v1/alerts                         — Alerts with context
* /v1/api-security                   — API inventory & risks (newer capability)

Notes
-----
* Agentless platform with deep context (workload, identity, data, API).
* Supports filtering by severity, resource type, cloud provider.
* Read-heavy for ingestion; some write for ticketing/integration.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d4e5f678-90ab-cdef-1234-56789abcdef0")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class OrcaClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Orca Security API.

    Parameters
    ----------
    host : str
        Base API URL (e.g. "https://api.orcasecurity.io" or region-specific).
    api_token : str
        Orca API token.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "vulnerability": "findings",
        "report": "assets",
    }

    def __init__(
        self, host: str = "https://api.orcasecurity.io", api_token: str = "", **kwargs: Any
    ):
        """Initialize OrcaClient."""
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via assets or findings."""
        self.get("/v1/assets", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "vulnerability":
            return self.get(f"/v1/findings/{object_id}")
        if stix_type == "report":
            return self.get(f"/v1/assets/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Orca: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size}
        params.update(filters)

        if stix_type == "vulnerability":
            resp = self.get("/v1/findings", params=params)
            return resp.get("findings", []) if isinstance(resp, dict) else []
        # Default: assets (includes misconfigs, API risks, etc.)
        resp = self.get("/v1/assets", params=params)
        return resp.get("assets", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Orca connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_findings(
        self,
        limit: int = 50,
        severity: str | None = None,
        cloud_provider: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch security findings / risks with filters."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        if cloud_provider:
            params["cloud_provider"] = cloud_provider.upper()
        resp = self.get("/v1/findings", params=params)
        return resp.get("findings", []) if isinstance(resp, dict) else []

    def fetch_assets(
        self,
        limit: int = 50,
        asset_type: str | None = None,  # e.g. ec2, lambda, api
    ) -> list[dict[str, Any]]:
        """Fetch cloud assets (includes API security inventory)."""
        params: dict[str, Any] = {"limit": limit}
        if asset_type:
            params["type"] = asset_type
        resp = self.get("/v1/assets", params=params)
        return resp.get("assets", []) if isinstance(resp, dict) else []

    def fetch_api_risks(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch API-specific risks (newer capability)."""
        params = {"limit": limit, "category": "api_security"}
        resp = self.get("/v1/findings", params=params)
        return resp.get("findings", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch finding vs. asset."""
        if "severity" in native and ("title" in native or "risk" in native):
            return self._finding_to_stix(native)
        return self._asset_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "Orca is read-only for cloud risk and asset data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _finding_to_stix(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for finding to stix."""
        now = _now_ts()
        fid = finding.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'orca:{fid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": finding.get("title", "Orca Finding"),
            "description": finding.get("description", ""),
            "external_references": [{"source_name": "orca", "external_id": fid}],
            "x_orca": {
                "finding_id": fid,
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score"),
                "cloud_provider": finding.get("cloud_provider"),
                "resource_type": finding.get("resource_type"),
                "category": finding.get("category"),  # e.g. api_security, misconfig
            },
        }

    def _asset_to_stix(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for asset to stix."""
        now = _now_ts()
        aid = asset.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'asset:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"Orca Asset: {asset.get('name', aid)}",
            "description": f"Cloud asset of type {asset.get('type', 'unknown')}",
            "report_types": ["asset-inventory"],
            "x_orca": {
                "asset_id": aid,
                "type": asset.get("type"),
                "cloud_provider": asset.get("cloud_provider"),
                "region": asset.get("region"),
                "risk": asset.get("risk"),
            },
        }
