# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cycognito.client
================================

CyCognito (Attack Surface Management / Exposure Management) connector — full client.

Authentication
--------------
API Key via ``Authorization: Bearer`` header::

    [cycognito]
    host      = https://api.platform.cycognito.com     # or region-specific (e.g. us-platform)
    api_key   = <your-cycognito-api-key>

Generate the key in CyCognito UI → Workflow & Integration → API Key Management.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | CyCognito Resource               |
+================+==================================+
| vulnerability  | Issues / findings                |
+----------------+----------------------------------+
| report         | Assets (domains, IPs, certs, etc.) |
+----------------+----------------------------------+

Key Endpoints (API v1, 2026)
----------------------------
* /v1/issues                          — List security issues/findings
* /v1/assets/{asset_type}             — Assets (ip, domain, cert, webapp, etc.)
* /v1/assets/ip/{id}, /v1/assets/domain/{id} — Single asset detail
* Unified asset query support via CyQL (flexible filtering)

Notes
-----
* Read-heavy platform focused on external attack surface discovery and validated risks.
* Strong on asset inventory + issue correlation.
* Many endpoints support filters and pagination.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CyCognitoClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for CyCognito API v1.

    Parameters
    ----------
    host : str
        Base API URL (usually "https://api.platform.cycognito.com").
    api_key : str
        CyCognito API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "vulnerability": "issues",
        "report": "assets",
    }

    def __init__(
        self, host: str = "https://api.platform.cycognito.com", api_key: str = "", **kwargs: Any
    ):
        """Initialize CyCognitoClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via issues or assets endpoint."""
        self.get("/v1/issues", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "vulnerability":
            return self.get(f"/v1/issues/issue/{object_id}")
        if stix_type == "report":
            # Generic asset fetch; caller can specify type in filters for list_objects
            return self.get(f"/v1/assets/ip/{object_id}")  # fallback; extend for other types
        raise GNATClientError(f"Unsupported STIX type for CyCognito: {stix_type}")

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
            resp = self.get("/v1/issues", params=params)
            return resp.get("issues", []) if isinstance(resp, dict) else []
        # Default: assets (unified or by type via filters, e.g. asset_type=ip)
        resp = self.get(
            "/v1/assets", params=params
        )  # unified asset query supported in recent versions
        return resp.get("assets", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("CyCognito is read-only for this connector (asset/issue ingestion).")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("CyCognito does not support deletion via this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_issues(
        self,
        limit: int = 50,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch security issues/findings with optional filters."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        if status:
            params["status"] = status
        resp = self.get("/v1/issues", params=params)
        return resp.get("issues", []) if isinstance(resp, dict) else []

    def fetch_assets(
        self,
        asset_type: str | None = None,  # ip, domain, cert, webapp, etc.
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch assets (unified or typed)."""
        params: dict[str, Any] = {"limit": limit}
        if asset_type:
            params["asset_type"] = asset_type
        resp = self.get("/v1/assets", params=params)
        return resp.get("assets", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch issue (vulnerability) vs. asset (report)."""
        if "severity" in native and ("title" in native or "description" in native):
            return self._issue_to_stix(native)
        return self._asset_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "CyCognito is read-only for external exposure data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _issue_to_stix(self, issue: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for issue to stix."""
        now = _now_ts()
        iid = issue.get("id") or issue.get("issue_instance_id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'cycognito:{iid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": issue.get("title", "CyCognito Issue"),
            "description": issue.get("description", ""),
            "external_references": [{"source_name": "cycognito", "external_id": iid}],
            "x_cycognito": {
                "issue_id": iid,
                "severity": issue.get("severity"),
                "status": issue.get("status"),
                "asset": issue.get("asset"),
                "risk_score": issue.get("risk_score"),
            },
        }

    def _asset_to_stix(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for asset to stix."""
        now = _now_ts()
        aid = asset.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'asset:{aid}')}"
        asset_type = asset.get("type", "unknown")
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"CyCognito Asset: {asset.get('name', aid)}",
            "description": f"External asset of type {asset_type}",
            "report_types": ["asset-inventory"],
            "x_cycognito": {
                "asset_id": aid,
                "type": asset_type,
                "name": asset.get("name"),
                "risk": asset.get("risk"),
                "exposed_services": asset.get("exposed_services", []),
            },
        }
