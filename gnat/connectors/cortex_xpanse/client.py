# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cortex_xpanse.client
====================================

Cortex Xpanse (External Attack Surface Management) connector — full client.

Authentication
--------------
API Key + API Key ID (Cortex-style)::

    [cortex_xpanse]
    host         = https://api.xpanse.paloaltonetworks.com   # or your region FQDN
    api_key      = <your-xpanse-api-key>
    api_key_id   = <your-xpanse-api-key-id>

Generate in Cortex Xpanse console (Settings → API Keys). Use the "API Key" and "API Key ID" values.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Xpanse Resource                  |
+================+==================================+
| vulnerability  | Exposures / findings             |
+----------------+----------------------------------+
| report         | Assets / Services / Incidents    |
+----------------+----------------------------------+

Key Endpoints
-------------
* /v2/assets, /v2/services, /v2/exposures — Asset & exposure discovery
* /v2/incidents — Incident management
* Pagination via limit/offset or cursor where supported

Notes
-----
* Strong on internet-facing assets, risk scoring, and exposure context.
* Complements your CyCognito (external ASM) and Orca/Wiz (cloud) connectors.
* Read-heavy; limited write for incident updates.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e7f8a9b0-c1d2-3e4f-5a6b-7c8d9e0f1a2b")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CortexXpanseClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Cortex Xpanse REST API.

    Parameters
    ----------
    host : str
        Base URL (e.g. "https://api.xpanse.paloaltonetworks.com").
    api_key : str
        Xpanse API Key.
    api_key_id : str
        Xpanse API Key ID.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "vulnerability": "exposures",
        "report": "assets",
    }

    def __init__(
        self,
        host: str = "https://api.xpanse.paloaltonetworks.com",
        api_key: str = "",
        api_key_id: str = "",
        **kwargs: Any,
    ):
        """Initialize CortexXpanseClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_key_id = api_key_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Cortex Xpanse auth headers (API Key ID + Bearer)."""
        self._auth_headers["x-xdr-auth-id"] = self._api_key_id
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via assets endpoint."""
        self.get("/v2/assets", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "report":
            return self.get(f"/v2/assets/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/v2/exposures/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Cortex Xpanse: {stix_type}")

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
            resp = self.get("/v2/exposures", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: assets/services as reports
        resp = self.get("/v2/assets", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError(
            "Cortex Xpanse connector is primarily read-only (limited incident updates)."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_assets(
        self,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch internet-facing assets."""
        params: dict[str, Any] = {"limit": limit, **(filters or {})}
        resp = self.get("/v2/assets", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_exposures(
        self,
        limit: int = 50,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch exposures/findings."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        resp = self.get("/v2/exposures", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_incidents(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch incidents/alerts."""
        resp = self.get("/v2/incidents", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch exposure (vulnerability) vs. asset/incident (report)."""
        if "severity" in native and ("exposure" in str(native).lower() or "risk" in native):
            return self._exposure_to_stix(native)
        return self._asset_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "Cortex Xpanse is primarily read-only for ASM data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _exposure_to_stix(self, exposure: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for exposure to stix."""
        now = _now_ts()
        eid = exposure.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'xpanse:{eid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": exposure.get("title", "Xpanse Exposure"),
            "description": exposure.get("description", ""),
            "external_references": [{"source_name": "cortex_xpanse", "external_id": eid}],
            "x_xpanse": {
                "exposure_id": eid,
                "severity": exposure.get("severity"),
                "risk_score": exposure.get("risk_score"),
                "asset": exposure.get("asset"),
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
            "name": f"Xpanse Asset: {asset.get('name', aid)}",
            "description": "Internet-facing asset discovered by Xpanse",
            "report_types": ["asset-inventory"],
            "x_xpanse": {
                "asset_id": aid,
                "ip": asset.get("ip"),
                "domain": asset.get("domain"),
                "services": asset.get("services", []),
                "risk": asset.get("risk"),
            },
        }
