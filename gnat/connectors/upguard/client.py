# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.upguard.client
==============================

UpGuard (Vendor Risk + CAASM + DRP) connector — full client.

Authentication
--------------
API Key via ``Authorization: Token`` or ``x-api-key`` header::

    [upguard]
    host     = https://cyber-risk.upguard.com
    api_key  = <your-upguard-api-key>

Generate the key in UpGuard UI (Settings → API Keys).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | UpGuard Resource                 |
+================+==================================+
| vulnerability  | Breaches / identity breaches     |
+----------------+----------------------------------+
| report         | Vendors / questionnaires / VIPs  |
+----------------+----------------------------------+

Key Endpoints (CyberRisk API)
-----------------------------
* /api/vendors                  — Vendor list & details
* /api/breaches                 — Breach history & identity breaches
* /api/questionnaires           — Security questionnaires
* /api/vip                      — VIP Management (new 2026)
* /api/content-library          — Read-only Content Library & Trust Center
* /api/companies                — Company-level risk data

Notes
-----
* Strong on third-party/vendor risk, breach intel, and supply-chain exposure.
* Read-heavy with some write for questionnaires/VIP management.
* Complements Axonius (assets) and CyCognito/Orca (exposure) with vendor-focused risk.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e8f9a0b1-c2d3-4e5f-6a7b-8c9d0e1f2a3b")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class UpGuardClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for UpGuard CyberRisk API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://cyber-risk.upguard.com").
    api_key : str
        UpGuard API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "vulnerability": "breaches",
        "report": "vendors",
    }

    def __init__(
        self, host: str = "https://cyber-risk.upguard.com", api_key: str = "", **kwargs: Any
    ):
        """Initialize UpGuardClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject API key header."""
        self._auth_headers["Authorization"] = f"Token {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via vendors endpoint."""
        self.get("/api/vendors", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "report":
            return self.get(f"/api/vendors/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/api/breaches/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for UpGuard: {stix_type}")

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
            resp = self.get("/api/breaches", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: vendors
        resp = self.get("/api/vendors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("UpGuard connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Expanded Domain-specific helpers ───────────────────────────────────

    def fetch_vendors(
        self,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch vendor list with optional filters."""
        params: dict[str, Any] = {"limit": limit, **(filters or {})}
        resp = self.get("/api/vendors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_breaches(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch breach and identity breach history."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        resp = self.get("/api/breaches", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_questionnaires(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch security questionnaires (Vendor Risk)."""
        resp = self.get("/api/questionnaires", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_vip_management(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch VIP identities (new 2026 capability)."""
        resp = self.get("/api/vip", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_content_library(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Read-only Content Library & Trust Center (new 2026)."""
        resp = self.get("/api/content-library", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch breach (vulnerability) vs. vendor/questionnaire (report)."""
        if "breach" in str(native).lower() or "identity" in str(native).lower():
            return self._breach_to_stix(native)
        return self._vendor_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "UpGuard is primarily read-only for vendor risk and breach data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _breach_to_stix(self, breach: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for breach to stix."""
        now = _now_ts()
        bid = breach.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'upguard:{bid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": breach.get("date") or now,
            "modified": now,
            "name": breach.get("title", "UpGuard Breach"),
            "description": breach.get("description", ""),
            "external_references": [{"source_name": "upguard", "external_id": bid}],
            "x_upguard": {
                "breach_id": bid,
                "severity": breach.get("severity"),
                "vendor": breach.get("vendor"),
                "identity_count": breach.get("identity_count"),
            },
        }

    def _vendor_to_stix(self, vendor: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for vendor to stix."""
        now = _now_ts()
        vid = vendor.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'upguard:{vid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"UpGuard Vendor: {vendor.get('name', vid)}",
            "description": vendor.get("description", ""),
            "report_types": ["vendor-risk"],
            "x_upguard": {
                "vendor_id": vid,
                "risk_score": vendor.get("risk_score"),
                "questionnaire_status": vendor.get("questionnaire_status"),
            },
        }
