# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.lansweeper.client
================================

Lansweeper IT Asset Management (ITAM) connector.

Authentication
--------------
OAuth2 client-credentials (Lansweeper Cloud) or personal access token::

    [lansweeper]
    host          = https://api.lansweeper.com
    client_id     = <application-client-id>
    client_secret = <application-client-secret>
    site_id       = <lansweeper-site-id>

Alternatively, use a personal access token::

    [lansweeper]
    host    = https://api.lansweeper.com
    api_key = <personal-access-token>

STIX Type Mapping
-----------------
+------------------+----------------------------------+
| STIX Type        | Lansweeper Resource              |
+==================+==================================+
| report           | Assets                           |
+------------------+----------------------------------+
| vulnerability    | Software / Installed Patches     |
+------------------+----------------------------------+

Key Endpoints (Lansweeper GraphQL + REST API)
---------------------------------------------
* /api/v2/graphql                  — Asset inventory (GraphQL)
* /api/v2/sites/{id}/assets        — Asset list for a site
* /api/v2/sites/{id}/assets/{aid}  — Single asset detail
* /api/v2/sites/{id}/software      — Installed software
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f6a7b8c9-d0e1-2345-f012-678901234567")
_AUTH_URL = "https://id.lansweeper.com/ls/connect/token"


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LansweeperClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Lansweeper Cloud REST/GraphQL API.

    Parameters
    ----------
    host : str
        API base URL (``"https://api.lansweeper.com"``).
    client_id : str
        OAuth2 application client ID.
    client_secret : str
        OAuth2 application client secret.
    site_id : str
        Lansweeper site identifier (required for most asset API calls).
    api_key : str
        Personal access token (alternative to OAuth2).
    """

    stix_type_map: dict[str, str] = {
        "report": "assets",
        "vulnerability": "software",
    }

    def __init__(
        self,
        host: str = "https://api.lansweeper.com",
        client_id: str = "",
        client_secret: str = "",
        site_id: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize LansweeperClient."""
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._site_id = site_id
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Obtain OAuth2 bearer token or inject personal access token."""
        if self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._client_id and self._client_secret:
            resp = self.post(
                "/ls/connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            token = resp.get("access_token") if isinstance(resp, dict) else None
            if not token:
                raise GNATClientError("Lansweeper: failed to obtain OAuth2 access token")
            self._auth_headers["Authorization"] = f"Bearer {token}"
        else:
            raise GNATClientError("Lansweeper: provide api_key or client_id + client_secret")
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the Lansweeper API via site list."""
        self.get("/api/v2/sites")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single asset by ID."""
        if not self._site_id:
            raise GNATClientError("Lansweeper: site_id is required for asset queries")
        if stix_type == "report":
            resp = self.get(f"/api/v2/sites/{self._site_id}/assets/{object_id}")
            return resp.get("asset", resp) if isinstance(resp, dict) else {}
        raise GNATClientError(f"Lansweeper: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "report",
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List assets or software inventory."""
        if not self._site_id:
            raise GNATClientError("Lansweeper: site_id is required for asset queries")
        params: dict[str, Any] = {"limit": page_size, "page": page}
        if filters:
            params.update(filters)

        if stix_type == "report":
            resp = self.get(f"/api/v2/sites/{self._site_id}/assets", params=params)
            return resp.get("items", []) if isinstance(resp, dict) else []
        if stix_type == "vulnerability":
            resp = self.get(f"/api/v2/sites/{self._site_id}/software", params=params)
            return resp.get("items", []) if isinstance(resp, dict) else []
        raise GNATClientError(f"Lansweeper: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Lansweeper is read-only; upsert is not supported."""
        raise GNATClientError("Lansweeper ITAM connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Lansweeper is read-only; delete is not supported."""
        raise GNATClientError("Lansweeper ITAM connector is read-only.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_sites(self) -> list[dict[str, Any]]:
        """List all Lansweeper sites accessible to this account."""
        resp = self.get("/api/v2/sites")
        return resp.get("items", []) if isinstance(resp, dict) else []

    def list_assets(
        self,
        asset_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List assets from the configured site.

        Parameters
        ----------
        asset_type : str, optional
            Filter by asset type (e.g. ``"Windows"``, ``"Linux"``, ``"Network"``)
        limit : int
            Maximum records to return.
        """
        if not self._site_id:
            raise GNATClientError("Lansweeper: site_id is required")
        params: dict[str, Any] = {"limit": limit}
        if asset_type:
            params["type"] = asset_type
        resp = self.get(f"/api/v2/sites/{self._site_id}/assets", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def query_graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Execute a Lansweeper GraphQL query against the asset inventory.

        Parameters
        ----------
        query : str
            GraphQL query string.
        variables : dict, optional
            GraphQL variables.
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = self.post("/api/v2/graphql", json=payload)
        return resp if isinstance(resp, dict) else {}

    def list_software(self, limit: int = 100) -> list[dict[str, Any]]:
        """List installed software across all assets in the site."""
        if not self._site_id:
            raise GNATClientError("Lansweeper: site_id is required")
        resp = self.get(f"/api/v2/sites/{self._site_id}/software", params={"limit": limit})
        return resp.get("items", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Lansweeper asset or software entry to a STIX 2.1 object."""
        if "softwareName" in native or "softwareVersion" in native:
            return self._software_to_stix(native)
        return self._asset_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a reference payload (Lansweeper is read-only)."""
        return {
            "note": "Lansweeper is read-only.",
            "stix_id": stix_dict.get("id", ""),
            "stix_type": stix_dict.get("type", ""),
        }

    def _asset_to_stix(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for asset to stix."""
        now = _now_ts()
        aid = str(asset.get("id", asset.get("assetId", "")))
        return {
            "type": "report",
            "id": f"report--{_uuid.uuid5(_STIX_NS, f'lansweeper:{aid}')}",
            "spec_version": "2.1",
            "created": asset.get("firstSeen", now),
            "modified": asset.get("lastSeen", now),
            "name": asset.get("name", f"Asset {aid}"),
            "description": f"Lansweeper managed asset: {asset.get('type', 'unknown')}",
            "report_types": ["asset-inventory"],
            "object_refs": [],
            "x_lansweeper": {
                "asset_id": aid,
                "type": asset.get("type"),
                "os": asset.get("operatingSystem"),
                "ip": asset.get("ip"),
                "mac": asset.get("mac"),
                "domain": asset.get("domain"),
                "site_id": self._site_id,
            },
        }

    def _software_to_stix(self, sw: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for software to stix."""
        now = _now_ts()
        sid = str(sw.get("id", ""))
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{_uuid.uuid5(_STIX_NS, f'lansweeper:sw:{sid}')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"{sw.get('softwareName', 'Unknown')} {sw.get('softwareVersion', '')}".strip(),
            "description": f"Software installed on {sw.get('assetCount', 0)} asset(s)",
            "external_references": [{"source_name": "lansweeper", "external_id": sid}],
            "x_lansweeper_software": {
                "name": sw.get("softwareName"),
                "version": sw.get("softwareVersion"),
                "publisher": sw.get("publisher"),
                "asset_count": sw.get("assetCount", 0),
            },
        }
