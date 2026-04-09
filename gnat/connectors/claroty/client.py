# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.claroty.client
==============================

Claroty (xDome / Continuous Threat Detection) connector for OT/ICS cybersecurity.

Authentication
--------------
API Token (preferred) generated for an API User in Admin Settings > User Management.
Some deployments support Bearer token or legacy username/password::

    [claroty]
    host      = https://<your-claroty-instance>.claroty.com
    api_token = <your-api-token>
    # username and password can be used as fallback for legacy auth

Get API token: Log into Claroty → Admin Settings → User Management → Add API User → Generate Token.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Claroty Resource                 |
+================+==================================+
| observed-data  | Alerts / events                  |
+----------------+----------------------------------+
| report         | Assets (OT/IoT/ICS inventory)    |
+----------------+----------------------------------+
| vulnerability  | Vulnerabilities with affected assets |
+----------------+----------------------------------+

Key Endpoints
-------------
* Assets: `/v1/assets` (or equivalent) — list and details of OT/IoT devices.
* Alerts: Endpoints for security alerts and anomalies.
* Vulnerabilities: Endpoints returning CVEs/risks linked to assets.
* API Explorer available in the Claroty UI (Swagger-based) for exact paths and schemas.

Notes
-----
* Strong focus on **cyber-physical systems** (CPS) visibility — excellent complement to Armis.
* Primarily read-oriented (asset inventory + threat intel); limited write for alert acknowledgment.
* `list_objects()` dispatches by STIX type with domain helpers (`list_assets`, `list_alerts`).
* `to_stix()` produces rich objects with `x_claroty` extension (device details, risk scores, protocols, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ClarotyClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Claroty xDome / CTD REST API (assets, alerts, vulnerabilities).

    Parameters
    ----------
    host : str
        Claroty base URL, e.g. ``"https://yourinstance.claroty.com"`` or ``"https://api.claroty.com"``.
    api_token : str
        API token for the dedicated API user.
    username : str, optional
        Fallback username for legacy auth.
    password : str, optional
        Fallback password for legacy auth.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "report": "assets",
        "observed-data": "alerts",
        "vulnerability": "vulnerabilities",
    }

    def __init__(
        self,
        host: str,
        api_token: str = "",
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ):
        """Initialize ClarotyClient."""
        super().__init__(host=host, **kwargs)
        self._api_token = api_token
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set up Bearer token (preferred) or fallback Basic Auth + JSON headers."""
        if self._api_token:
            self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
        elif self._username and self._password:
            # Legacy fallback
            self._auth_headers["Authorization"] = self._basic_auth(self._username, self._password)
        else:
            raise GNATClientError("Claroty requires either api_token or username+password")

        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight check via assets or system endpoint."""
        try:
            self.get("/v1/assets", params={"limit": 1})  # Adjust version/path if needed
            return True
        except Exception:
            # Fallback
            self.get("/api/health")  # or any lightweight path exposed
            return True

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List assets, alerts, or vulnerabilities.

        Common filters: site, risk_score, category, etc. (adapt to your version).
        """
        filters = dict(filters or {})
        limit = page_size

        if stix_type == "report":  # Assets
            params = {"limit": limit, "page": page, **filters}
            resp = self.get(
                "/v1/assets", params=params
            )  # Common path; adjust if your instance uses different versioning
            return resp.get("data", []) if isinstance(resp, dict) else []

        if stix_type == "observed-data":  # Alerts
            params = {"limit": limit, "page": page, **filters}
            resp = self.get("/v1/alerts", params=params)  # Adjust exact path
            return resp.get("data", []) if isinstance(resp, dict) else []

        if stix_type == "vulnerability":
            params = {"limit": limit, "page": page, **filters}
            resp = self.get("/v1/vulnerabilities", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"list_objects not fully implemented for {stix_type} in Claroty")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Limited write support (e.g., acknowledge alert)."""
        if stix_type == "observed-data" and "alert_id" in payload:
            # Example: acknowledge or update alert status
            alert_id = payload.pop("alert_id")
            return self.put(f"/v1/alerts/{alert_id}", json=payload)
        raise GNATClientError(f"upsert_object limited support for {stix_type} in Claroty")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Claroty connector does not support deletion via standard API.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_assets(self, **filters: Any) -> list[dict[str, Any]]:
        """Convenience: List OT/IoT/ICS assets with filters (category, site, risk, etc.)."""
        return self.list_objects("report", filters=filters)

    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]:
        """Convenience: List security alerts/anomalies."""
        return self.list_objects("observed-data", filters=filters)

    def get_asset_details(self, asset_id: str) -> dict[str, Any]:
        """Fetch detailed information for a single asset."""
        return self.get(f"/v1/assets/{asset_id}")

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate Claroty asset, alert, or vulnerability to STIX 2.1.

        Dispatches based on typical keys (e.g., asset_uid, alert_id, cve).
        """
        now = _now_ts()

        if "asset_uid" in native or "device_type" in native:
            return self._asset_to_stix(native, now)
        if "alert_id" in native or "event_type" in native:
            return self._alert_to_stix(native, now)
        if "cve" in native or "vulnerability_id" in native:
            return self._vulnerability_to_stix(native, now)

        # Generic fallback
        return {
            "type": "report",
            "id": f"report--claroty-{hash(str(native)) % 10**12}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Claroty Record",
            "x_claroty": native,
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Prepare payload for limited writes (e.g., alert updates)."""
        return {
            "note": "Claroty from_stix prepares update/ack payload.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _asset_to_stix(self, asset: dict[str, Any], now: str) -> dict[str, Any]:
        """Map Claroty asset to STIX report (rich OT/ICS inventory)."""
        asset_id = asset.get("asset_uid") or asset.get("id") or "unknown"
        return {
            "type": "report",
            "id": f"report--claroty-asset-{asset_id}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": asset.get("name", "Claroty Asset"),
            "description": f"OT/ICS Asset: {asset.get('device_type', '')}",
            "x_claroty_asset": {
                "asset_uid": asset_id,
                "category": asset.get("category"),
                "subcategory": asset.get("subcategory"),
                "ip_list": asset.get("ip_list", []),
                "mac_list": asset.get("mac_list", []),
                "manufacturer": asset.get("manufacturer"),
                "model": asset.get("model"),
                "risk_score": asset.get("risk_score"),
                "raw": asset,
            },
        }

    def _alert_to_stix(self, alert: dict[str, Any], now: str) -> dict[str, Any]:
        """Map Claroty alert to STIX observed-data."""
        alert_id = alert.get("alert_id") or alert.get("id")
        return {
            "type": "observed-data",
            "id": f"observed-data--claroty-alert-{alert_id}",
            "spec_version": "2.1",
            "created": alert.get("timestamp") or now,
            "modified": now,
            "first_observed": alert.get("timestamp"),
            "number_observed": 1,
            "x_claroty_alert": {
                "alert_id": alert_id,
                "type": alert.get("event_type"),
                "severity": alert.get("severity"),
                "affected_asset": alert.get("device_asset_id"),
                "raw": alert,
            },
        }

    def _vulnerability_to_stix(self, vuln: dict[str, Any], now: str) -> dict[str, Any]:
        """Map Claroty vulnerability to STIX vulnerability."""
        cve = vuln.get("cve") or vuln.get("vulnerability_id", "")
        return {
            "type": "vulnerability",
            "id": f"vulnerability--claroty-{cve}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": cve or "Claroty Vulnerability",
            "description": vuln.get("description", ""),
            "x_claroty_vuln": vuln,
        }
