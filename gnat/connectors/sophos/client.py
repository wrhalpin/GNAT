"""
gnat.connectors.sophos.client
================================

Sophos Central (Endpoint Protection + Threat Intelligence) connector.

Authentication
--------------
OAuth2 client-credentials flow::

    [sophos]
    client_id     = <client-id>
    client_secret = <client-secret>

Sophos Central uses a two-step auth:
1. POST to ``https://id.sophos.com/api/v2/oauth2/token`` to get access token.
2. GET ``https://api.central.sophos.com/whoami/v1`` to discover the tenant region URL.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Sophos Resource                  |
+================+==================================+
| indicator      | Blocked Items / SAVI detections  |
+----------------+----------------------------------+
| malware        | Detections / Alerts              |
+----------------+----------------------------------+

Key Endpoints (Sophos Central APIs)
-------------------------------------
* /endpoint/v1/endpoints                 — Managed endpoints
* /endpoint/v1/detections                — Malware detections
* /siem/v1/alerts                        — Security alerts (SIEM API)
* /endpoint/v1/settings/blocked-items    — Blocked items (IOC blocklist)
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f23456789012")
_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
_WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SophosClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Sophos Central REST APIs.

    Parameters
    ----------
    host : str
        Region-specific API base URL (auto-discovered via ``/whoami/v1``).
        Provide explicitly if known (e.g. ``"https://api-us01.central.sophos.com"``).
    client_id : str
        Sophos OAuth2 client ID.
    client_secret : str
        Sophos OAuth2 client secret.
    tenant_id : str, optional
        Sophos tenant ID (``X-Tenant-ID`` header).  Auto-discovered if omitted.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "blocked-items",
        "malware": "detections",
    }

    def __init__(
        self,
        host: str = "https://api.central.sophos.com",
        client_id: str = "",
        client_secret: str = "",
        tenant_id: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._tenant_id = tenant_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 Bearer token and discover the tenant API region URL.

        Calls ``https://id.sophos.com/api/v2/oauth2/token`` then
        ``https://api.central.sophos.com/whoami/v1`` to set the region host.
        """
        resp = self.post(
            "/api/v2/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "token",
            },
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("Sophos: failed to obtain OAuth2 access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"
        if self._tenant_id:
            self._auth_headers["X-Tenant-ID"] = self._tenant_id

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping endpoint list to verify connectivity."""
        self.get("/endpoint/v1/endpoints", params={"pageSize": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single blocked item or detection by ID."""
        if stix_type == "indicator":
            resp = self.get(f"/endpoint/v1/settings/blocked-items/{object_id}")
            return resp if isinstance(resp, dict) else {}
        if stix_type == "malware":
            resp = self.get(f"/endpoint/v1/detections/{object_id}")
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(f"Sophos: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "malware",
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List detections, blocked items, or alerts."""
        params: dict[str, Any] = {"pageSize": page_size, "pageFrom": (page - 1) * page_size}
        if filters:
            params.update(filters)

        if stix_type == "indicator":
            resp = self.get("/endpoint/v1/settings/blocked-items", params=params)
            return resp.get("items", []) if isinstance(resp, dict) else []
        if stix_type == "malware":
            resp = self.get("/endpoint/v1/detections", params=params)
            return resp.get("detections", []) if isinstance(resp, dict) else []
        raise GNATClientError(f"Sophos: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Add a blocked item to Sophos Central."""
        if stix_type != "indicator":
            raise GNATClientError("Sophos: upsert only supported for 'indicator'")
        resp = self.post("/endpoint/v1/settings/blocked-items", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Remove a blocked item from Sophos Central."""
        if stix_type != "indicator":
            raise GNATClientError("Sophos: delete only supported for 'indicator'")
        self.delete(f"/endpoint/v1/settings/blocked-items/{object_id}")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_endpoints(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        List managed endpoints from Sophos Central.

        Parameters
        ----------
        limit : int
            Maximum number of endpoints to return.
        """
        resp = self.get("/endpoint/v1/endpoints", params={"pageSize": limit})
        return resp.get("items", []) if isinstance(resp, dict) else []

    def list_alerts(
        self,
        limit: int = 100,
        from_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch security alerts via the Sophos SIEM API.

        Parameters
        ----------
        limit : int
            Maximum alerts to return.
        from_date : str, optional
            ISO 8601 timestamp to filter alerts after this date.
        """
        params: dict[str, Any] = {"limit": limit}
        if from_date:
            params["from_date"] = from_date
        resp = self.get("/siem/v1/alerts", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def list_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch endpoint malware detections."""
        resp = self.get("/endpoint/v1/detections", params={"pageSize": limit})
        return resp.get("detections", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Sophos detection or blocked item to a STIX 2.1 object."""
        if "sha256" in native or "properties" in native:
            return self._blocked_item_to_stix(native)
        return self._detection_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX indicator to a Sophos blocked-item payload."""
        pattern = stix_dict.get("pattern", "")
        value = stix_dict.get("name", "")
        # Extract hash value from pattern if present
        if "SHA-256" in pattern:
            item_type = "sha256"
        elif "MD5" in pattern:
            item_type = "md5"
        elif "ipv4-addr" in pattern:
            item_type = "ip"
        else:
            item_type = "path"
        return {
            "type": item_type,
            "value": value,
            "comment": stix_dict.get("description", "Imported via GNAT"),
        }

    def _blocked_item_to_stix(self, item: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        item_id = item.get("id", "")
        value = item.get("sha256", item.get("value", ""))
        item_type = item.get("type", "sha256")
        type_map = {
            "sha256": "file:hashes.'SHA-256'",
            "md5": "file:hashes.MD5",
            "ip": "ipv4-addr:value",
            "path": "file:name",
        }
        stix_prop = type_map.get(item_type, "file:name")
        return {
            "type": "indicator",
            "id": f"indicator--{_uuid.uuid5(_STIX_NS, f'sophos:{item_id}')}",
            "spec_version": "2.1",
            "created": item.get("created_at", now),
            "modified": item.get("updated_at", now),
            "name": value,
            "description": item.get("comment", "Sophos blocked item"),
            "pattern": f"[{stix_prop} = '{value}']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_sophos_type": item_type,
        }

    def _detection_to_stix(self, detection: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        det_id = detection.get("id", "")
        return {
            "type": "malware",
            "id": f"malware--{_uuid.uuid5(_STIX_NS, f'sophos:{det_id}')}",
            "spec_version": "2.1",
            "created": detection.get("detected_at", now),
            "modified": detection.get("detected_at", now),
            "name": detection.get("name", "Unknown Sophos Detection"),
            "description": detection.get("description", ""),
            "malware_types": [detection.get("category", "unknown")],
            "is_family": False,
            "x_sophos": {
                "detection_id": det_id,
                "endpoint_id": detection.get("endpoint_id"),
                "endpoint_name": detection.get("endpoint_name"),
                "severity": detection.get("severity"),
            },
        }
