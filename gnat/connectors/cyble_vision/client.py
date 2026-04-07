# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cyble_vision.client
====================================

Cyble Vision (AI-native TIP / DRP) connector.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [cyble_vision]
    host      = https://<your-tenant>.cyble.ai          # or https://api.cyble.ai/engine/api/v4
    api_token = <your-cyble-vision-access-token>

Generate token in Cyble Vision → Utilities → Access API (admin required).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Cyble Resource                   |
+================+==================================+
| indicator      | IOCs / indicators                |
+----------------+----------------------------------+
| report         | alerts / events                  |
+----------------+----------------------------------+

Key Endpoints (v4)
------------------
* ``/engine/api/v4/iocs``          — fetch IOCs (pagination, filters)
* ``/engine/api/v4/alerts``        — fetch alerts/events
* ``/engine/api/v4/events/{id}``   — event detail

Notes
-----
* Read-only platform (dark web, credentials, vulnerabilities, brand risk, etc.).
* Customer-specific host (e.g. https://acme.cyble.ai).
* Supports the same alert types as Stellar/Splunk integrations (leaked_credentials, darkweb_*, vulnerability, etc.).
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f5e5c8b0-5e5e-4e5e-9e5e-5e5e5e5e5e5e")  # namespace for deterministic IDs


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CybleVisionClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Cyble Vision REST API (v4).

    Parameters
    ----------
    host : str
        Base URL (customer-specific, e.g. ``https://acme.cyble.ai`` or
        ``https://api.cyble.ai/engine/api/v4``).
    api_token : str
        Cyble Vision access token.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report": "alerts",
    }

    def __init__(
        self, host: str = "https://api.cyble.ai/engine/api/v4", api_token: str = "", **kwargs: Any
    ):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token and JSON headers."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping (uses alerts endpoint with limit=1)."""
        self.get("/alerts", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch single alert or IOC by ID."""
        if stix_type == "report":
            return self.get(f"/events/{object_id}")
        if stix_type == "indicator":
            return self.get(f"/iocs/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Cyble Vision: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List alerts or IOCs with pagination/filters."""
        filters = dict(filters or {})
        if stix_type == "indicator":
            return self.fetch_iocs(
                start_date=filters.pop("start_date", None),
                end_date=filters.pop("end_date", None),
                ioc_type=filters.pop("type", None),
                keyword=filters.pop("keyword", None),
                limit=page_size,
            )
        # Default: alerts
        return self.fetch_alerts(
            start_date=filters.pop("start_date", None),
            end_date=filters.pop("end_date", None),
            priority=filters.pop("priority", None),
            limit=page_size,
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Cyble Vision is read-only — no upsert support.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Cyble Vision is read-only — no deletion support.")

    # ── Domain-specific helpers (platform-specific) ───────────────────────

    def fetch_iocs(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        ioc_type: str | None = None,
        keyword: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch indicators of compromise."""
        params: dict[str, Any] = {"limit": limit}
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        if ioc_type:
            params["type"] = ioc_type
        if keyword:
            params["keyword"] = keyword
        resp = self.get("/iocs", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_alerts(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        priority: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch alerts/events (leaked_credentials, darkweb_*, vulnerability, etc.)."""
        params: dict[str, Any] = {"limit": limit, "order_by": "Descending"}
        if start_date:
            params["start_date"] = start_date.replace("-", "/")  # Cyble expects YYYY/MM/DD
        if end_date:
            params["end_date"] = end_date.replace("-", "/")
        if priority:
            params["priority"] = priority.lower()
        resp = self.get("/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX conversion ───────────────────────────────────────────────────

    def to_stix(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Map a Cyble Vision alert or IOC dict to a STIX object."""
        # IOC → STIX indicator
        if "ioc_value" in obj or "type" in obj:
            ioc_val = obj.get("ioc_value", obj.get("value", ""))
            ioc_type = obj.get("type", "unknown").lower()
            pattern_map = {
                "ipv4": f"[ipv4-addr:value = '{ioc_val}']",
                "domain": f"[domain-name:value = '{ioc_val}']",
                "url": f"[url:value = '{ioc_val}']",
                "md5": f"[file:hashes.MD5 = '{ioc_val}']",
                "sha256": f"[file:hashes.'SHA-256' = '{ioc_val}']",
                "email": f"[email-addr:value = '{ioc_val}']",
            }
            pattern = pattern_map.get(ioc_type, f"[x-cyble:value = '{ioc_val}']")
            return {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_uuid.uuid5(_STIX_NS, ioc_val)}",
                "name": ioc_val,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": obj.get("first_seen", _now_ts()),
                "x_cyble_type": ioc_type,
                "x_cyble_confidence": obj.get("confidence"),
            }
        # Alert/event → STIX report
        alert_id = str(obj.get("id", _uuid.uuid4()))
        title = obj.get("title", obj.get("event_type", "Cyble Alert"))
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{_uuid.uuid5(_STIX_NS, alert_id)}",
            "name": title,
            "published": obj.get("date", _now_ts()),
            "object_refs": [],
            "x_cyble_event_type": obj.get("event_type", ""),
            "x_cyble_priority": obj.get("priority", ""),
            "x_cyble_raw": obj,
        }

    def from_stix(self, stix_obj: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX object back to a Cyble Vision payload (no-op — read-only)."""
        raise GNATClientError("Cyble Vision is read-only — from_stix not supported.")
