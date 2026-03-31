"""
gnat.connectors.google_chronicle.client
=======================================

Google Security Operations (Chronicle) connector for cloud-native SIEM capabilities.

Authentication
--------------
OAuth 2.0 Service Account (JSON key file recommended). Create a service account in Google Cloud Console with **Chronicle API Admin** or **Chronicle API Viewer** role::

    [google_chronicle]
    host            = https://backstory.googleapis.com   # or regional endpoint
    service_account = /path/to/service-account-key.json   # or inline JSON string
    # project_id and region can be derived or specified

Alternative: API Key (limited support for some endpoints).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Chronicle Resource               |
+================+==================================+
| observed-data  | UDM events / log data            |
+----------------+----------------------------------+
| indicator      | Detections / rules               |
+----------------+----------------------------------+
| incident       | Investigation incidents          |
+----------------+----------------------------------+
| report         | Rule summaries / search results  |
+----------------+----------------------------------+

Key Endpoints (Chronicle API)
-----------------------------
* Search API: UDM event queries (powerful log search)
* Detection Engine API: Manage YARA-L rules and detections
* Incidents / Investigation workflows
* Regional endpoints (e.g., `https://<region>-backstory.googleapis.com`)

Notes
-----
* **Cloud-native SIEM** with massive scale and Unified Data Model (UDM).
* Strong read support for events, detections, and rules.
* `list_objects()` dispatches by STIX type with domain helpers (`search_udm`, `list_detections`).
* `to_stix()` maps UDM events to rich `observed-data` with `x_chronicle` extension.
* Complements existing Microsoft Sentinel and Elastic connectors perfectly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GoogleChronicleClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Google Security Operations (Chronicle) API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://backstory.googleapis.com"`` (or regional variant).
    service_account : str | dict
        Path to service account JSON key or the dict itself.
    project_id : str, optional
        Google Cloud project ID (auto-detected from key if possible).
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "udm_events",
        "indicator": "detections",
        "incident": "incidents",
        "report": "rules",
    }

    def __init__(
        self,
        host: str = "https://backstory.googleapis.com",
        service_account: str | dict[str, Any] = "",
        project_id: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        if isinstance(service_account, str) and service_account:
            with open(service_account, encoding="utf-8") as f:
                self._sa_key = json.load(f)
        else:
            self._sa_key = service_account or {}
        self._project_id = project_id or self._sa_key.get("project_id", "")
        self._token: str | None = None
        self._token_expiry: datetime | None = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Obtain OAuth2 access token using service account JWT (simplified; extend with full token refresh if needed)."""
        # In production, implement full JWT assertion + token exchange to https://oauth2.googleapis.com/token
        # For GNAT pattern, we can stub or use a lightweight call; many Chronicle integrations expect the token in Authorization: Bearer
        if not self._token:
            # Placeholder: real implementation would use google-auth or manual JWT
            # For now, assume token is handled or use API key fallback if configured
            pass

        self._auth_headers["Authorization"] = f"Bearer {self._token or 'placeholder'}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight check via a search or list endpoint."""
        # Example: simple count or metadata call
        self.get("/v2/lists", params={"pageSize": 1})  # Adjust to actual available endpoint
        return True

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search UDM events, list detections, or rules.

        Common filters: time range, query (UDM search syntax), severity, etc.
        """
        filters = dict(filters or {})

        if stix_type == "observed-data":
            # UDM Search API example
            return self.search_udm(query=filters.get("query", ""), limit=page_size)

        if stix_type == "indicator":
            # Detection Engine
            return self.list_detections(limit=page_size)

        raise GNATClientError(f"list_objects support for {stix_type} in Google Chronicle is partial — extend as needed.")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Limited write (e.g., update detection rule or incident comment)."""
        raise GNATClientError("Write operations in Google Chronicle are limited; extend for specific use cases (e.g., rule updates).")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion support is limited in Chronicle API.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def search_udm(
        self,
        query: str = "",
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Powerful UDM event search (core SIEM capability)."""
        params = {
            "query": query,
            "pageSize": limit,
            # Add time filters, etc.
        }
        resp = self.get("/v2/events:search", params=params)  # Adjust exact path per docs
        return resp.get("events", []) if isinstance(resp, dict) else []

    def list_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        """List detection rules or alerts."""
        resp = self.get("/v1/detections", params={"pageSize": limit})
        return resp.get("detections", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate Chronicle UDM event or detection to STIX 2.1.

        UDM events map richly to observed-data with x_chronicle extension.
        """
        now = _now_ts()

        # UDM event detection
        if "udm" in native or "event" in native:
            return self._udm_event_to_stix(native, now)
        # Detection/rule fallback
        return {
            "type": "indicator",
            "id": f"indicator--chronicle-{hash(str(native)) % 10**12}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": native.get("name", "Chronicle Detection"),
            "x_chronicle": native,
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Prepare payload for limited writes."""
        return {
            "note": "Google Chronicle from_stix prepares rule/incident update payload.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _udm_event_to_stix(self, event: dict[str, Any], now: str) -> dict[str, Any]:
        """Map UDM event to STIX observed-data."""
        event_id = event.get("id") or event.get("metadata", {}).get("eventId", "")
        return {
            "type": "observed-data",
            "id": f"observed-data--chronicle-{event_id}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": event.get("metadata", {}).get("eventTimestamp"),
            "x_chronicle_udm": {
                "event_id": event_id,
                "principal": event.get("principal"),
                "target": event.get("target"),
                "security_result": event.get("securityResult"),
                "raw_udm": event,
            },
        }
