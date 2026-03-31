"""
gnat.connectors.flashpoint.client
=================================

Flashpoint (Underground / Dark Web CTI) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [flashpoint]
    host  = https://api.flashpoint.io
    token = <your-flashpoint-api-token>

Generate the token in the Flashpoint portal (Settings → API Access).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Flashpoint Resource              |
+================+==================================+
| indicator      | IOCs from underground sources    |
+----------------+----------------------------------+
| report         | Alerts / Threat Actor intel / Forum posts |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/alerts                     — Real-time alerts from underground sources
* /v1/iocs                       — IOCs extracted from dark web / forums
* /v1/threat-actors              — Threat actor profiles and activity
* /v1/forums                     — Forum posts and marketplace listings
* /v1/ransomware                 — Ransomware-specific intelligence
* /v1/search                     — Unified search across collections

Notes
-----
* Deep underground visibility (forums, dark web markets, Telegram, etc.).
* Strong on early ransomware and cybercrime signals.
* Read-only for most use cases; excellent for enrichment.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a9b8c7d6-e5f4-3a2b-1c0d-9e8f7a6b5c4d")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FlashpointClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Flashpoint Underground CTI API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.flashpoint.io").
    token : str
        Flashpoint API token.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report":    "alerts",
    }

    def __init__(self, host: str = "https://api.flashpoint.io", token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via alerts endpoint."""
        self.get("/v1/alerts", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "indicator":
            return self.get(f"/v1/iocs/{object_id}")
        if stix_type == "report":
            return self.get(f"/v1/alerts/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Flashpoint: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size}
        params.update(filters)

        if stix_type == "indicator":
            resp = self.get("/v1/iocs", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: alerts
        resp = self.get("/v1/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Flashpoint connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Expanded Domain-specific helpers ───────────────────────────────────

    def fetch_alerts(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch real-time alerts from underground sources."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        resp = self.get("/v1/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_iocs(
        self,
        limit: int = 50,
        ioc_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch IOCs extracted from dark web and forums."""
        params: dict[str, Any] = {"limit": limit}
        if ioc_type:
            params["type"] = ioc_type
        resp = self.get("/v1/iocs", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_threat_actors(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch threat actor profiles and activity."""
        resp = self.get("/v1/threat-actors", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_forums(
        self,
        limit: int = 50,
        keyword: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch forum posts and marketplace listings."""
        params: dict[str, Any] = {"limit": limit}
        if keyword:
            params["keyword"] = keyword
        resp = self.get("/v1/forums", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_ransomware(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch ransomware group intelligence and leak site activity."""
        resp = self.get("/v1/ransomware", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def search(
        self,
        query: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Unified search across all Flashpoint collections."""
        params: dict[str, Any] = {"query": query, "limit": limit}
        resp = self.get("/v1/search", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch IOC (indicator) vs. alert/actor (report)."""
        if "value" in native or "ioc_type" in native or "hash" in native:
            return self._ioc_to_stix(native)
        return self._alert_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "Flashpoint is read-only for underground threat intelligence.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _ioc_to_stix(self, ioc: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        iid = ioc.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'flashpoint:{iid}')}"
        ioc_value = ioc.get("value", "")
        ioc_type = ioc.get("ioc_type", "").lower()
        if ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{ioc_value}']"
        elif ioc_type in ("domain", "hostname"):
            pattern = f"[domain-name:value = '{ioc_value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{ioc_value}']"
        elif ioc_type in ("md5", "sha1", "sha256"):
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{ioc_value}']"
        else:
            pattern = f"[artifact:payload_bin = '{ioc_value}']"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": ioc.get("first_seen") or now,
            "modified": ioc.get("last_seen") or now,
            "name": f"Flashpoint IOC: {ioc_value}",
            "description": ioc.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_flashpoint": {
                "ioc_id": iid,
                "ioc_type": ioc_type,
                "source": ioc.get("source"),
                "confidence": ioc.get("confidence"),
            },
        }

    def _alert_to_stix(self, alert: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        aid = alert.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'flashpoint:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": alert.get("created_at") or now,
            "modified": alert.get("updated_at") or now,
            "name": alert.get("title", "Flashpoint Alert"),
            "description": alert.get("description", ""),
            "report_types": ["threat-report"],
            "labels": [alert.get("category", "")],
            "x_flashpoint": {
                "alert_id": aid,
                "severity": alert.get("severity"),
                "source": alert.get("source"),
                "threat_actor": alert.get("threat_actor"),
            },
        }
