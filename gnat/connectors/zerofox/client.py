# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.zerofox.client
==============================

ZeroFox (Brand Protection + Digital Risk Protection + CTI) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [zerofox]
    host  = https://api.zerofox.com
    token = <your-zerofox-api-token>

Generate the token in the ZeroFox console (Settings → API & Integrations or Data Connections).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | ZeroFox Resource                 |
+================+==================================+
| indicator      | Threats / IOCs (botnets, malware, phishing) |
+----------------+----------------------------------+
| report         | Alerts / Brand incidents         |
+----------------+----------------------------------+

Key Endpoints
-------------
* /v1/alerts                     — Platform alerts (brand threats, impersonation, etc.)
* /cti/...                       — CTI feeds (botnets, malware, ransomware, C2, etc.)
* /v1/threats or similar         — Threat intelligence data

Notes
-----
* Strong on social media, brand impersonation, phishing, and external digital risks.
* Read-heavy with rich CTI feeds for enrichment.
* Complements your Cyble Vision, CloudSEK, and Flare connectors with brand/social focus.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ZeroFoxClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for ZeroFox Platform and CTI APIs.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.zerofox.com").
    token : str
        ZeroFox API token.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "indicator": "threats",
        "report": "alerts",
    }

    def __init__(self, host: str = "https://api.zerofox.com", token: str = "", **kwargs: Any):
        """Initialize ZeroFoxClient."""
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
        """Retrieve object."""
        if stix_type == "report":
            return self.get(f"/v1/alerts/{object_id}")
        if stix_type == "indicator":
            # CTI threat detail (adjust endpoint if exact ID path differs)
            return self.get(f"/cti/threats/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for ZeroFox: {stix_type}")

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

        if stix_type == "indicator":
            # CTI threats/feeds
            resp = self.get("/cti/threats", params=params)  # or specific feed endpoint
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: alerts as reports
        resp = self.get("/v1/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("ZeroFox connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_alerts(
        self,
        limit: int = 50,
        alert_type: str | None = None,  # e.g., impersonation, phishing
    ) -> list[dict[str, Any]]:
        """Fetch brand protection and digital risk alerts."""
        params: dict[str, Any] = {"limit": limit}
        if alert_type:
            params["type"] = alert_type
        resp = self.get("/v1/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_cti_threats(
        self,
        limit: int = 50,
        threat_type: str | None = None,  # botnet, malware, ransomware, etc.
    ) -> list[dict[str, Any]]:
        """Fetch CTI feeds (botnets, malware, C2, phishing, etc.)."""
        params: dict[str, Any] = {"limit": limit}
        if threat_type:
            params["type"] = threat_type
        resp = self.get("/cti/threats", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch alert (report) vs. threat/IOC (indicator)."""
        if "ioc" in native or "hash" in native or "url" in native:
            return self._threat_to_stix(native)
        return self._alert_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "ZeroFox is read-only for brand protection and CTI data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _alert_to_stix(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for alert to stix."""
        now = _now_ts()
        aid = alert.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'zerofox:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": alert.get("created_at") or now,
            "modified": now,
            "name": alert.get("title", "ZeroFox Alert"),
            "description": alert.get("description", ""),
            "report_types": ["brand-threat", "digital-risk"],
            "labels": [alert.get("type", ""), alert.get("severity", "")],
            "x_zerofox": {
                "alert_id": aid,
                "type": alert.get("type"),
                "severity": alert.get("severity"),
                "source": alert.get("source"),
            },
        }

    def _threat_to_stix(self, threat: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for threat to stix."""
        now = _now_ts()
        tid = threat.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'zerofox:{tid}')}"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": threat.get("name", "ZeroFox Threat"),
            "description": threat.get("description", ""),
            "pattern": self._build_pattern(threat),  # simple pattern helper
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_zerofox": {
                "threat_id": tid,
                "type": threat.get("type"),
                "category": threat.get("category"),
            },
        }

    def _build_pattern(self, threat: dict[str, Any]) -> str | None:
        """Basic STIX pattern builder (expand as needed)."""
        if "url" in threat:
            return f"[url:value = '{threat['url']}']"
        if "hash" in threat:
            return f"[file:hashes.'SHA-256' = '{threat['hash']}']"
        return None
