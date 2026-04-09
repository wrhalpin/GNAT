# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hudsonrock.client
=================================

Hudson Rock (Breach Intelligence & Credential Exposure) connector — full client.

Authentication
--------------
API Key via ``x-api-key`` header::

    [hudsonrock]
    host     = https://api.hudsonrock.com
    api_key  = <your-hudsonrock-api-key>

Generate the key in Hudson Rock dashboard (Settings → API Keys).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Hudson Rock Resource             |
+================+==================================+
| indicator      | Compromised credentials & IOCs   |
+----------------+----------------------------------+
| report         | Breach events & victim intel     |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/breaches                   — List recent breaches
* /v1/credentials                — Search compromised credentials
* /v1/iocs                       — Extracted IOCs from breaches
* /v1/victims                    — Victim company / individual details
* /v1/search                     — Unified search across all data

Notes
-----
* Extremely fast collection of fresh compromises (often within hours).
* Strong credential and initial access broker intelligence.
* Complements your Flashpoint, ZeroFox, Group-IB, and Flare connectors with rapid credential exposure data.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b0c1d2e3-f4a5-6b7c-8d9e-0f1a2b3c4d5e")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class HudsonRockClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Hudson Rock Breach Intelligence API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.hudsonrock.com").
    api_key : str
        Hudson Rock API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "indicator": "credentials",
        "report": "breaches",
    }

    def __init__(self, host: str = "https://api.hudsonrock.com", api_key: str = "", **kwargs: Any):
        """Initialize HudsonRockClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject x-api-key header."""
        self._auth_headers["x-api-key"] = self._api_key
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via recent breaches."""
        self.get("/v1/breaches", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "report":
            return self.get(f"/v1/breaches/{object_id}")
        if stix_type == "indicator":
            return self.get(f"/v1/credentials/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Hudson Rock: {stix_type}")

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
            resp = self.get("/v1/credentials", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: breaches
        resp = self.get("/v1/breaches", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Hudson Rock connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Expanded Domain-specific helpers ───────────────────────────────────

    def fetch_breaches(
        self,
        limit: int = 50,
        since: str | None = None,
        victim_type: str | None = None,  # company, individual, etc.
    ) -> list[dict[str, Any]]:
        """Fetch recent breach events."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        if victim_type:
            params["victim_type"] = victim_type
        resp = self.get("/v1/breaches", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_credentials(
        self,
        limit: int = 50,
        domain: str | None = None,
        email: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search compromised credentials."""
        params: dict[str, Any] = {"limit": limit}
        if domain:
            params["domain"] = domain
        if email:
            params["email"] = email
        resp = self.get("/v1/credentials", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_iocs(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch extracted IOCs from recent compromises."""
        resp = self.get("/v1/iocs", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_victims(
        self,
        limit: int = 50,
        victim_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch victim details (companies or individuals)."""
        params: dict[str, Any] = {"limit": limit}
        if victim_name:
            params["name"] = victim_name
        resp = self.get("/v1/victims", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch credential/IOC (indicator) vs. breach/victim (report)."""
        if "email" in native or "password" in native or "hash" in native:
            return self._credential_to_stix(native)
        return self._breach_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "Hudson Rock is read-only for breach and credential intelligence.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _credential_to_stix(self, cred: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for credential to stix."""
        now = _now_ts()
        cid = cred.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'hudsonrock:{cid}')}"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": cred.get("breach_date") or now,
            "modified": now,
            "name": cred.get("email") or cred.get("username", "Compromised Credential"),
            "description": f"Compromised credential from {cred.get('source', 'unknown')}",
            "pattern": f"[email-addr:value = '{cred.get('email')}']" if cred.get("email") else None,
            "pattern_type": "stix",
            "indicator_types": ["compromised"],
            "x_hudsonrock": {
                "credential_id": cid,
                "source": cred.get("source"),
                "breach_id": cred.get("breach_id"),
                "victim": cred.get("victim"),
            },
        }

    def _breach_to_stix(self, breach: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for breach to stix."""
        now = _now_ts()
        bid = breach.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'hudsonrock:{bid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": breach.get("date") or now,
            "modified": now,
            "name": breach.get("title", "Hudson Rock Breach"),
            "description": breach.get("description", ""),
            "report_types": ["data-breach"],
            "labels": [breach.get("type", "")],
            "x_hudsonrock": {
                "breach_id": bid,
                "victim_count": breach.get("victim_count"),
                "data_types": breach.get("data_types", []),
                "severity": breach.get("severity"),
            },
        }
