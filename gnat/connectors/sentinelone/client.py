# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sentinelone.client
==================================

SentinelOne Singularity (Threat Intelligence + Endpoint Threats) connector — full client.

Authentication
--------------
API Token via ``Authorization: ApiToken`` header::

    [sentinelone]
    host  = https://<your-region>.sentinelone.net   # e.g. https://usea1-partners.sentinelone.net
    token = <your-sentinelone-api-token>

Generate token in SentinelOne Console (Settings → Users → Service Users or API Tokens). Grant "Threat Intelligence" scope where possible.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | SentinelOne Resource             |
+================+==================================+
| indicator      | Threats / IOCs / hashes          |
+----------------+----------------------------------+
| report         | Threat details / Storylines      |
+----------------+----------------------------------+

Key Endpoints (Management API)
------------------------------
* /web/api/v2.1/threats/               — List threats
* /web/api/v2.1/threats/{id}           — Single threat
* /web/api/v2.1/hash-reputation        — Hash reputation (Mandiant-powered)
* /web/api/v2.1/agents/                — Endpoints (asset context)
* /web/api/v2.1/blacklist              — Blocklist management (write-capable)

Notes
-----
* Primarily read-oriented for threat intel ingestion.
* Mandiant integration enriches threats with actor/context.
* Pagination uses `limit` + `cursor` or offset.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

_STIX_NS = _uuid.UUID("f0a1b2c3-d4e5-4f6a-8b9c-0d1e2f3a4b5c")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SentinelOneClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for SentinelOne Singularity Management API (v2.1+).

    Parameters
    ----------
    host : str
        Region-specific base URL (e.g. "https://usea1-partners.sentinelone.net").
    token : str
        SentinelOne API token.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v2.1"
    API_PREFIX: str = "/web/api"

    stix_type_map: dict[str, str] = {
        "indicator": "threats",
        "report": "threats",  # enriched threat details
    }

    def __init__(self, host: str, token: str = "", **kwargs: Any):
        """Initialize SentinelOneClient."""
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject ApiToken header."""
        self._auth_headers["Authorization"] = f"ApiToken {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via threats or agents endpoint."""
        self.get("/web/api/v2.1/threats/", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type in ("indicator", "report"):
            return self.get(f"/web/api/v2.1/threats/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for SentinelOne: {stix_type}")

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
        # Add common filters (e.g., created_after, threat_level)
        for k, v in filters.items():
            params[k] = v

        if stix_type in ("indicator", "report"):
            resp = self.get("/web/api/v2.1/threats/", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        raise GNATClientError(f"list_objects not supported for STIX type: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError(
            "SentinelOne connector is primarily read-only (limited write via blacklist)."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not directly supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def get_hash_reputation(self, sha1: str) -> dict[str, Any]:
        """Get Mandiant-powered hash reputation."""
        params = {"hash": sha1}
        return self.get("/web/api/v2.1/hash-reputation", params=params)

    def list_agents(
        self,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """List endpoints/agents for asset context."""
        params: dict[str, Any] = {"limit": limit, **(filters or {})}
        resp = self.get("/web/api/v2.1/agents/", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def add_to_blocklist(self, sha1: str, comment: str = "") -> dict[str, Any]:
        """Add hash to blocklist (write capability)."""
        payload = {"hashes": [sha1], "comment": comment}
        return self.post("/web/api/v2.1/blacklist", json=payload)

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert threat or agent data to STIX."""
        if "threatInfo" in native or "mitigationStatus" in native:
            return self._threat_to_stix(native)
        return self._agent_to_stix(native)  # fallback for asset context

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "SentinelOne is primarily read-only for threat intel. Use get_hash_reputation or add_to_blocklist for actions.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _threat_to_stix(self, threat: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for threat to stix."""
        now = _now_ts()
        tid = threat.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f's1:{tid}')}"
        threat_info = threat.get("threatInfo", {})
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": CURRENT_SPEC_VERSION,
            "created": threat.get("createdAt") or now,
            "modified": now,
            "name": threat_info.get("threatName", "SentinelOne Threat"),
            "description": threat.get("description", ""),
            "pattern": f"[file:hashes.'SHA-1' = '{threat_info.get('sha1', '')}']"
            if threat_info.get("sha1")
            else None,
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_sentinelone": {
                "threat_id": tid,
                "severity": threat_info.get("severity"),
                "classification": threat_info.get("classification"),
                "mitigation_status": threat.get("mitigationStatus"),
                "mandiant_context": threat.get("mandiant", {}),  # if enriched
            },
        }

    def _agent_to_stix(self, agent: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for agent to stix."""
        now = _now_ts()
        aid = agent.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'agent:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": CURRENT_SPEC_VERSION,
            "created": now,
            "modified": now,
            "name": f"SentinelOne Agent: {agent.get('computerName', '')}",
            "description": "Endpoint asset with threat context",
            "report_types": ["asset-inventory"],
            "x_sentinelone": {
                "agent_id": aid,
                "computer_name": agent.get("computerName"),
                "os": agent.get("osName"),
                "last_seen": agent.get("lastSeen"),
            },
        }
