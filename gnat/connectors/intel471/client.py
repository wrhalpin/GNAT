"""
gnat.connectors.intel471.client
===============================

Intel 471 (Cybercrime-Focused Threat Intelligence) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [intel471]
    host  = https://api.intel471.com
    token = <your-intel471-api-token>

Generate the token in the Intel 471 portal (Settings → API Access).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Intel 471 Resource               |
+================+==================================+
| indicator      | IOCs from cybercrime sources     |
+----------------+----------------------------------+
| report         | Actor profiles, malware campaigns, ransomware intel |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/actors                     — Threat actor profiles and activity
* /v1/malware                    — Malware samples and campaigns
* /v1/ransomware                 — Ransomware group intel and leaks
* /v1/iocs                       — Extracted IOCs from underground sources
* /v1/alerts                     — Real-time alerts on cybercrime activity
* /v1/search                     — Unified search across collections

Notes
-----
* Deep focus on actor attribution, malware, and ransomware operations.
* Strong on underground forum and marketplace monitoring.
* Excellent complement to Flashpoint and Hudson Rock for cybercrime depth.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c9d0e1f2-a3b4-5c6d-7e8f-9a0b1c2d3e4f")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Intel471Client(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Intel 471 Cybercrime Intelligence API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.intel471.com").
    token : str
        Intel 471 API token.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report":    "actors",
    }

    def __init__(self, host: str = "https://api.intel471.com", token: str = "", **kwargs: Any):
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
        """Lightweight ping via actors endpoint."""
        self.get("/v1/actors", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "indicator":
            return self.get(f"/v1/iocs/{object_id}")
        if stix_type == "report":
            return self.get(f"/v1/actors/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Intel 471: {stix_type}")

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
        # Default: actors
        resp = self.get("/v1/actors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Intel 471 connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Expanded Domain-specific helpers ───────────────────────────────────

    def fetch_actors(
        self,
        limit: int = 50,
        handle: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch threat actor profiles and activity."""
        params: dict[str, Any] = {"limit": limit}
        if handle:
            params["handle"] = handle
        resp = self.get("/v1/actors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_malware(
        self,
        limit: int = 50,
        family: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch malware samples and campaign intelligence."""
        params: dict[str, Any] = {"limit": limit}
        if family:
            params["family"] = family
        resp = self.get("/v1/malware", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_ransomware(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch ransomware group intelligence and leak site activity."""
        resp = self.get("/v1/ransomware", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_iocs(
        self,
        limit: int = 50,
        ioc_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch IOCs extracted from underground cybercrime sources."""
        params: dict[str, Any] = {"limit": limit}
        if ioc_type:
            params["type"] = ioc_type
        resp = self.get("/v1/iocs", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_alerts(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch real-time cybercrime intelligence alerts."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        resp = self.get("/v1/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def search(
        self,
        query: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Unified search across all Intel 471 collections."""
        params: dict[str, Any] = {"query": query, "limit": limit}
        resp = self.get("/v1/search", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch IOC (indicator) vs. actor/malware/ransomware (report)."""
        if "value" in native or "ioc_type" in native or "hash" in native:
            return self._ioc_to_stix(native)
        return self._actor_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "Intel 471 is read-only for cybercrime threat intelligence.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _ioc_to_stix(self, ioc: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        iid = ioc.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'intel471:{iid}')}"
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
            "name": f"Intel 471 IOC: {ioc_value}",
            "description": ioc.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_intel471": {
                "ioc_id": iid,
                "ioc_type": ioc_type,
                "actor": ioc.get("actor"),
                "malware_family": ioc.get("malware_family"),
                "confidence": ioc.get("confidence"),
            },
        }

    def _actor_to_stix(self, actor: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        aid = actor.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'intel471:{aid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": actor.get("observed_at") or now,
            "modified": now,
            "name": actor.get("handle") or actor.get("name") or f"Intel 471 Actor {aid}",
            "description": actor.get("description", ""),
            "report_types": ["threat-actor"],
            "x_intel471": {
                "actor_id": aid,
                "handle": actor.get("handle"),
                "forum": actor.get("forum"),
                "country": actor.get("country"),
                "active_since": actor.get("active_since"),
                "malware_families": actor.get("malware_families", []),
            },
        }
