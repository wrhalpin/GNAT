"""
gnat.connectors.tenable_one.client
==================================

Tenable One (Exposure Management) connector — full client.

Authentication
--------------
API Keys (accessKey + secretKey) via ``X-ApiKeys`` header::

    [tenable_one]
    host       = https://cloud.tenable.com
    access_key = <tenable-access-key>
    secret_key = <tenable-secret-key>

Generate keys in Tenable UI (My Account → API Keys). One pair per account.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Tenable Resource                 |
+================+==================================+
| vulnerability  | Vulnerabilities / findings       |
+----------------+----------------------------------+
| report         | Exposure View cards, Attack Paths|
+----------------+----------------------------------+

Key Endpoints (2026 Tenable One API)
------------------------------------
* /api/v1/t1/exposure-view/cards          — Exposure cards with Cyber Exposure Scores
* /api/v1/t1/apa/top-attack-paths/search  — Attack Path Analysis
* /scans, /assets, /vulnerabilities       — Classic VM endpoints (still widely used)

Notes
-----
* Primarily read-oriented for ingestion of exposure intel and attack paths.
* Many endpoints support filters, pagination (limit/offset or cursor).
* Attack Path Analysis leverages MITRE ATT&CK and graph analytics.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e6f7a8b9-c0d1-2e3f-4a5b-6c7d8e9f0a1b")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TenableOneClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Tenable One Exposure Management API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://cloud.tenable.com").
    access_key : str
        Tenable access key.
    secret_key : str
        Tenable secret key.
    """

    stix_type_map: dict[str, str] = {
        "vulnerability": "vulnerabilities",
        "report":        "exposure-view",  # cards + attack paths
    }

    def __init__(self, host: str = "https://cloud.tenable.com", access_key: str = "", secret_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._access_key = access_key
        self._secret_key = secret_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set X-ApiKeys header with accessKey/secretKey pair."""
        self._auth_headers["X-ApiKeys"] = f"accessKey={self._access_key};secretKey={self._secret_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via user or assets endpoint."""
        self.get("/users", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch single object (e.g., vulnerability or exposure card)."""
        if stix_type == "vulnerability":
            return self.get(f"/vulnerabilities/{object_id}")
        if stix_type == "report":
            return self.get(f"/api/v1/t1/exposure-view/cards/{object_id}")
        raise GNATClientError(f"Unsupported get_object for STIX type: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        if stix_type == "vulnerability":
            return self.fetch_vulnerabilities(limit=page_size, **filters)
        # Default: exposure cards + attack paths as reports
        return self.fetch_exposure_cards(limit=page_size, **filters)

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Tenable One connector is read-focused.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Tenable One connector does not support deletion.")

    # ── Domain-specific helpers (expanded) ─────────────────────────────────

    def fetch_vulnerabilities(
        self,
        limit: int = 50,
        severity: str | None = None,
        plugin_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch vulnerabilities/findings."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        if plugin_id:
            params["plugin_id"] = plugin_id
        resp = self.get("/vulnerabilities", params=params)
        return resp.get("vulnerabilities", []) if isinstance(resp, dict) else []

    def fetch_exposure_cards(
        self,
        limit: int = 50,
        card_type: str | None = None,  # e.g., "cyber-exposure-score"
    ) -> list[dict[str, Any]]:
        """Fetch Exposure View cards (Cyber Exposure Scores, risk metrics)."""
        params: dict[str, Any] = {"limit": limit}
        if card_type:
            params["type"] = card_type
        resp = self.get("/api/v1/t1/exposure-view/cards", params=params)
        return resp.get("cards", []) if isinstance(resp, dict) else []

    def fetch_attack_paths(
        self,
        limit: int = 20,
        exclude_resolved: bool = True,
    ) -> list[dict[str, Any]]:
        """Fetch top Attack Paths (graph analytics + MITRE ATT&CK)."""
        payload = {
            "limit": limit,
            "exclude_resolved": exclude_resolved,
        }
        resp = self.post("/api/v1/t1/apa/top-attack-paths/search", json=payload)
        return resp.get("attack_paths", []) if isinstance(resp, dict) else []

    def fetch_assets(
        self,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch asset inventory (supports advanced filtering)."""
        params = {"limit": limit, **(filters or {})}
        resp = self.get("/assets", params=params)
        return resp.get("assets", []) if isinstance(resp, dict) else []

    # ── STIX Translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch based on structure (vulnerability, exposure card, attack path)."""
        if "plugin_id" in native or "severity" in native and "risk" in native:
            return self._vuln_to_stix(native)
        if "attack_path" in str(native).lower() or "technique" in native:
            return self._attack_path_to_stix(native)
        return self._exposure_card_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "Tenable One is primarily read-only. Use fetch_* helpers.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private STIX mappers ───────────────────────────────────────────────

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        vid = vuln.get("id") or vuln.get("plugin_id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'tenable:{vid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": vuln.get("name") or f"Tenable Plugin {vid}",
            "description": vuln.get("description", ""),
            "external_references": [{"source_name": "tenable", "external_id": vid}],
            "x_tenable": {
                "plugin_id": vid,
                "severity": vuln.get("severity"),
                "risk_score": vuln.get("risk_score"),
                "cvss": vuln.get("cvss"),
            },
        }

    def _exposure_card_to_stix(self, card: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        cid = card.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'card:{cid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": card.get("title") or "Tenable Exposure Card",
            "description": card.get("description", ""),
            "report_types": ["exposure-metrics"],
            "x_tenable": {
                "card_id": cid,
                "cyber_exposure_score": card.get("cyber_exposure_score"),
                "type": card.get("type"),
            },
        }

    def _attack_path_to_stix(self, path: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        pid = path.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'attackpath:{pid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": path.get("name") or "Tenable Attack Path",
            "description": path.get("description", "Attack path with MITRE ATT&CK techniques"),
            "report_types": ["attack-path"],
            "labels": [path.get("priority_rating", "")],
            "x_tenable": {
                "path_id": pid,
                "priority_rating": path.get("priority_rating"),
                "techniques": path.get("techniques", []),
                "nodes": path.get("nodes", []),
            },
        }
