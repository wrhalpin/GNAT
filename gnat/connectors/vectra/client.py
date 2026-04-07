# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.vectra.client
================================

Vectra AI Network Detection and Response (NDR) connector.

Authentication
--------------
API token (Bearer)::

    [vectra]
    host    = https://<tenant>.vectra.ai
    api_key = <vectra-api-token>

Generate the token in Vectra Console → Settings → API Clients.

STIX Type Mapping
-----------------
+------------------+----------------------------------+
| STIX Type        | Vectra Resource                  |
+==================+==================================+
| observed-data    | Detections                       |
+------------------+----------------------------------+
| threat-actor     | Hosts (scored entities)          |
+------------------+----------------------------------+

Key Endpoints (Vectra AI v2.5+ REST API)
-----------------------------------------
* /api/v2.5/detections      — Detections with scoring
* /api/v2.5/hosts           — Host / entity scores
* /api/v2.5/accounts        — Account threat scoring
* /api/v2.5/search/hosts    — Advanced host search
* /api/v2.5/search/detections — Advanced detection search
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c3d4e5f6-a7b8-9012-cdef-345678901234")


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class VectraClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Vectra AI NDR REST API (v2.5+).

    Parameters
    ----------
    host : str
        Vectra tenant base URL (e.g. ``"https://yourorg.vectra.ai"``).
    api_key : str
        Vectra API token (Bearer).
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "detections",
        "threat-actor": "hosts",
    }

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        if not self._api_key:
            raise GNATClientError("Vectra: api_key is required")
        self._auth_headers["Authorization"] = f"Token {self._api_key}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via detection list endpoint."""
        self.get("/api/v2.5/detections", params={"page_size": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single detection or host by ID."""
        if stix_type == "observed-data":
            return self.get(f"/api/v2.5/detections/{object_id}") or {}
        if stix_type == "threat-actor":
            return self.get(f"/api/v2.5/hosts/{object_id}") or {}
        raise GNATClientError(f"Vectra: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "observed-data",
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List detections or hosts with optional filtering."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if filters:
            params.update(filters)

        if stix_type == "observed-data":
            resp = self.get("/api/v2.5/detections", params=params)
        elif stix_type == "threat-actor":
            resp = self.get("/api/v2.5/hosts", params=params)
        else:
            raise GNATClientError(f"Vectra: unsupported STIX type '{stix_type}'")
        return resp.get("results", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Vectra is primarily read-only; upsert is not supported."""
        raise GNATClientError("Vectra NDR connector is read-only — upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Vectra is primarily read-only; delete is not supported."""
        raise GNATClientError("Vectra NDR connector is read-only — delete not supported.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_detections(
        self,
        detection_type: str | None = None,
        threat_score_gte: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List network detections, optionally filtered by type or threat score.

        Parameters
        ----------
        detection_type : str, optional
            Vectra detection category (e.g. ``"Command & Control"``).
        threat_score_gte : int, optional
            Minimum threat score (0-100).
        limit : int
            Maximum records to return.
        """
        params: dict[str, Any] = {"page_size": limit}
        if detection_type:
            params["detection_type"] = detection_type
        if threat_score_gte is not None:
            params["threat_gte"] = threat_score_gte
        resp = self.get("/api/v2.5/detections", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def list_hosts(
        self,
        certainty_gte: int | None = None,
        threat_gte: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List host entities with AI-assigned threat and certainty scores.

        Parameters
        ----------
        certainty_gte : int, optional
            Minimum certainty score (0-100).
        threat_gte : int, optional
            Minimum threat score (0-100).
        limit : int
            Maximum records to return.
        """
        params: dict[str, Any] = {"page_size": limit}
        if certainty_gte is not None:
            params["certainty_gte"] = certainty_gte
        if threat_gte is not None:
            params["threat_gte"] = threat_gte
        resp = self.get("/api/v2.5/hosts", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def search_detections(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Run a Vectra advanced detection search.

        Parameters
        ----------
        query : str
            Vectra search expression (e.g. ``"detection.detection_type:\"C&C\""``)
        limit : int
            Maximum records to return.
        """
        resp = self.get(
            "/api/v2.5/search/detections", params={"query_string": query, "page_size": limit}
        )
        return resp.get("results", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Vectra detection or host to a STIX 2.1 object."""
        if "detection_type" in native:
            return self._detection_to_stix(native)
        return self._host_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a minimal Vectra search payload from a STIX object."""
        return {
            "note": "Vectra is read-only; this payload is for reference.",
            "stix_id": stix_dict.get("id", ""),
            "stix_type": stix_dict.get("type", ""),
        }

    def _detection_to_stix(self, detection: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        det_id = str(detection.get("id", ""))
        first_ts = detection.get("first_timestamp", now)
        last_ts = detection.get("last_timestamp", now)
        return {
            "type": "observed-data",
            "id": f"observed-data--{_uuid.uuid5(_STIX_NS, f'vectra:{det_id}')}",
            "spec_version": "2.1",
            "created": first_ts,
            "modified": last_ts,
            "first_observed": first_ts,
            "last_observed": last_ts,
            "number_observed": 1,
            "object_refs": [],
            "x_vectra": {
                "detection_id": det_id,
                "detection_type": detection.get("detection_type"),
                "category": detection.get("category"),
                "threat": detection.get("threat"),
                "certainty": detection.get("certainty"),
                "src_ip": detection.get("src_ip"),
                "src_host": detection.get("src_host", {}).get("name"),
                "state": detection.get("state"),
            },
        }

    def _host_to_stix(self, host: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        host_id = str(host.get("id", ""))
        return {
            "type": "threat-actor",
            "id": f"threat-actor--{_uuid.uuid5(_STIX_NS, f'vectra:{host_id}')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": host.get("name", f"Vectra Host {host_id}"),
            "description": "Host entity scored by Vectra AI NDR",
            "x_vectra": {
                "host_id": host_id,
                "ip": host.get("ip"),
                "threat": host.get("threat"),
                "certainty": host.get("certainty"),
                "tags": host.get("tags", []),
                "state": host.get("state"),
            },
        }
