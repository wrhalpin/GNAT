"""
gnat.connectors.extrahop.client
================================

ExtraHop Reveal(x) Network Detection and Response (NDR) connector.

Authentication
--------------
API key (Bearer token)::

    [extrahop]
    host    = https://<appliance-hostname>
    api_key = <extrahop-api-key>

For cloud deployments (Reveal(x) 360), use::

    [extrahop]
    host          = https://company.api.cloud.extrahop.com
    client_id     = <client-id>
    client_secret = <client-secret>
    auth_type     = oauth2

STIX Type Mapping
-----------------
+------------------+----------------------------------+
| STIX Type        | ExtraHop Resource                |
+==================+==================================+
| observed-data    | Detections                       |
+------------------+----------------------------------+
| network-traffic  | Records / Packets                |
+------------------+----------------------------------+

Key Endpoints (ExtraHop REST API v1)
--------------------------------------
* /api/v1/detections          — Security detections
* /api/v1/records/search      — Transaction records search
* /api/v1/devices             — Discovered devices
* /api/v1/threats             — Threat intelligence lookups
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d4e5f6a7-b8c9-0123-def0-456789012345")


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ExtraHopClient(BaseClient, ConnectorMixin):
    """
    HTTP client for ExtraHop Reveal(x) REST API (v1).

    Parameters
    ----------
    host : str
        ExtraHop appliance or cloud base URL.
    api_key : str
        ExtraHop API key (Bearer token auth).
    client_id : str
        OAuth2 client ID (for Reveal(x) 360 cloud only).
    client_secret : str
        OAuth2 client secret (for Reveal(x) 360 cloud only).
    """

    stix_type_map: Dict[str, str] = {
        "observed-data":  "detections",
        "network-traffic": "records",
    }

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._client_id = client_id
        self._client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject API key header or obtain OAuth2 token for cloud deployments."""
        if self._api_key:
            self._auth_headers["Authorization"] = f"ExtraHop apikey={self._api_key}"
        elif self._client_id and self._client_secret:
            resp = self.post(
                "/oauth2/token",
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            token = resp.get("access_token") if isinstance(resp, dict) else None
            if not token:
                raise GNATClientError("ExtraHop: failed to obtain OAuth2 access token")
            self._auth_headers["Authorization"] = f"Bearer {token}"
        else:
            raise GNATClientError("ExtraHop: provide api_key or client_id + client_secret")
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via detections endpoint."""
        self.get("/api/v1/detections", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch a single detection or device by ID."""
        if stix_type == "observed-data":
            return self.get(f"/api/v1/detections/{object_id}") or {}
        raise GNATClientError(f"ExtraHop: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "observed-data",
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """List detections or devices."""
        params: Dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if filters:
            params.update(filters)

        if stix_type == "observed-data":
            resp = self.get("/api/v1/detections", params=params)
            return resp if isinstance(resp, list) else []
        raise GNATClientError(f"ExtraHop: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """ExtraHop Reveal(x) is read-only; upsert is not supported."""
        raise GNATClientError("ExtraHop Reveal(x) connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ExtraHop Reveal(x) is read-only; delete is not supported."""
        raise GNATClientError("ExtraHop Reveal(x) connector is read-only.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_detections(
        self,
        risk_score_min: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List security detections from Reveal(x).

        Parameters
        ----------
        risk_score_min : int, optional
            Filter detections by minimum risk score (0-99).
        status : str, optional
            Filter by status: ``"new"``, ``"in_progress"``, ``"closed"``.
        limit : int
            Maximum records to return.
        """
        params: Dict[str, Any] = {"limit": limit}
        if risk_score_min is not None:
            params["risk_score_min"] = risk_score_min
        if status:
            params["status"] = status
        resp = self.get("/api/v1/detections", params=params)
        return resp if isinstance(resp, list) else []

    def search_records(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search transaction records in ExtraHop.

        Parameters
        ----------
        query : dict, optional
            ExtraHop record search filter dict.
        limit : int
            Maximum records to return.
        """
        payload: Dict[str, Any] = {"limit": limit}
        if query:
            payload["filter"] = query
        resp = self.post("/api/v1/records/search", json=payload)
        return resp.get("records", []) if isinstance(resp, dict) else []

    def list_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List discovered network devices."""
        resp = self.get("/api/v1/devices", params={"limit": limit})
        return resp if isinstance(resp, list) else []

    def threat_lookup(self, observable: str) -> Dict[str, Any]:
        """
        Look up a threat observable (IP, domain, URL) via ExtraHop TI.

        Parameters
        ----------
        observable : str
            The value to look up (e.g. ``"1.2.3.4"`` or ``"evil.com"``).
        """
        resp = self.post("/api/v1/threats/search", json={"observables": [observable]})
        results = resp.get("results", []) if isinstance(resp, dict) else []
        return results[0] if results else {}

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ExtraHop detection or record to a STIX 2.1 object."""
        if "risk_score" in native or "detection_type" in native:
            return self._detection_to_stix(native)
        return self._record_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Return a minimal ExtraHop reference payload from a STIX object."""
        return {
            "note":      "ExtraHop Reveal(x) is read-only.",
            "stix_id":   stix_dict.get("id", ""),
            "stix_type": stix_dict.get("type", ""),
        }

    def _detection_to_stix(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        det_id = str(detection.get("id", ""))
        start_time = detection.get("start_time", now)
        update_time = detection.get("update_time", now)
        return {
            "type":            "observed-data",
            "id":              f"observed-data--{_uuid.uuid5(_STIX_NS, f'extrahop:{det_id}')}",
            "spec_version":    "2.1",
            "created":         start_time,
            "modified":        update_time,
            "first_observed":  start_time,
            "last_observed":   update_time,
            "number_observed": 1,
            "object_refs":     [],
            "x_extrahop": {
                "detection_id":   det_id,
                "detection_type": detection.get("detection_type"),
                "category":       detection.get("category"),
                "risk_score":     detection.get("risk_score"),
                "status":         detection.get("status"),
                "participants":   detection.get("participants", []),
            },
        }

    def _record_to_stix(self, record: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        rec_id = str(record.get("id", ""))
        return {
            "type":            "observed-data",
            "id":              f"observed-data--{_uuid.uuid5(_STIX_NS, f'extrahop:rec:{rec_id}')}",
            "spec_version":    "2.1",
            "created":         now,
            "modified":        now,
            "first_observed":  record.get("timestamp", now),
            "last_observed":   record.get("timestamp", now),
            "number_observed": 1,
            "object_refs":     [],
            "x_extrahop_record": {
                "record_type": record.get("type"),
                "src_ip":      record.get("src_addr"),
                "dst_ip":      record.get("dst_addr"),
                "src_port":    record.get("src_port"),
                "dst_port":    record.get("dst_port"),
                "proto":       record.get("proto"),
            },
        }
