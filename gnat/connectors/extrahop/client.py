# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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
from typing import Any

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

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "observed-data": "detections",
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
        """Initialize ExtraHopClient."""
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
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
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

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single detection or device by ID."""
        if stix_type == "observed-data":
            return self.get(f"/api/v1/detections/{object_id}") or {}
        raise GNATClientError(f"ExtraHop: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "observed-data",
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List detections or devices."""
        params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if filters:
            params.update(filters)

        if stix_type == "observed-data":
            resp = self.get("/api/v1/detections", params=params)
            return resp if isinstance(resp, list) else []
        raise GNATClientError(f"ExtraHop: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """ExtraHop Reveal(x) is read-only; upsert is not supported."""
        raise GNATClientError("ExtraHop Reveal(x) connector is read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ExtraHop Reveal(x) is read-only; delete is not supported."""
        raise GNATClientError("ExtraHop Reveal(x) connector is read-only.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_detections(
        self,
        risk_score_min: int | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
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
        params: dict[str, Any] = {"limit": limit}
        if risk_score_min is not None:
            params["risk_score_min"] = risk_score_min
        if status:
            params["status"] = status
        resp = self.get("/api/v1/detections", params=params)
        return resp if isinstance(resp, list) else []

    def search_records(
        self,
        query: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search transaction records in ExtraHop.

        Parameters
        ----------
        query : dict, optional
            ExtraHop record search filter dict.
        limit : int
            Maximum records to return.
        """
        payload: dict[str, Any] = {"limit": limit}
        if query:
            payload["filter"] = query
        resp = self.post("/api/v1/records/search", json=payload)
        return resp.get("records", []) if isinstance(resp, dict) else []

    def list_devices(self, limit: int = 100) -> list[dict[str, Any]]:
        """List discovered network devices."""
        resp = self.get("/api/v1/devices", params={"limit": limit})
        return resp if isinstance(resp, list) else []

    def threat_lookup(self, observable: str) -> dict[str, Any]:
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

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an ExtraHop detection or record to a STIX 2.1 object."""
        if "risk_score" in native or "detection_type" in native:
            return self._detection_to_stix(native)
        return self._record_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a minimal ExtraHop reference payload from a STIX object."""
        return {
            "note": "ExtraHop Reveal(x) is read-only.",
            "stix_id": stix_dict.get("id", ""),
            "stix_type": stix_dict.get("type", ""),
        }

    # ── Detections (enhanced) ─────────────────────────────────────────────────

    def get_detection(self, detection_id: int | str) -> dict[str, Any]:
        """Retrieve a single detection by ID."""
        resp = self.get(f"/api/v1/detections/{detection_id}")
        return resp if isinstance(resp, dict) else {}

    def update_detection(
        self,
        detection_id: int | str,
        status: str = "",
        assignee: str = "",
        resolution: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        """
        Update a detection's triage status or assignee.

        ``status`` options: ``"new"``, ``"in_progress"``, ``"closed"``.
        ``resolution`` options: ``"action_taken"``, ``"no_action_taken"``,
        ``"acknowledged"``.
        """
        payload: dict[str, Any] = {}
        if status:
            payload["status"] = status
        if assignee:
            payload["assignee"] = assignee
        if resolution:
            payload["resolution"] = resolution
        if notes:
            payload["notes"] = notes
        resp = self.patch(f"/api/v1/detections/{detection_id}", json=payload)
        return resp if isinstance(resp, dict) else {}

    def search_detections(
        self,
        filter_body: dict[str, Any] | None = None,
        from_time: int | None = None,
        until_time: int | None = None,
        limit: int = 100,
        offset: int = 0,
        sort: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Advanced detection search using the ExtraHop filter DSL.

        ``filter_body`` example::

            {"field": "risk_score", "operator": ">=", "operand": 70}

        ``from_time`` / ``until_time`` — Unix timestamps in milliseconds.
        """
        payload: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter_body:
            payload["filter"] = filter_body
        if from_time is not None:
            payload["from"] = from_time
        if until_time is not None:
            payload["until"] = until_time
        if sort:
            payload["sort"] = sort
        resp = self.post("/api/v1/detections/search", json=payload)
        return resp if isinstance(resp, list) else []

    def add_detection_note(
        self, detection_id: int | str, note: str
    ) -> dict[str, Any]:
        """Add an analyst note to a detection."""
        resp = self.post(
            f"/api/v1/detections/{detection_id}/notes",
            json={"note": note},
        )
        return resp if isinstance(resp, dict) else {}

    def list_detection_notes(self, detection_id: int | str) -> list[dict[str, Any]]:
        """List analyst notes attached to a detection."""
        resp = self.get(f"/api/v1/detections/{detection_id}/notes")
        return resp if isinstance(resp, list) else []

    # ── Devices ───────────────────────────────────────────────────────────────

    def get_device(self, device_id: int | str) -> dict[str, Any]:
        """Retrieve full metadata for a specific discovered device."""
        resp = self.get(f"/api/v1/devices/{device_id}")
        return resp if isinstance(resp, dict) else {}

    def search_devices(
        self,
        query: str = "",
        active_from: int | None = None,
        active_until: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Search devices by name, IP, MAC, or other attributes.

        ``query`` is matched against device names, IPs, and hostnames.
        ``active_from`` / ``active_until`` — Unix timestamps (ms) for activity window.
        """
        payload: dict[str, Any] = {"limit": limit, "offset": offset}
        if query:
            payload["search_type"] = "any"
            payload["value"] = query
        if active_from is not None:
            payload["active_from"] = active_from
        if active_until is not None:
            payload["active_until"] = active_until
        resp = self.post("/api/v1/devices/search", json=payload)
        return resp if isinstance(resp, list) else []

    def get_device_alerts(
        self, device_id: int | str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List detections involving a specific device."""
        payload: dict[str, Any] = {
            "limit": limit,
            "filter": {
                "field": "participants",
                "operator": "includes",
                "operand": {"type": "device", "id": int(device_id)},
            },
        }
        resp = self.post("/api/v1/detections/search", json=payload)
        return resp if isinstance(resp, list) else []

    def get_device_activity(
        self,
        device_id: int | str,
        from_time: int | None = None,
        until_time: int | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve protocol activity summary for a device.

        ``from_time`` / ``until_time`` — Unix timestamps in milliseconds.
        """
        params: dict[str, Any] = {}
        if from_time is not None:
            params["from"] = from_time
        if until_time is not None:
            params["until"] = until_time
        resp = self.get(f"/api/v1/devices/{device_id}/activity", params=params)
        return resp if isinstance(resp, dict) else {}

    def list_device_peers(
        self, device_id: int | str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List peer devices that communicated with a specific device."""
        resp = self.get(f"/api/v1/devices/{device_id}/peers", params={"limit": limit})
        return resp if isinstance(resp, list) else []

    # ── Custom device groups ──────────────────────────────────────────────────

    def list_custom_devices(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all custom device groups defined in ExtraHop."""
        resp = self.get("/api/v1/customdevices", params={"limit": limit})
        return resp if isinstance(resp, list) else []

    def create_custom_device(
        self,
        name: str,
        criteria: list[dict[str, Any]],
        description: str = "",
    ) -> dict[str, Any]:
        """
        Create a custom device group.

        ``criteria`` example::

            [{"ipaddr": "10.0.1.0/24"},
             {"ipaddr": "10.0.2.5"}]
        """
        payload: dict[str, Any] = {"name": name, "criteria": criteria}
        if description:
            payload["description"] = description
        resp = self.post("/api/v1/customdevices", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Network locality ──────────────────────────────────────────────────────

    def list_network_localities(self) -> list[dict[str, Any]]:
        """List network locality entries (CIDR → label mappings)."""
        resp = self.get("/api/v1/networklocalities")
        return resp if isinstance(resp, list) else []

    def create_network_locality(
        self,
        cidr: str,
        label: str,
        description: str = "",
    ) -> dict[str, Any]:
        """
        Define a network locality (label a CIDR block).

        Useful for tagging internal subnets, DMZs, or cloud VPCs.
        """
        payload: dict[str, Any] = {"network": cidr, "name": label}
        if description:
            payload["description"] = description
        resp = self.post("/api/v1/networklocalities", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Records (advanced) ────────────────────────────────────────────────────

    def search_records_typed(
        self,
        record_types: list[str] | None = None,
        filter_body: dict[str, Any] | None = None,
        from_time: int | None = None,
        until_time: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search transaction records with explicit type filtering.

        ``record_types`` example: ``["~ssl", "~http", "~dns"]``.
        ``filter_body`` — ExtraHop record filter DSL dict.
        """
        payload: dict[str, Any] = {"limit": limit}
        if record_types:
            payload["types"] = record_types
        if filter_body:
            payload["filter"] = filter_body
        if from_time is not None:
            payload["from"] = from_time
        if until_time is not None:
            payload["until"] = until_time
        resp = self.post("/api/v1/records/search", json=payload)
        return resp.get("records", []) if isinstance(resp, dict) else []

    # ── Metrics ───────────────────────────────────────────────────────────────

    def query_metrics(
        self,
        metric_category: str,
        object_type: str,
        object_ids: list[int],
        metric_specs: list[dict[str, Any]],
        from_time: int | None = None,
        until_time: int | None = None,
        cycle: str = "auto",
    ) -> dict[str, Any]:
        """
        Query ExtraHop wire-data metrics.

        Parameters
        ----------
        metric_category : str
            Metric category, e.g. ``"net"``, ``"http"``, ``"ssl"``.
        object_type : str
            ``"device"``, ``"network"``, ``"application"``, ``"device_group"``.
        object_ids : list of int
            IDs of the objects to query metrics for.
        metric_specs : list of dict
            List of ``{"name": "..."}`` metric specification dicts.
        cycle : str
            Time granularity: ``"auto"``, ``"1sec"``, ``"30sec"``, ``"5min"``, ``"1hr"``.
        """
        payload: dict[str, Any] = {
            "metric_category": metric_category,
            "object_type": object_type,
            "object_ids": object_ids,
            "metric_specs": metric_specs,
            "cycle": cycle,
        }
        if from_time is not None:
            payload["from"] = from_time
        if until_time is not None:
            payload["until"] = until_time
        resp = self.post("/api/v1/metrics", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Watchlists ────────────────────────────────────────────────────────────

    def list_watchlists(self) -> list[dict[str, Any]]:
        """List all device watchlists defined in ExtraHop."""
        resp = self.get("/api/v1/watchlists")
        return resp if isinstance(resp, list) else []

    def create_watchlist(
        self,
        name: str,
        description: str = "",
        device_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Create a device watchlist."""
        payload: dict[str, Any] = {"name": name}
        if description:
            payload["description"] = description
        if device_ids:
            payload["assignments"] = device_ids
        resp = self.post("/api/v1/watchlists", json=payload)
        return resp if isinstance(resp, dict) else {}

    def add_devices_to_watchlist(
        self, watchlist_id: int | str, device_ids: list[int]
    ) -> dict[str, Any]:
        """Add devices to an existing watchlist."""
        resp = self.post(
            f"/api/v1/watchlists/{watchlist_id}/devices",
            json={"assign": device_ids},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Appliance info & administration ──────────────────────────────────────

    def get_appliance_info(self) -> dict[str, Any]:
        """Retrieve ExtraHop appliance metadata, firmware version, and health."""
        resp = self.get("/api/v1/extrahop")
        return resp if isinstance(resp, dict) else {}

    def list_users(self) -> list[dict[str, Any]]:
        """List all user accounts on the ExtraHop appliance."""
        resp = self.get("/api/v1/users")
        return resp if isinstance(resp, list) else []

    def list_api_keys(self) -> list[dict[str, Any]]:
        """List API keys (excludes secret values)."""
        resp = self.get("/api/v1/apikeys")
        return resp if isinstance(resp, list) else []

    def get_audit_log(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Retrieve the ExtraHop audit log (admin actions, config changes)."""
        resp = self.get(
            "/api/v1/auditlog",
            params={"limit": limit, "offset": offset},
        )
        return resp if isinstance(resp, list) else []

    # ── Threat intelligence ───────────────────────────────────────────────────

    def bulk_threat_lookup(self, observables: list[str]) -> list[dict[str, Any]]:
        """
        Look up multiple threat observables in a single request.

        ``observables`` — list of IPs, domains, or URLs to check.
        Returns a list of threat match results, one per observable.
        """
        resp = self.post("/api/v1/threats/search", json={"observables": observables})
        return resp.get("results", []) if isinstance(resp, dict) else []

    def get_threat_collection(self, collection_id: str) -> dict[str, Any]:
        """Retrieve a configured ExtraHop threat intelligence collection."""
        resp = self.get(f"/api/v1/threatcollections/{collection_id}")
        return resp if isinstance(resp, dict) else {}

    def list_threat_collections(self) -> list[dict[str, Any]]:
        """List all configured threat intelligence collections."""
        resp = self.get("/api/v1/threatcollections")
        return resp if isinstance(resp, list) else []

    def _detection_to_stix(self, detection: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for detection to stix."""
        now = _now_ts()
        det_id = str(detection.get("id", ""))
        start_time = detection.get("start_time", now)
        update_time = detection.get("update_time", now)
        return {
            "type": "observed-data",
            "id": f"observed-data--{_uuid.uuid5(_STIX_NS, f'extrahop:{det_id}')}",
            "spec_version": "2.1",
            "created": start_time,
            "modified": update_time,
            "first_observed": start_time,
            "last_observed": update_time,
            "number_observed": 1,
            "object_refs": [],
            "x_extrahop": {
                "detection_id": det_id,
                "detection_type": detection.get("detection_type"),
                "category": detection.get("category"),
                "risk_score": detection.get("risk_score"),
                "status": detection.get("status"),
                "participants": detection.get("participants", []),
            },
        }

    def _record_to_stix(self, record: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for record to stix."""
        now = _now_ts()
        rec_id = str(record.get("id", ""))
        return {
            "type": "observed-data",
            "id": f"observed-data--{_uuid.uuid5(_STIX_NS, f'extrahop:rec:{rec_id}')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": record.get("timestamp", now),
            "last_observed": record.get("timestamp", now),
            "number_observed": 1,
            "object_refs": [],
            "x_extrahop_record": {
                "record_type": record.get("type"),
                "src_ip": record.get("src_addr"),
                "dst_ip": record.get("dst_addr"),
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "proto": record.get("proto"),
            },
        }
