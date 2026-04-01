"""
gnat.connectors.ossim.client
==================================

AlienVault OSSIM connector (Open Source SIEM).

Authentication
--------------
API key via ``X-USM-API-KEY`` header::

    [ossim]
    host       = https://ossim.corp.example.com
    api_key    = <ossim-api-key>
    verify_ssl = false

API keys are obtained from the OSSIM UI:
Configuration → Administration → Users → API.

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | OSSIM Resource                   |
+====================+==================================+
| observed-data      | alarms                           |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``/api/1.0/alarms``          — alarm listing
* ``/api/1.0/alarms/{id}``     — single alarm
* ``/api/1.0/events``          — raw event search
* ``/api/1.0/assets``          — asset inventory
* ``/api/1.0/system/info``     — health check

Notes
-----
* OSSIM 5.x REST API.  Community support ended 2024; widely deployed.
* Self-signed certs are common — ``verify_ssl = false`` is the default.
"""

from __future__ import annotations

import contextlib
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class OSSIMClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the AlienVault OSSIM 5.x REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://ossim.corp.example.com"``.
    api_key : str
        OSSIM API key.
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "alarms",
    }

    def __init__(self, host: str, api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the OSSIM API key header."""
        self._auth_headers["X-USM-API-KEY"] = self._api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the OSSIM system info endpoint."""
        self.get("/api/1.0/system/info")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single OSSIM alarm by UUID.

        Parameters
        ----------
        object_id : str
            OSSIM alarm UUID.
        """
        return self.get(f"/api/1.0/alarms/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """
        List OSSIM alarms.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:

            * ``status``   — ``"open"``, ``"closed"``, ``"unresolved"``
            * ``priority`` — 1–5
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page_items": page_size,
            "page": page,
        }
        if "status" in filters:
            params["status"] = filters.pop("status")
        if "priority" in filters:
            params["priority"] = filters.pop("priority")

        resp = self.get("/api/1.0/alarms", params=params)
        if isinstance(resp, dict):
            return resp.get("data", [])
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Update an OSSIM alarm status.

        Parameters
        ----------
        payload : dict
            Must include ``id`` and ``status`` (``"open"`` or ``"closed"``).
        """
        alarm_id = payload.get("id")
        if not alarm_id:
            raise GNATClientError("OSSIM upsert_object: 'id' is required in payload.")
        return self.put(
            f"/api/1.0/alarms/{alarm_id}", json={"status": payload.get("status", "open")}
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an OSSIM alarm by UUID."""
        self.delete(f"/api/1.0/alarms/{object_id}")

    # ── Domain-specific operations ────────────────────────────────────────

    def list_alarms(
        self,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        List OSSIM alarms with optional filters.

        Parameters
        ----------
        status : str, optional
            ``"open"``, ``"closed"``, or ``"unresolved"``.
        priority : int, optional
            Filter by priority 1–5.
        limit : int
            Max results.

        Returns
        -------
        list of dict
        """
        params: dict[str, Any] = {"page_items": limit}
        if status:
            params["status"] = status
        if priority is not None:
            params["priority"] = priority
        resp = self.get("/api/1.0/alarms", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_alarm(self, alarm_id: str) -> dict[str, Any]:
        """Retrieve a single OSSIM alarm by UUID."""
        return self.get(f"/api/1.0/alarms/{alarm_id}")

    def get_alarm_events(self, alarm_id: str) -> list[dict[str, Any]]:
        """Get raw events associated with an alarm."""
        resp = self.get(f"/api/1.0/alarms/{alarm_id}/events")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def close_alarm(self, alarm_id: str) -> dict[str, Any]:
        """Close an OSSIM alarm."""
        return self.put(f"/api/1.0/alarms/{alarm_id}", json={"status": "closed"})

    def list_assets(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the OSSIM asset inventory."""
        resp = self.get("/api/1.0/assets", params={"page_items": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a normalised OSSIM alarm to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            OSSIM alarm dict (raw or normalised).

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        alarm = self._normalise(native)
        now = _now_ts()
        ts = alarm.get("timestamp") or now

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (alarm.get("src_ip"), alarm.get("dst_ip")):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append(
                        {
                            "type": "ipv4-addr",
                            "id": ip_id,
                            "spec_version": "2.1",
                            "value": ip,
                        }
                    )
                refs.append(ip_id)

        src_ip = alarm.get("src_ip")
        dst_ip = alarm.get("dst_ip")
        src_p = alarm.get("src_port")
        dst_p = alarm.get("dst_port")
        if src_ip and dst_ip and (src_p or dst_p):
            key = f"{src_ip}:{src_p}-{dst_ip}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
                    "protocols": [str(alarm.get("protocol", "tcp")).lower()],
                }
                if src_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_port"] = int(src_p)
                if dst_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_port"] = int(dst_p)
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        obs: dict[str, Any] = {
            "type": "observed-data",
            "id": obs_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": max(1, alarm.get("event_count", 1)),
            "object_refs": refs,
            "x_ossim_alarm": {
                "alarm_id": alarm.get("id"),
                "name": alarm.get("name"),
                "priority": alarm.get("priority"),
                "severity": alarm.get("severity"),
                "status": alarm.get("status"),
                "sensor": alarm.get("sensor"),
            },
        }
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX observed-data to an OSSIM alarm update dict.

        Returns a payload for ``upsert_object()``.
        """
        ossim = stix_dict.get("x_ossim_alarm", {})
        return {
            "id": ossim.get("alarm_id", ""),
            "status": ossim.get("status", "open"),
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    @staticmethod
    def _normalise(alarm: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw OSSIM alarm dict."""
        prio = int(alarm.get("priority", 1))
        sev_map = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4}
        return {
            "id": alarm.get("uuid") or alarm.get("id"),
            "timestamp": alarm.get("timestamp"),
            "name": alarm.get("rule_name") or alarm.get("name"),
            "priority": prio,
            "severity": sev_map.get(prio, 1),
            "status": alarm.get("status"),
            "src_ip": alarm.get("src_ip"),
            "dst_ip": alarm.get("dst_ip"),
            "src_port": alarm.get("src_port"),
            "dst_port": alarm.get("dst_port"),
            "protocol": alarm.get("protocol"),
            "sensor": alarm.get("sensor"),
            "event_count": alarm.get("event_count", 0),
        }
