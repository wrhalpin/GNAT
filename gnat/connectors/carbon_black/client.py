"""
gnat.connectors.carbon_black.client
=======================================

VMware Carbon Black Cloud connector.

Carbon Black Cloud (CBC) is an endpoint protection platform combining
next-generation antivirus (NGAV), EDR, behavioral analytics, and managed
threat hunting. It replaces the legacy Carbon Black Response (CB Response)
and CB Defense products.

Authentication
--------------
Custom API token passed as a composite header::

    [carbon_black]
    host          = https://defense.conferdeploy.net
    org_key       = <ORG_KEY>
    api_key       = <API_KEY>
    connector_id  = <CONNECTOR_ID>
    auth_type     = api_key

The ``X-Auth-Token`` header value is: ``<api_key>/<connector_id>``

For older CB Response on-prem deployments, set ``legacy_mode = true``
and provide only ``api_token``.

STIX Type Mapping
-----------------
+----------------+-------------------------------------------+
| STIX Type      | CBC Resource                              |
+================+===========================================+
| indicator      | alerts (behavioral detections / watchlist)|
+----------------+-------------------------------------------+
| malware        | processes (process analysis)              |
+----------------+-------------------------------------------+
| vulnerability  | devices (endpoint posture)                |
+----------------+-------------------------------------------+

Key Endpoints
-------------
* POST /appservices/v6/orgs/{org_key}/alerts/search       — Search alerts
* GET  /appservices/v6/orgs/{org_key}/alerts/{alert_id}  — Single alert
* POST /appservices/v6/orgs/{org_key}/alerts/dismiss_threat — Dismiss
* GET  /appservices/v6/orgs/{org_key}/devices/           — Device list
* POST /api/investigate/v2/orgs/{org_key}/processes/search_jobs — Process search
* GET  /threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists — Watchlists
* POST /threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists — Create watchlist

References
----------
https://developer.carbonblack.com/reference/carbon-black-cloud/
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e4f5a6b7-c8d9-0123-defa-123456789012")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CarbonBlackClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the VMware Carbon Black Cloud REST API.

    Parameters
    ----------
    host : str
        CBC console URL (e.g. ``https://defense.conferdeploy.net``).
    org_key : str
        Organization key from the CBC console.
    api_key : str
        API key generated in the CBC console.
    connector_id : str
        Connector/API ID that accompanies the ``api_key``.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":     "alerts",
        "malware":       "processes",
        "vulnerability": "devices",
    }

    def __init__(
        self,
        host: str = "https://defense.conferdeploy.net",
        org_key: str = "",
        api_key: str = "",
        connector_id: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._org_key = org_key
        self._api_key = api_key
        self._connector_id = connector_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the composite X-Auth-Token header."""
        token = (
            f"{self._api_key}/{self._connector_id}"
            if self._connector_id
            else self._api_key
        )
        self._auth_headers["X-Auth-Token"] = token
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the device list endpoint for the org."""
        self.get(f"/appservices/v6/orgs/{self._org_key}/devices/",
                 params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch a single alert or device by ID."""
        if stix_type == "indicator":
            resp = self.get(
                f"/appservices/v6/orgs/{self._org_key}/alerts/{object_id}"
            )
            return resp if isinstance(resp, dict) else {}

        if stix_type == "vulnerability":
            resp = self.get(
                f"/appservices/v6/orgs/{self._org_key}/devices/{object_id}"
            )
            return resp if isinstance(resp, dict) else {}

        if stix_type == "malware":
            # Process lookup requires search job; return minimal info
            resp = self.post(
                f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs",
                json={"query": f"process_guid:{object_id}", "rows": 1},
            )
            job_id = resp.get("job_id", "") if isinstance(resp, dict) else ""
            if job_id:
                results = self.get(
                    f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs/{job_id}/results",
                    params={"rows": 1},
                )
                items = results.get("results", []) if isinstance(results, dict) else []
                return items[0] if items else {}
            return {}

        raise GNATClientError(f"Unsupported STIX type for Carbon Black: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """List CBC alerts, devices, or processes."""
        f = filters or {}
        start = (page - 1) * page_size

        if stix_type == "indicator":
            criteria: Dict[str, Any] = {}
            if "minimum_severity" in f:
                criteria["minimum_severity"] = f["minimum_severity"]
            if "device_os" in f:
                criteria["device_os"] = [f["device_os"]]
            if "type" in f:
                criteria["type"] = [f["type"]]
            body: Dict[str, Any] = {
                "criteria": criteria,
                "rows": page_size,
                "start": start,
                "sort": [{"field": "backend_update_timestamp", "order": "DESC"}],
            }
            resp = self.post(
                f"/appservices/v6/orgs/{self._org_key}/alerts/search", json=body
            )
            return resp.get("results", []) if isinstance(resp, dict) else []

        if stix_type == "vulnerability":
            params: Dict[str, Any] = {"rows": page_size, "start": start}
            if "os" in f:
                params["os"] = f["os"]
            if "status" in f:
                params["status"] = f["status"]
            resp = self.get(
                f"/appservices/v6/orgs/{self._org_key}/devices/", params=params
            )
            return resp.get("results", []) if isinstance(resp, dict) else []

        if stix_type == "malware":
            query = f.get("query", "*")
            resp = self.post(
                f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs",
                json={"query": query, "rows": page_size, "start": start},
            )
            job_id = resp.get("job_id", "") if isinstance(resp, dict) else ""
            if job_id:
                results = self.get(
                    f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs/{job_id}/results",
                    params={"rows": page_size, "start": start},
                )
                return results.get("results", []) if isinstance(results, dict) else []
            return []

        raise GNATClientError(f"Unsupported STIX type for Carbon Black: {stix_type}")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dismiss an alert or create a watchlist entry."""
        if stix_type == "indicator":
            alert_id = payload.get("id", payload.get("alert_id", ""))
            reason = payload.get("reason", "Dismissed via GNAT")
            resp = self.post(
                f"/appservices/v6/orgs/{self._org_key}/alerts/dismiss_threat",
                json={"threat_id": alert_id, "reason": reason},
            )
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"Carbon Black: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Dismiss a CBC alert (no hard delete for alerts/processes)."""
        if stix_type == "indicator":
            self.post(
                f"/appservices/v6/orgs/{self._org_key}/alerts/dismiss_threat",
                json={"threat_id": object_id, "reason": "Dismissed via GNAT"},
            )
            return
        raise GNATClientError(
            f"Carbon Black: delete not supported for STIX type '{stix_type}'"
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_watchlists(self) -> List[Dict[str, Any]]:
        """Return all watchlists for the organization."""
        resp = self.get(
            f"/threathunter/watchlistmgr/v3/orgs/{self._org_key}/watchlists"
        )
        return resp.get("results", []) if isinstance(resp, dict) else []

    def create_watchlist(self, name: str, description: str = "",
                         tags_enabled: bool = True) -> Dict[str, Any]:
        """Create a new CBC watchlist."""
        resp = self.post(
            f"/threathunter/watchlistmgr/v3/orgs/{self._org_key}/watchlists",
            json={
                "name": name,
                "description": description,
                "tags_enabled": tags_enabled,
                "alerts_enabled": True,
            },
        )
        return resp if isinstance(resp, dict) else {}

    def get_devices(
        self,
        os: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve managed endpoints from CBC."""
        params: Dict[str, Any] = {"rows": limit}
        if os:
            params["os"] = os
        if status:
            params["status"] = status
        resp = self.get(
            f"/appservices/v6/orgs/{self._org_key}/devices/", params=params
        )
        return resp.get("results", []) if isinstance(resp, dict) else []

    def quarantine_device(self, device_id: str) -> Dict[str, Any]:
        """Toggle quarantine on a CBC-managed device."""
        resp = self.post(
            f"/appservices/v6/orgs/{self._org_key}/device_actions",
            json={
                "action_type": "QUARANTINE",
                "device_id": [device_id],
                "options": {"toggle": "ON"},
            },
        )
        return resp if isinstance(resp, dict) else {}

    def search_processes(
        self,
        query: str = "*",
        rows: int = 100,
        start: int = 0,
    ) -> List[Dict[str, Any]]:
        """Submit a process-level threat hunt query."""
        resp = self.post(
            f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs",
            json={"query": query, "rows": rows, "start": start},
        )
        job_id = resp.get("job_id", "") if isinstance(resp, dict) else ""
        if job_id:
            results = self.get(
                f"/api/investigate/v2/orgs/{self._org_key}/processes/search_jobs/{job_id}/results",
                params={"rows": rows, "start": start},
            )
            return results.get("results", []) if isinstance(results, dict) else []
        return []

    def get_observations(
        self,
        alert_id: str,
        rows: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve observations associated with a specific CBC alert."""
        resp = self.post(
            f"/api/investigate/v2/orgs/{self._org_key}/observations/search_jobs",
            json={"criteria": {"alert_id": [alert_id]}, "rows": rows},
        )
        job_id = resp.get("job_id", "") if isinstance(resp, dict) else ""
        if job_id:
            results = self.get(
                f"/api/investigate/v2/orgs/{self._org_key}/observations/search_jobs/{job_id}/results",
                params={"rows": rows},
            )
            return results.get("results", []) if isinstance(results, dict) else []
        return []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a CBC alert, device, or process to STIX."""
        if "type" in native and native.get("type") in (
            "CB_ANALYTICS", "WATCHLIST", "DEVICE_CONTROL", "INTRUSION_DETECTION_SYSTEM"
        ):
            return self._alert_to_stix(native)
        if "device_os" in native or "sensor_version" in native:
            return self._device_to_stix(native)
        if "process_guid" in native or "process_name" in native:
            return self._process_to_stix(native)
        # Default: treat as alert
        return self._alert_to_stix(native)

    def _alert_to_stix(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = str(alert.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"cbc-alert-{alert_id}"))
        severity_map = {10: 90, 9: 85, 8: 75, 7: 65, 6: 55, 5: 50,
                        4: 40, 3: 30, 2: 20, 1: 10}
        sev_int = int(alert.get("severity", 5))
        confidence = severity_map.get(sev_int, 50)

        ts = alert.get("backend_update_timestamp", alert.get("create_time", _now_ts()))

        # Build pattern from process hash or device IP
        sha256 = alert.get("process_sha256", "")
        device_ip = alert.get("device_internal_ip", alert.get("device_external_ip", ""))
        if sha256:
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        elif device_ip:
            pattern = f"[ipv4-addr:value = '{device_ip}']"
        else:
            pattern = f"[file:name = 'cbc-alert-{alert_id[:32]}']"

        sectors = alert.get("x_target_sectors", [])
        stix: Dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": alert.get("reason", f"CBC Alert {alert_id}"),
            "description": alert.get("reason_code", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": confidence,
            "x_source_platform": "carbon_black",
            "x_carbon_black": {
                "alert_id": alert_id,
                "severity": sev_int,
                "type": alert.get("type", ""),
                "threat_id": alert.get("threat_id", ""),
                "status": alert.get("status", ""),
                "device_id": alert.get("device_id", ""),
                "device_name": alert.get("device_name", ""),
                "device_os": alert.get("device_os", ""),
                "process_name": alert.get("process_name", ""),
                "process_sha256": sha256,
                "policy_name": alert.get("policy_name", ""),
            },
        }
        if isinstance(sectors, list) and sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def _device_to_stix(self, device: Dict[str, Any]) -> Dict[str, Any]:
        device_id = str(device.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"cbc-device-{device_id}"))
        ts = device.get("last_contact_time", _now_ts())
        ip = device.get("last_internal_ip_address", device.get("last_external_ip_address", ""))
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": device.get("name", f"CBC Device {device_id}"),
            "description": (
                f"Carbon Black managed endpoint — OS: {device.get('os', '')}, "
                f"Policy: {device.get('policy_name', '')}"
            )[:500],
            "created": ts,
            "modified": ts,
            "x_source_platform": "carbon_black",
            "x_carbon_black": {
                "device_id": device_id,
                "os": device.get("os", ""),
                "os_version": device.get("os_version", ""),
                "policy_name": device.get("policy_name", ""),
                "sensor_version": device.get("sensor_version", ""),
                "status": device.get("status", ""),
                "last_internal_ip": ip,
                "email": device.get("email", ""),
            },
        }

    def _process_to_stix(self, process: Dict[str, Any]) -> Dict[str, Any]:
        proc_guid = process.get("process_guid", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"cbc-process-{proc_guid}"))
        sha256 = process.get("process_sha256", "")
        ts = process.get("process_start_time", _now_ts())
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": process.get("process_name", f"CBC Process {proc_guid[:8]}"),
            "is_family": False,
            "created": ts,
            "modified": ts,
            "x_source_platform": "carbon_black",
            "x_carbon_black": {
                "process_guid": proc_guid,
                "process_name": process.get("process_name", ""),
                "process_sha256": sha256,
                "device_id": process.get("device_id", ""),
                "device_name": process.get("device_name", ""),
                "username": process.get("process_username", []),
                "reputation": process.get("process_reputation", ""),
            },
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Carbon Black-compatible fields from a STIX dict."""
        return {
            "threat_id": stix_dict.get("id", "").replace("indicator--", ""),
            "reason": stix_dict.get("name", ""),
            "stix_id": stix_dict.get("id", ""),
        }
