"""
gnat.connectors.cortex_xdr.client
=====================================

Palo Alto Networks Cortex XDR / XSIAM connector.

Cortex XDR and XSIAM (eXtended Security Intelligence and Automation
Management) are Palo Alto Networks' detection, investigation, and response
platforms. Cortex XDR focuses on endpoint, network, and cloud telemetry
correlation; XSIAM extends this with SIEM-scale analytics and automation.

Authentication
--------------
API key pair (API Key ID + API Key) with HMAC-SHA256 request signing.
Each request includes three headers derived from the credentials::

    [cortex_xdr]
    host        = https://api-<tenant>.xdr.us.paloaltonetworks.com
    api_key_id  = <integer key ID>
    api_key     = <API key string>
    auth_type   = api_key

The Authorization header value is::

    <API_KEY_ID>/<nonce>/<timestamp>/<hash>

where ``hash = SHA256(api_key + nonce + timestamp)`` encoded as hex.

STIX Type Mapping
-----------------
+----------------+------------------------------------+
| STIX Type      | Cortex XDR Resource                |
+================+====================================+
| indicator      | alerts                             |
+----------------+------------------------------------+
| malware        | incidents                          |
+----------------+------------------------------------+
| threat-actor   | incidents                          |
+----------------+------------------------------------+
| vulnerability  | alerts (CVE-tagged)                |
+----------------+------------------------------------+

Key Endpoints (Public API v1)
-----------------------------
* POST /public_api/v1/alerts/get_alerts_multi_events
* POST /public_api/v1/incidents/get_incidents
* POST /public_api/v1/incidents/get_incident_extra_data
* POST /public_api/v1/endpoints/get_endpoints
* POST /public_api/v1/indicators/

References
----------
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-API-Reference
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b1c2d3e4-f5a6-7890-abcd-ef0123456789")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_auth_string(api_key_id: str, api_key: str) -> str:
    """Build the Cortex XDR Authorization header value.

    Format: ``<key_id>/<nonce>/<timestamp_ms>/<sha256_hash>``
    where the hash is SHA-256 of ``api_key + nonce + timestamp_ms``.
    """
    nonce = secrets.token_hex(16)
    ts_ms = str(int(time.time() * 1000))
    raw = f"{api_key}{nonce}{ts_ms}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"{api_key_id}/{nonce}/{ts_ms}/{digest}"


class CortexXDRClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Palo Alto Cortex XDR / XSIAM Public API.

    Parameters
    ----------
    host : str
        Base URL (e.g. ``https://api-<tenant>.xdr.us.paloaltonetworks.com``).
    api_key_id : str
        Numeric API key ID from the Cortex XDR console.
    api_key : str
        API key string.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":     "alerts",
        "malware":       "incidents",
        "threat-actor":  "incidents",
        "vulnerability": "alerts",
    }

    def __init__(
        self,
        host: str = "https://api.xdr.paloaltonetworks.com",
        api_key_id: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key_id = api_key_id
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject signed Authorization header for Cortex XDR."""
        auth_string = _build_auth_string(self._api_key_id, self._api_key)
        self._auth_headers["Authorization"] = auth_string
        self._auth_headers["x-xdr-auth-id"] = str(self._api_key_id)
        self._auth_headers["x-xdr-nonce"] = secrets.token_hex(16)
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the incidents endpoint with an empty filter."""
        self.post("/public_api/v1/incidents/get_incidents", json={
            "request_data": {"filters": [], "search_from": 0, "search_to": 1}
        })
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch a single alert or incident by ID."""
        if stix_type in ("indicator", "vulnerability"):
            resp = self.post("/public_api/v1/alerts/get_alerts_multi_events", json={
                "request_data": {
                    "filters": [{"field": "alert_id_list", "operator": "in",
                                 "value": [object_id]}],
                    "search_from": 0,
                    "search_to": 1,
                }
            })
            alerts = (resp.get("reply", {}).get("alerts", [])
                      if isinstance(resp, dict) else [])
            return alerts[0] if alerts else {}

        if stix_type in ("malware", "threat-actor"):
            resp = self.post("/public_api/v1/incidents/get_incidents", json={
                "request_data": {
                    "filters": [{"field": "incident_id_list", "operator": "in",
                                 "value": [object_id]}],
                    "search_from": 0,
                    "search_to": 1,
                }
            })
            incidents = (resp.get("reply", {}).get("incidents", [])
                         if isinstance(resp, dict) else [])
            return incidents[0] if incidents else {}

        raise GNATClientError(f"Unsupported STIX type for Cortex XDR: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """List alerts or incidents."""
        f = filters or {}
        search_from = (page - 1) * page_size
        search_to = search_from + page_size
        api_filters: List[Dict[str, Any]] = []
        if "severity" in f:
            api_filters.append({"field": "severity", "operator": "in",
                                 "value": [f["severity"]]})
        if "status" in f:
            api_filters.append({"field": "status", "operator": "in",
                                 "value": [f["status"]]})

        if stix_type in ("indicator", "vulnerability"):
            resp = self.post("/public_api/v1/alerts/get_alerts_multi_events", json={
                "request_data": {
                    "filters": api_filters,
                    "search_from": search_from,
                    "search_to": search_to,
                }
            })
            return (resp.get("reply", {}).get("alerts", [])
                    if isinstance(resp, dict) else [])

        if stix_type in ("malware", "threat-actor"):
            resp = self.post("/public_api/v1/incidents/get_incidents", json={
                "request_data": {
                    "filters": api_filters,
                    "search_from": search_from,
                    "search_to": search_to,
                }
            })
            return (resp.get("reply", {}).get("incidents", [])
                    if isinstance(resp, dict) else [])

        raise GNATClientError(f"Unsupported STIX type for Cortex XDR: {stix_type}")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update an incident status or severity."""
        if stix_type in ("malware", "threat-actor"):
            incident_id = payload.get("incident_id", payload.get("id", ""))
            body: Dict[str, Any] = {"request_data": {"incident_id": incident_id}}
            if "status" in payload:
                body["request_data"]["status"] = payload["status"]
            if "resolve_comment" in payload:
                body["request_data"]["resolve_comment"] = payload["resolve_comment"]
            resp = self.post("/public_api/v1/incidents/update_incident", json=body)
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"Cortex XDR: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Resolve an incident (Cortex XDR has no hard delete on alerts/incidents)."""
        if stix_type in ("malware", "threat-actor"):
            self.post("/public_api/v1/incidents/update_incident", json={
                "request_data": {
                    "incident_id": object_id,
                    "status": "resolved",
                }
            })
            return
        raise GNATClientError(
            f"Cortex XDR: delete not supported for STIX type '{stix_type}'"
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_endpoints(
        self,
        filters: Optional[List[Dict[str, Any]]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return a list of managed endpoints."""
        resp = self.post("/public_api/v1/endpoints/get_endpoints", json={
            "request_data": {
                "filters": filters or [],
                "search_from": 0,
                "search_to": limit,
            }
        })
        return (resp.get("reply", {}).get("endpoints", [])
                if isinstance(resp, dict) else [])

    def get_incident_extra_data(self, incident_id: str) -> Dict[str, Any]:
        """Retrieve detailed alert and artifact data for an incident."""
        resp = self.post("/public_api/v1/incidents/get_incident_extra_data", json={
            "request_data": {"incident_id": incident_id, "alerts_limit": 100}
        })
        return resp.get("reply", {}) if isinstance(resp, dict) else {}

    def update_alert(self, alert_id: str, status: str) -> Dict[str, Any]:
        """Update the status of a single alert."""
        resp = self.post("/public_api/v1/alerts/update_alerts", json={
            "request_data": {
                "alert_id_list": [alert_id],
                "update_data": {"status": status},
            }
        })
        return resp if isinstance(resp, dict) else {}

    def isolate_endpoint(self, endpoint_id: str) -> Dict[str, Any]:
        """Isolate a managed endpoint from the network."""
        resp = self.post("/public_api/v1/endpoints/isolate", json={
            "request_data": {"endpoint_id": endpoint_id}
        })
        return resp if isinstance(resp, dict) else {}

    def get_indicators(
        self,
        ioc_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve threat indicators (IOCs) from the XDR/XSIAM feed."""
        body: Dict[str, Any] = {
            "request_data": {"page_size": limit, "page_number": 0}
        }
        if ioc_type:
            body["request_data"]["type"] = ioc_type
        resp = self.post("/public_api/v1/indicators/", json=body)
        return (resp.get("reply", {}).get("indicators", [])
                if isinstance(resp, dict) else [])

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Cortex XDR alert or incident to STIX."""
        if "alert_id" in native or "detection_timestamp" in native:
            return self._alert_to_stix(native)
        return self._incident_to_stix(native)

    def _alert_to_stix(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = str(alert.get("alert_id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"xdr-alert-{alert_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        sev = str(alert.get("severity", "low")).lower()

        # Build STIX pattern from available IOC fields
        local_ip = alert.get("local_insert_ts", "") and alert.get("actor_process_image_path", "")
        remote_ip = alert.get("remote_ip", "")
        sha256 = alert.get("actor_process_image_sha256", "")
        if remote_ip:
            pattern = f"[ipv4-addr:value = '{remote_ip}']"
        elif sha256:
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        else:
            pattern = f"[file:name = 'xdr-alert-{alert_id[:32]}']"

        ts = alert.get("detection_timestamp", "")
        if isinstance(ts, int):
            ts = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        ts = ts or _now_ts()

        sectors = alert.get("x_target_sectors", [])
        stix: Dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": alert.get("name", f"XDR Alert {alert_id}"),
            "description": alert.get("description", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": severity_map.get(sev, 25),
            "x_source_platform": "cortex_xdr",
            "x_cortex_xdr": {
                "alert_id": alert_id,
                "severity": sev,
                "status": alert.get("status", ""),
                "category": alert.get("category", ""),
                "actor_process_image_name": alert.get("actor_process_image_name", ""),
                "host_name": alert.get("host_name", ""),
                "endpoint_id": alert.get("endpoint_id", ""),
            },
        }
        if isinstance(sectors, list) and sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def _incident_to_stix(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        inc_id = str(incident.get("incident_id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"xdr-incident-{inc_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        sev = str(incident.get("severity", "medium")).lower()
        ts = incident.get("creation_time", "")
        if isinstance(ts, int):
            ts = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        ts = ts or _now_ts()
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": incident.get("incident_name", f"XDR Incident {inc_id}"),
            "description": incident.get("description", "")[:500],
            "is_family": False,
            "created": ts,
            "modified": ts,
            "confidence": severity_map.get(sev, 50),
            "x_source_platform": "cortex_xdr",
            "x_cortex_xdr": {
                "incident_id": inc_id,
                "severity": sev,
                "status": incident.get("status", ""),
                "alert_count": incident.get("alert_count", 0),
                "assigned_user_mail": incident.get("assigned_user_mail", ""),
                "hosts": incident.get("hosts", []),
                "users": incident.get("users", []),
            },
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Cortex XDR-compatible fields from a STIX dict."""
        return {
            "name": stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "severity": "medium",
            "stix_id": stix_dict.get("id", ""),
        }
