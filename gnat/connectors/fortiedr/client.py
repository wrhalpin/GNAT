"""
gnat.connectors.fortiedr.client
===============================

FortiEDR (Fortinet Endpoint Detection and Response) connector.

Authentication
--------------
HTTP Basic Auth with a user that has the **Rest API** role enabled::

    [fortiedr]
    host     = https://<fortiedr-central-manager>
    username = <api-user>
    password = <password>

Notes on setup:
- In FortiEDR Console: Administration → Users → Add/Edit user → Enable "Rest API" role.
- Some versions support X-Auth-Token after initial auth (extend `authenticate()` if needed).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | FortiEDR Resource                |
+================+==================================+
| observed-data  | Security events / incidents      |
+----------------+----------------------------------+
| report         | Collectors / endpoint inventory  |
+----------------+----------------------------------+
| indicator      | IOCs / processes / files         |
+----------------+----------------------------------+

Key Endpoints
-------------
* ``/rest/incidents`` or similar — incident/event queries (exact paths vary by version)
* Collectors, forensics (file/memory retrieval), playbook actions
* Use `/rest-ui` suffix on your FortiEDR URL for additional UI-exposed endpoints during exploration

Notes
-----
* Primarily read-oriented with some write capabilities (isolate collector, trigger actions).
* `list_objects()` dispatches by STIX type with domain-specific helpers.
* `to_stix()` maps events to `observed-data` with rich `x_fortiedr` extension.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FortiEDRClient(BaseClient, ConnectorMixin):
    """
    HTTP client for FortiEDR REST API (focus on incidents, collectors, events).

    Parameters
    ----------
    host : str
        Central Manager URL, e.g. ``"https://fortiedr.example.com"``.
    username : str
        Username with Rest API role.
    password : str
        Password for Basic Auth.
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "event",
        "incident": "incident",
        "report": "collector",
        "indicator": "ioc",
    }

    def __init__(self, host: str, username: str = "", password: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set up HTTP Basic Auth and JSON headers for FortiEDR."""
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"
        # BaseClient typically injects Basic Auth via username/password

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight health check — attempt to fetch collectors or incidents summary."""
        try:
            # Common lightweight endpoint; adjust based on your version
            self.get("/rest/collectors", params={"limit": 1})
            return True
        except Exception:
            # Fallback
            self.get("/rest/incidents", params={"limit": 1})
            return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch single object by ID (incident, collector, etc.)."""
        if stix_type in ("incident", "observed-data"):
            # Adjust endpoint based on actual FortiEDR paths
            resp = self.get(f"/rest/incidents/{object_id}")
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(f"get_object support limited for {stix_type} in FortiEDR")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List events/incidents or collectors.

        Common filters: time range, severity, status, collector group, etc.
        """
        filters = dict(filters or {})
        limit = page_size

        if stix_type in ("observed-data", "incident"):
            params = {
                "limit": limit,
                "offset": (page - 1) * limit,
                **{k: v for k, v in filters.items() if k in ("from", "to", "severity", "status")},
            }
            resp = self.get(
                "/rest/incidents", params={k: v for k, v in params.items() if v is not None}
            )
            return resp.get("data", []) if isinstance(resp, dict) else []

        if stix_type == "report":  # Collectors / inventory
            params = {"limit": limit}
            resp = self.get("/rest/collectors", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"list_objects not implemented for STIX type {stix_type} in FortiEDR")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Limited write support (e.g., update incident status or trigger playbook action)."""
        if stix_type == "incident":
            # Example: update incident or trigger action
            return self.post(
                "/rest/incidents/update", json=payload
            )  # placeholder — adapt to real endpoint
        raise GNATClientError(f"upsert_object limited for {stix_type} in FortiEDR")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("FortiEDR connector does not support object deletion via public API.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_collectors(self, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        """Fetch endpoint collectors (inventory)."""
        params = {"limit": limit, **filters}
        resp = self.get("/rest/collectors", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_incident_details(self, incident_id: str) -> dict[str, Any]:
        """Fetch detailed incident/event information."""
        return self.get(f"/rest/incidents/{incident_id}")

    # Add more helpers as you explore: isolate_collector, retrieve_file, trigger_playbook, etc.

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate FortiEDR incident/event or collector to STIX 2.1.

        Dispatches based on presence of typical keys (e.g., incidentId vs. collectorId).
        """
        now = _now_ts()

        if "incidentId" in native or "eventId" in native or "severity" in native:
            return self._incident_to_stix(native, now)
        # Fallback for collectors/endpoints
        return self._collector_to_stix(native, now)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Prepare payload for updates/actions (e.g., isolate device)."""
        return {
            "note": "FortiEDR from_stix prepares action/update payload.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _incident_to_stix(self, event: dict[str, Any], now: str) -> dict[str, Any]:
        """Map FortiEDR security event/incident to STIX observed-data."""
        event_id = event.get("incidentId") or event.get("eventId") or str(hash(str(event)))
        return {
            "type": "observed-data",
            "id": f"observed-data--fortiedr-{event_id}",
            "spec_version": "2.1",
            "created": event.get("firstSeen") or now,
            "modified": now,
            "first_observed": event.get("firstSeen"),
            "last_observed": event.get("lastSeen"),
            "number_observed": 1,
            "x_fortiedr": {
                "event_id": event_id,
                "severity": event.get("severity"),
                "classification": event.get("classification"),
                "collector_id": event.get("collectorId"),
                "process": event.get("processName"),
                "file": event.get("filePath"),
                "raw": event,  # full payload for reference
            },
        }

    def _collector_to_stix(self, collector: dict[str, Any], now: str) -> dict[str, Any]:
        """Map collector/endpoint to STIX report."""
        coll_id = collector.get("collectorId") or collector.get("id") or "unknown"
        return {
            "type": "report",
            "id": f"report--fortiedr-collector-{coll_id}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"FortiEDR Collector {coll_id}",
            "description": "Endpoint inventory from FortiEDR",
            "x_fortiedr_collector": collector,
        }
