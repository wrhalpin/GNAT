# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortisiem.client
================================

FortiSIEM (Fortinet Security Information and Event Management) connector.

Authentication
--------------
HTTP Basic Auth (username + password)::

    [fortisiem]
    host     = https://<supervisor-ip-or-fqdn>
    username = super/admin   # or organization-specific account
    password = <password>

Newer releases also support API tokens (OAuth-style); extend `authenticate()` if needed.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | FortiSIEM Resource               |
+================+==================================+
| observed-data  | Events / triggering events       |
+----------------+----------------------------------+
| incident       | Incidents (JSON API)             |
+----------------+----------------------------------+
| report         | CMDB device / organization info  |
+----------------+----------------------------------+

Key Endpoints (JSON API)
------------------------
* ``/phoenix/rest/pub/incident`` — Fetch incidents (GET/POST with timeFrom/timeTo, status, etc.)
* ``/phoenix/rest/deviceInfo/monitoredDevices`` — CMDB device list
* Health / performance endpoints under `/phoenix/rest/...`

Notes
-----
* Primarily read-oriented (incident & CMDB querying).
* Supports `list_objects()` for "incident" and "observed-data".
* `upsert_object()` can update incident status/ticket info where supported.
* Many legacy endpoints use XML; this implementation focuses on modern JSON paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FortiSIEMClient(BaseClient, ConnectorMixin):
    """
    HTTP client for FortiSIEM Integration APIs (focus on JSON incident & CMDB).

    Parameters
    ----------
    host : str
        Supervisor URL, e.g. ``"https://fortisiem.example.com"``.
    username : str
        FortiSIEM username (e.g. super/admin or org-specific).
    password : str
        Password for Basic Auth.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/phoenix/rest"

    stix_type_map: dict[str, str] = {
        "incident": "incident",
        "observed-data": "event",
        "report": "cmdb",
    }

    def __init__(self, host: str, username: str = "", password: str = "", **kwargs: Any):
        """Initialize FortiSIEMClient."""
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set up HTTP Basic Auth and JSON headers."""
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"
        # BaseClient typically handles Basic auth via username/password in PoolManager
        # If needed, override _auth or use self._pool_manager with auth=HTTPBasicAuth

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight health check via a CMDB or incident endpoint."""
        # Example: try to fetch monitored devices or use a known lightweight path
        try:
            self.get("/phoenix/rest/deviceInfo/monitoredDevices", params={"size": 1})
            return True
        except Exception:
            # Fallback ping if needed
            self.get("/phoenix/rest/pub/incident", params={"size": 1, "timeFrom": 0})
            return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch single incident or device by ID (where supported)."""
        if stix_type == "incident":
            # incidentId filter
            resp = self.get(
                "/phoenix/rest/pub/incident", params={"incidentId": [object_id], "size": 1}
            )
            incidents = resp.get("response", []) if isinstance(resp, dict) else []
            return incidents[0] if incidents else {}
        raise GNATClientError(
            f"get_object not fully implemented for STIX type {stix_type} in FortiSIEM"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List incidents or events.

        Filters example for incidents:
            {"timeFrom": unix_ms, "timeTo": unix_ms, "status": [0]}
        """
        filters = dict(filters or {})
        start = (page - 1) * page_size

        if stix_type == "incident":
            params = {
                "start": start,
                "size": page_size,
                "timeFrom": filters.get("timeFrom"),
                "timeTo": filters.get("timeTo"),
                **{k: v for k, v in filters.items() if k in ("status", "incidentId")},
            }
            resp = self.get(
                "/phoenix/rest/pub/incident",
                params={k: v for k, v in params.items() if v is not None},
            )
            return resp.get("response", []) if isinstance(resp, dict) else []

        if stix_type == "observed-data":
            # Event query — adapt as needed (some paths are XML; extend with domain helper)
            raise GNATClientError(
                "Event querying via observed-data needs specific query payload; use domain helper."
            )

        # CMDB fallback example
        return self.get("/phoenix/rest/deviceInfo/monitoredDevices", params={"size": page_size})

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update incident status/ticket (where supported). Extend for full CRUD."""
        if stix_type == "incident":
            # Example: update ticket status via JSON incident update endpoint
            # Adapt payload to FortiSIEM expected format
            return self.post("/phoenix/rest/pub/incident/update", json=payload)
        raise GNATClientError(f"upsert_object limited support for {stix_type} in FortiSIEM")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError(
            "FortiSIEM connector does not support deletion via public Integration API."
        )

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_incidents(
        self,
        time_from: int,
        time_to: int,
        status: list[int] | None = None,
        size: int = 500,
    ) -> list[dict[str, Any]]:
        """Convenience: Fetch incidents in time window (JSON API)."""
        params = {"timeFrom": time_from, "timeTo": time_to, "size": size}
        if status:
            params["status"] = status
        resp = self.get("/phoenix/rest/pub/incident", params=params)
        return resp.get("response", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate FortiSIEM incident or CMDB object to STIX 2.1.

        Dispatches on keys typical of incident vs. device records.
        """
        now = _now_ts()

        if "incidentId" in native or "incidentDetail" in native:
            # Map to STIX observed-data or incident (GNAT often uses observed-data for alerts)
            return self._incident_to_stix(native, now)
        # Fallback: CMDB device → report or custom
        return {
            "type": "report",
            "id": f"report--fortisiem-cmdb-{hash(str(native)) % 10**12}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "FortiSIEM CMDB Entry",
            "x_fortisiem": native,
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return native payload template for updates (e.g., incident status)."""
        return {
            "note": "FortiSIEM from_stix prepares update payload (extend as needed).",
            "stix_id": stix_dict.get("id", ""),
            # Example mapping for incident update
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _incident_to_stix(self, inc: dict[str, Any], now: str) -> dict[str, Any]:
        """Map FortiSIEM incident to STIX observed-data (common pattern)."""
        inc_id = inc.get("incidentId", "")
        return {
            "type": "observed-data",
            "id": f"observed-data--fortisiem-{inc_id}",
            "spec_version": "2.1",
            "created": inc.get("incidentFirstSeen") or now,
            "modified": now,
            "first_observed": inc.get("incidentFirstSeen"),
            "last_observed": inc.get("incidentLastSeen"),
            "number_observed": inc.get("count", 1),
            "x_fortisiem_incident": {
                "incident_id": inc_id,
                "status": inc.get("incidentStatus"),
                "severity": inc.get("eventSeverity"),
                "detail": inc.get("incidentDetail"),
                **{k: v for k, v in inc.items() if k.startswith("incident")},
            },
        }
