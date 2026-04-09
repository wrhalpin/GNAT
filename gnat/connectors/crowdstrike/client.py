# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.crowdstrike.client
======================================

CrowdStrike Falcon Platform connector (OAuth2 client-credentials).

INI config::

    [crowdstrike]
    host          = https://api.crowdstrike.com
    client_id     = <CID>
    client_secret = <secret>
    auth_type     = oauth2
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class CrowdStrikeClient(BaseClient, ConnectorMixin):
    """HTTP client for the CrowdStrike Falcon REST API."""
    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/oauth2"
    COST_UNIT: int = 1



    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "malware": "detections",
        "vulnerability": "vulnerabilities",
    }

    def __init__(self, host: str, client_id: str = "", client_secret: str = "", **kwargs: Any):
        """Initialize CrowdStrikeClient."""
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret

    def authenticate(self) -> None:
        """Exchange client credentials for an OAuth2 Bearer token."""
        resp = self.post(
            "/oauth2/token",
            data={"client_id": self._client_id, "client_secret": self._client_secret},
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("CrowdStrike: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        self.get("/sensors/queries/installers/v1", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        resource = self.stix_type_map.get(stix_type, stix_type)
        resp = self.get(f"/indicators/entities/{resource}/v1", params={"ids": object_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        resource = self.stix_type_map.get(stix_type, stix_type)
        params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if filters:
            params["filter"] = " + ".join(f"{k}:'{v}'" for k, v in filters.items())
        resp = self.get(f"/indicators/queries/{resource}/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        resp = self.post("/indicators/entities/iocs/v1", json={"indicators": [payload]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        self.delete(f"/indicators/entities/iocs/v1?ids={object_id}")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert this object to STIX format."""
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{native.get('value', '')}']",
            "pattern_type": "stix",
            "created": native.get("created_timestamp", ""),
            "modified": native.get("modified_timestamp", ""),
            "indicator_types": [native.get("type", "unknown")],
        }
        # target_industries is present on adversary profile objects
        # (GET /intel/combined/adversaries/v1) but absent on IOC objects.
        industries = native.get("target_industries", [])
        if isinstance(industries, list) and industries:
            stix["x_target_sectors"] = industries
        return stix

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "type": "ipv4",
            "value": stix_dict.get("name", ""),
            "action": "detect",
            "severity": "medium",
        }

    # ── Detections ────────────────────────────────────────────────────────────────

    def list_detections(
        self,
        filter_fql: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List detection summaries via FQL filter."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter_fql:
            params["filter"] = filter_fql
        ids_resp = self.get("/detects/queries/detects/v1", params=params)
        ids = (ids_resp.get("resources", []) if isinstance(ids_resp, dict) else [])[:limit]
        if not ids:
            return []
        resp = self.post("/detects/entities/summaries/GET/v1", json={"ids": ids})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_detection(self, detection_id: str) -> dict[str, Any]:
        """Retrieve a single detection summary by ID."""
        resp = self.post("/detects/entities/summaries/GET/v1", json={"ids": [detection_id]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def update_detection(
        self,
        detection_id: str,
        status: str = "",
        assigned_to_uuid: str = "",
        comment: str = "",
    ) -> dict[str, Any]:
        """Update detection status, assignment, or add a comment."""
        payload: dict[str, Any] = {"ids": [detection_id]}
        if status:
            payload["status"] = status
        if assigned_to_uuid:
            payload["assigned_to_uuid"] = assigned_to_uuid
        if comment:
            payload["comment"] = comment
        return self.patch("/detects/entities/detects/v2", json=payload)

    # ── Incidents ─────────────────────────────────────────────────────────────────

    def list_incidents(
        self,
        filter_fql: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List incident summaries."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter_fql:
            params["filter"] = filter_fql
        ids_resp = self.get("/incidents/queries/incidents/v1", params=params)
        ids = (ids_resp.get("resources", []) if isinstance(ids_resp, dict) else [])[:limit]
        if not ids:
            return []
        resp = self.post("/incidents/entities/incidents/GET/v1", json={"ids": ids})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Retrieve a single incident by ID."""
        resp = self.post("/incidents/entities/incidents/GET/v1", json={"ids": [incident_id]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def update_incident(
        self,
        incident_id: str,
        status: Optional[int] = None,
        assigned_to: str = "",
        tags: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Update incident status or assignment."""
        action: dict[str, Any] = {"id": incident_id}
        if status is not None:
            action["status"] = status
        if assigned_to:
            action["assigned_to"] = assigned_to
        if tags is not None:
            action["tags"] = tags
        return self.post("/incidents/entities/incident-actions/v1", json={"action_parameters": [action]})

    def get_incident_behaviors(self, incident_id: str) -> list[dict[str, Any]]:
        """List behaviors (sub-events) associated with an incident."""
        resp = self.get("/incidents/queries/behaviors/v1", params={"filter": f"incident_id:'{incident_id}'"})
        ids = resp.get("resources", []) if isinstance(resp, dict) else []
        if not ids:
            return []
        detail = self.post("/incidents/entities/behaviors/GET/v1", json={"ids": ids})
        return detail.get("resources", []) if isinstance(detail, dict) else []

    # ── Hosts ─────────────────────────────────────────────────────────────────────

    def list_hosts(
        self,
        filter_fql: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List host device summaries."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter_fql:
            params["filter"] = filter_fql
        ids_resp = self.get("/devices/queries/devices/v1", params=params)
        ids = (ids_resp.get("resources", []) if isinstance(ids_resp, dict) else [])[:limit]
        if not ids:
            return []
        resp = self.post("/devices/entities/devices/GET/v2", json={"ids": ids})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_host(self, device_id: str) -> dict[str, Any]:
        """Retrieve a single host device summary."""
        resp = self.post("/devices/entities/devices/GET/v2", json={"ids": [device_id]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def contain_host(self, device_id: str) -> dict[str, Any]:
        """Network-contain a host (isolate from network)."""
        return self.post(
            "/devices/entities/devices-actions/v2",
            params={"action_name": "contain"},
            json={"ids": [device_id]},
        )

    def lift_containment(self, device_id: str) -> dict[str, Any]:
        """Lift network containment from a host."""
        return self.post(
            "/devices/entities/devices-actions/v2",
            params={"action_name": "lift_containment"},
            json={"ids": [device_id]},
        )

    def get_host_login_history(self, device_id: str) -> list[dict[str, Any]]:
        """Retrieve login history for a specific host."""
        resp = self.post("/devices/combined/devices/login-history/v1", json={"ids": [device_id]})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_host_network_addresses(self, device_id: str) -> list[dict[str, Any]]:
        """Retrieve network address history for a host."""
        resp = self.post("/devices/combined/devices/network-address-history/v1", json={"ids": [device_id]})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    # ── Threat Intelligence ───────────────────────────────────────────────────────

    def get_intel_actor(self, actor_id: str) -> dict[str, Any]:
        """Retrieve a Falcon Intelligence adversary/actor by ID or slug."""
        resp = self.get("/intel/entities/actors/v1", params={"ids": actor_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def list_intel_actors(
        self,
        query: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search Falcon Intelligence adversary profiles."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if query:
            params["q"] = query
        resp = self.get("/intel/combined/actors/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_intel_malware(self, malware_id: str) -> dict[str, Any]:
        """Retrieve a Falcon Intelligence malware family profile."""
        resp = self.get("/intel/entities/malware/v1", params={"ids": malware_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def list_intel_reports(
        self,
        query: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search Falcon Intelligence reports."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if query:
            params["q"] = query
        resp = self.get("/intel/combined/reports/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_intel_report(self, report_id: str) -> dict[str, Any]:
        """Retrieve a single Falcon Intelligence report by ID."""
        resp = self.get("/intel/entities/reports/v1", params={"ids": report_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def list_intel_indicators(
        self,
        filter_fql: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List Falcon Intelligence indicators (not custom IOCs)."""
        params: dict[str, Any] = {"limit": limit, "offset": offset, "include_deleted": False}
        if filter_fql:
            params["filter"] = filter_fql
        resp = self.get("/intel/combined/indicators/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    # ── Custom IOCs ───────────────────────────────────────────────────────────────

    def create_ioc(self, ioc_payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create a custom IOC.

        ``ioc_payload`` should follow the CrowdStrike IOC entity schema::

            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "action": "detect",
                "severity": "high",
                "description": "...",
                "platforms": ["windows"],
            }
        """
        resp = self.post("/iocs/entities/indicators/v1", json={"indicators": [ioc_payload]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def update_ioc(self, ioc_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an existing custom IOC by ID."""
        updates["id"] = ioc_id
        resp = self.patch("/iocs/entities/indicators/v1", json={"indicators": [updates]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def delete_ioc(self, ioc_id: str) -> dict[str, Any]:
        """Delete a custom IOC by ID."""
        return self.delete(f"/iocs/entities/indicators/v1?ids={ioc_id}")

    def list_iocs(
        self,
        filter_fql: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List custom IOCs with optional FQL filter."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter_fql:
            params["filter"] = filter_fql
        ids_resp = self.get("/iocs/queries/indicators/v1", params=params)
        ids = (ids_resp.get("resources", []) if isinstance(ids_resp, dict) else [])[:limit]
        if not ids:
            return []
        resp = self.get("/iocs/entities/indicators/v1", params={"ids": ids})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    # ── Real-Time Response (RTR) ──────────────────────────────────────────────────

    def init_rtr_session(self, device_id: str, queue_offline: bool = False) -> dict[str, Any]:
        """
        Initialise a Real-Time Response session with a host.

        Returns a session dict containing ``session_id``.
        """
        return self.post(
            "/real-time-response/entities/sessions/v1",
            json={"device_id": device_id, "queue_offline": queue_offline},
        )

    def execute_rtr_command(
        self,
        session_id: str,
        command_string: str,
        base_command: str = "runscript",
    ) -> dict[str, Any]:
        """
        Execute a command in an active RTR session.

        ``base_command`` options: ``ls``, ``cd``, ``pwd``, ``ps``,
        ``runscript``, ``get``, ``put``, ``reg query``, etc.
        """
        return self.post(
            "/real-time-response/entities/command/v1",
            json={
                "session_id": session_id,
                "base_command": base_command,
                "command_string": command_string,
            },
        )

    def delete_rtr_session(self, session_id: str) -> dict[str, Any]:
        """Delete an RTR session and release the connection."""
        return self.delete(f"/real-time-response/entities/sessions/v1?session_id={session_id}")

    # ── Vulnerabilities / Spotlight ───────────────────────────────────────────────

    def list_vulnerabilities(
        self,
        filter_fql: str = "",
        limit: int = 100,
        after: str = "",
    ) -> list[dict[str, Any]]:
        """List Spotlight vulnerability findings."""
        params: dict[str, Any] = {"limit": limit}
        if filter_fql:
            params["filter"] = filter_fql
        if after:
            params["after"] = after
        ids_resp = self.get("/spotlight/queries/vulnerabilities/v1", params=params)
        ids = (ids_resp.get("resources", []) if isinstance(ids_resp, dict) else [])[:limit]
        if not ids:
            return []
        resp = self.get("/spotlight/entities/vulnerabilities/v2", params={"ids": ids})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """Retrieve a single Spotlight vulnerability finding."""
        resp = self.get("/spotlight/entities/vulnerabilities/v2", params={"ids": vuln_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}
