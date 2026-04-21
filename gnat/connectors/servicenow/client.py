# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.servicenow.client
===================================
ServiceNow Security Incident (sn_si_incident) connector.

Authentication
--------------
Basic (username + password) or OAuth2 bearer token::

    [servicenow]
    host     = https://instance.service-now.com
    username = admin
    password = <password>
    ; OR
    api_key  = <bearer-token>
    auth_type = api_key

STIX Type Mapping
-----------------
+-------------------+-----------------------------------+
| STIX Type         | ServiceNow Table                  |
+===================+===================================+
| observed-data     | sn_si_incident                    |
+-------------------+-----------------------------------+
| course-of-action  | sn_si_incident (remediation note) |
+-------------------+-----------------------------------+

Incident Linking
----------------
Use :meth:`annotate_incident` to attach a STIX-derived work note to an
existing security incident::

    client.annotate_incident("a1b2c3d4...", stix_obj)

This calls ``PUT /api/now/table/sn_si_incident/{sys_id}`` with a ``work_notes``
field update, keeping full audit history.
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class ServiceNowClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ServiceNow Table API (sn_si_incident).

    Parameters
    ----------
    host : str
        ServiceNow instance base URL, e.g. ``"https://dev12345.service-now.com"``.
    username : str
        Basic-auth username (mutually exclusive with *api_key*).
    password : str
        Basic-auth password.
    api_key : str
        Bearer token (mutually exclusive with *username* / *password*).
    verify_ssl : bool
        TLS certificate verification.  Default ``True``.
    timeout : float
        Request timeout in seconds.  Default ``30``.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/now"

    # Base path for all Table API calls
    _TABLE_BASE = "/api/now/table"
    _SI_TABLE = "sn_si_incident"

    def __init__(
        self,
        host: str = "",
        username: str = "",
        password: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize ServiceNowClient."""
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._api_key = api_key

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject auth headers (Basic or Bearer token)."""
        if self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username:
            import base64

            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """
        Verify connectivity via the ServiceNow instance status endpoint.

        Returns
        -------
        bool
            ``True`` if the instance responds with HTTP 2xx.

        Raises
        ------
        GNATClientError
            On connection failure or non-2xx response.
        """
        try:
            self.get(
                "/api/now/table/sys_properties",
                params={"sysparm_limit": "1", "sysparm_fields": "name"},
            )
            return True
        except Exception as exc:
            raise GNATClientError(f"ServiceNow health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs: Any) -> dict[str, Any]:
        """
        Fetch a single security incident by ``sys_id``.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` (security incident) or ``"course-of-action"``.
        object_id : str
            ServiceNow ``sys_id`` (32-char hex string).
        """
        table = self._resolve(stix_type)
        resp = self.get(f"{self._TABLE_BASE}/{table}/{object_id}")
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str = "observed-data",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        List security incidents matching an optional sysparm_query string.

        Parameters
        ----------
        stix_type : str
            STIX type to list.  Default ``"observed-data"``.
        query : str
            ServiceNow encoded query (e.g. ``"state=1^priority=1"``).
        limit : int
            Maximum records to return.  Default 100.
        offset : int
            Pagination offset.  Default 0.
        """
        table = self._resolve(stix_type)
        params: dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }
        if query:
            params["sysparm_query"] = query
        resp = self.get(f"{self._TABLE_BASE}/{table}", params=params)
        return resp.get("result", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: dict[str, Any],
        sys_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create or update a security incident.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` → ``sn_si_incident``.
        payload : dict
            STIX object or pre-built ServiceNow field dict.
        sys_id : str, optional
            If provided, updates the existing record; otherwise creates new.
        """
        table = self._resolve(stix_type)
        sn_payload = self._stix_to_sn(payload)
        if sys_id:
            resp = self.put(f"{self._TABLE_BASE}/{table}/{sys_id}", json=sn_payload)
        else:
            resp = self.post(f"{self._TABLE_BASE}/{table}", json=sn_payload)
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str, **kwargs: Any) -> None:
        """Delete a security incident by ``sys_id``."""
        table = self._resolve(stix_type)
        self.delete(f"{self._TABLE_BASE}/{table}/{object_id}")

    def to_stix(self, native_object: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a ServiceNow security incident record to STIX ``observed-data``.

        Parameters
        ----------
        native_object : dict
            ServiceNow ``sn_si_incident`` record dict (``result`` payload).
        """
        sys_id = native_object.get("sys_id", "")
        description = native_object.get("description", "")
        short_desc = native_object.get("short_description", "")
        opened_at = native_object.get("opened_at", "")
        return {
            "type": "observed-data",
            "id": f"observed-data--{sys_id}",
            "created": opened_at,
            "modified": native_object.get("sys_updated_on", opened_at),
            "first_observed": opened_at,
            "last_observed": opened_at,
            "number_observed": 1,
            "object_refs": [],
            "name": short_desc,
            "description": description,
            "x_sn_sys_id": sys_id,
            "x_sn_state": native_object.get("state", ""),
            "x_sn_priority": native_object.get("priority", ""),
            "x_sn_category": native_object.get("category", ""),
            "x_sn_assigned_to": native_object.get("assigned_to", {}).get("value", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a STIX object to a ServiceNow security incident payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 SDO (any type; ``observed-data`` maps most cleanly).
        """
        return self._stix_to_sn(stix_dict)

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_incidents(
        self,
        state: str = "",
        priority: str = "",
        assigned_to: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List rows from the ``incident`` table, optionally filtered."""
        parts: list[str] = []
        if state:
            parts.append(f"state={state}")
        if priority:
            parts.append(f"priority={priority}")
        if assigned_to:
            parts.append(f"assigned_to={assigned_to}")
        params: dict[str, Any] = {"sysparm_limit": int(limit)}
        if parts:
            params["sysparm_query"] = "^".join(parts)
        resp = self.get(f"{self._TABLE_BASE}/incident", params=params)
        return _extract_sn_records(resp)

    def get_incident(self, sys_id: str) -> dict[str, Any]:
        """Fetch a single incident by sys_id."""
        resp = self.get(f"{self._TABLE_BASE}/incident/{sys_id}")
        return _extract_sn_record(resp)

    def create_incident(
        self,
        short_description: str,
        description: str = "",
        urgency: str = "2",
        impact: str = "2",
        category: str = "",
    ) -> dict[str, Any]:
        """Create a new incident row."""
        payload: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            "impact": impact,
        }
        if category:
            payload["category"] = category
        resp = self.post(f"{self._TABLE_BASE}/incident", json=payload)
        return _extract_sn_record(resp)

    def list_change_requests(self, state: str = "", limit: int = 100) -> list[dict[str, Any]]:
        """List rows from the ``change_request`` table."""
        params: dict[str, Any] = {"sysparm_limit": int(limit)}
        if state:
            params["sysparm_query"] = f"state={state}"
        resp = self.get(f"{self._TABLE_BASE}/change_request", params=params)
        return _extract_sn_records(resp)

    def create_change_request(
        self,
        short_description: str,
        description: str = "",
        assignment_group: str = "",
    ) -> dict[str, Any]:
        """Create a new change_request row."""
        payload: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
        }
        if assignment_group:
            payload["assignment_group"] = assignment_group
        resp = self.post(f"{self._TABLE_BASE}/change_request", json=payload)
        return _extract_sn_record(resp)

    def query_table(
        self,
        table: str,
        sysparm_query: str = "",
        sysparm_fields: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Generic table query for arbitrary ServiceNow tables."""
        params: dict[str, Any] = {"sysparm_limit": int(limit)}
        if sysparm_query:
            params["sysparm_query"] = sysparm_query
        if sysparm_fields:
            params["sysparm_fields"] = sysparm_fields
        resp = self.get(f"{self._TABLE_BASE}/{table}", params=params)
        return _extract_sn_records(resp)

    def get_cmdb_ci(self, sys_id: str) -> dict[str, Any]:
        """Fetch a CMDB configuration item (``cmdb_ci`` table) by sys_id."""
        resp = self.get(f"{self._TABLE_BASE}/cmdb_ci/{sys_id}")
        return _extract_sn_record(resp)

    def list_cmdb_ci_by_name(self, name: str, limit: int = 100) -> list[dict[str, Any]]:
        """Find CMDB configuration items by display name substring."""
        return self.query_table(
            "cmdb_ci",
            sysparm_query=f"nameLIKE{name}",
            limit=limit,
        )

    # ── Incident linking ──────────────────────────────────────────────────

    def annotate_incident(
        self,
        incident_sys_id: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Attach a STIX-derived work note to an existing security incident.

        Appends a structured work note containing the STIX object type, ID,
        and name (or description) to ``sn_si_incident.work_notes``.

        Parameters
        ----------
        incident_sys_id : str
            ServiceNow ``sys_id`` of the target security incident.
        stix_obj : dict
            STIX 2.1 SDO whose key fields are embedded in the work note.

        Returns
        -------
        dict
            ServiceNow ``result`` dict of the updated incident record.

        Raises
        ------
        GNATClientError
            If the incident does not exist or the update fails.
        """
        stix_type = stix_obj.get("type", "unknown")
        stix_id = stix_obj.get("id", "")
        name = stix_obj.get("name", stix_obj.get("description", stix_id))
        note = f"[GNAT] Linked STIX object\nType: {stix_type}\nID: {stix_id}\nName/Value: {name}"
        resp = self.put(
            f"{self._TABLE_BASE}/{self._SI_TABLE}/{incident_sys_id}",
            json={"work_notes": note},
        )
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve(stix_type: str) -> str:
        """Map a STIX type to a ServiceNow table name."""
        mapping = {
            "observed-data": "sn_si_incident",
            "course-of-action": "sn_si_incident",
        }
        table = mapping.get(stix_type)
        if not table:
            raise GNATClientError(
                f"ServiceNow: unsupported STIX type '{stix_type}'. "
                f"Supported: {sorted(mapping.keys())}"
            )
        return table

    @staticmethod
    def _stix_to_sn(stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Derive a ServiceNow field payload from a STIX SDO."""
        name = stix_dict.get("name", stix_dict.get("id", ""))
        desc = stix_dict.get("description", "")
        return {
            "short_description": name[:160] if name else "",
            "description": desc,
            "category": "threat-intelligence",
            "work_notes": f"[GNAT] Ingested from STIX {stix_dict.get('type', 'unknown')}",
        }


def _extract_sn_record(resp: Any) -> dict[str, Any]:
    """Pull a single record out of a ServiceNow Table API response."""
    if isinstance(resp, dict):
        result = resp.get("result")
        if isinstance(result, dict):
            return result
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return result[0]
        return resp
    return {}


def _extract_sn_records(resp: Any) -> list[dict[str, Any]]:
    """Pull a list of records out of a ServiceNow Table API response."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if isinstance(resp, dict):
        result = resp.get("result")
        if isinstance(result, list):
            return [r for r in result if isinstance(r, dict)]
        if isinstance(result, dict):
            return [result]
    return []
