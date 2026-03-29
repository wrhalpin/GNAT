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

import json as _json
from typing import Any, Dict, List, Optional

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

    # Base path for all Table API calls
    _TABLE_BASE = "/api/now/table"
    _SI_TABLE   = "sn_si_incident"

    def __init__(
        self,
        host: str = "",
        username: str = "",
        password: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._api_key  = api_key

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject auth headers (Basic or Bearer token)."""
        if self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username:
            import base64
            creds = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["Accept"]       = "application/json"
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
            self.get("/api/now/table/sys_properties",
                     params={"sysparm_limit": "1", "sysparm_fields": "name"})
            return True
        except Exception as exc:
            raise GNATClientError(f"ServiceNow health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs: Any) -> Dict[str, Any]:
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
        resp  = self.get(f"{self._TABLE_BASE}/{table}/{object_id}")
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str = "observed-data",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
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
        table  = self._resolve(stix_type)
        params: Dict[str, Any] = {
            "sysparm_limit":  limit,
            "sysparm_offset": offset,
        }
        if query:
            params["sysparm_query"] = query
        resp = self.get(f"{self._TABLE_BASE}/{table}", params=params)
        return resp.get("result", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: Dict[str, Any],
        sys_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
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

    def to_stix(self, native_object: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a ServiceNow security incident record to STIX ``observed-data``.

        Parameters
        ----------
        native_object : dict
            ServiceNow ``sn_si_incident`` record dict (``result`` payload).
        """
        sys_id      = native_object.get("sys_id", "")
        description = native_object.get("description", "")
        short_desc  = native_object.get("short_description", "")
        opened_at   = native_object.get("opened_at", "")
        return {
            "type":              "observed-data",
            "id":                f"observed-data--{sys_id}",
            "created":           opened_at,
            "modified":          native_object.get("sys_updated_on", opened_at),
            "first_observed":    opened_at,
            "last_observed":     opened_at,
            "number_observed":   1,
            "object_refs":       [],
            "name":              short_desc,
            "description":       description,
            "x_sn_sys_id":       sys_id,
            "x_sn_state":        native_object.get("state", ""),
            "x_sn_priority":     native_object.get("priority", ""),
            "x_sn_category":     native_object.get("category", ""),
            "x_sn_assigned_to":  native_object.get("assigned_to", {}).get("value", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX object to a ServiceNow security incident payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 SDO (any type; ``observed-data`` maps most cleanly).
        """
        return self._stix_to_sn(stix_dict)

    # ── Incident linking ──────────────────────────────────────────────────

    def annotate_incident(
        self,
        incident_sys_id: str,
        stix_obj: Dict[str, Any],
    ) -> Dict[str, Any]:
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
        stix_id   = stix_obj.get("id", "")
        name      = stix_obj.get("name", stix_obj.get("description", stix_id))
        note = (
            f"[GNAT] Linked STIX object\n"
            f"Type: {stix_type}\n"
            f"ID: {stix_id}\n"
            f"Name/Value: {name}"
        )
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
            "observed-data":   "sn_si_incident",
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
    def _stix_to_sn(stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Derive a ServiceNow field payload from a STIX SDO."""
        name = stix_dict.get("name", stix_dict.get("id", ""))
        desc = stix_dict.get("description", "")
        return {
            "short_description": name[:160] if name else "",
            "description":       desc,
            "category":          "threat-intelligence",
            "work_notes":        f"[GNAT] Ingested from STIX {stix_dict.get('type', 'unknown')}",
        }
