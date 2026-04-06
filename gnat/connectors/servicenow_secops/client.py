"""
gnat.connectors.servicenow_secops.client
=========================================

ServiceNow Security Operations (SecOps) dedicated connector.

Covers the full ServiceNow SecOps module suite beyond the basic ITSM
connector, including Vulnerability Response, Threat Intelligence, and
Security Incident Response workflows.

Authentication
--------------
Basic auth (username + password) or OAuth2 Bearer token::

    [servicenow_secops]
    host     = https://instance.service-now.com
    username = admin
    password = <password>
    ; OR
    api_key  = <bearer-token>

STIX Type Mapping
-----------------
+--------------------+-------------------------------------------+
| STIX Type          | ServiceNow SecOps Table                   |
+====================+===========================================+
| observed-data      | sn_si_incident (Security Incidents)       |
+--------------------+-------------------------------------------+
| vulnerability      | sn_vr_vulnerable_item (Vuln Response)     |
+--------------------+-------------------------------------------+
| indicator          | sn_ti_observable (Threat Intelligence)    |
+--------------------+-------------------------------------------+
| course-of-action   | sn_si_task (Security Tasks / Remediations)|
+--------------------+-------------------------------------------+

Key SecOps Tables
-----------------
* ``sn_si_incident``        — Security Incident Response (SIR) incidents
* ``sn_si_task``            — Security tasks linked to SIR incidents
* ``sn_vr_vulnerable_item`` — Vulnerability Response items (VR module)
* ``sn_ti_observable``      — Threat Intelligence observables (TIARA)
* ``sn_ti_indicator``       — Threat Intelligence indicators (TIARA)
"""

from __future__ import annotations

import base64
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b8c9d0e1-f2a3-4567-1234-890123456789")

# ServiceNow SecOps table mapping
_TABLE_MAP: dict[str, str] = {
    "observed-data": "sn_si_incident",
    "vulnerability": "sn_vr_vulnerable_item",
    "indicator": "sn_ti_observable",
    "course-of-action": "sn_si_task",
}

_TABLE_BASE = "/api/now/table"


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ServiceNowSecOpsClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ServiceNow Security Operations (SecOps) module.

    Provides access to Security Incident Response (SIR), Vulnerability
    Response (VR), and Threat Intelligence (TIARA) modules via the
    ServiceNow Table API.

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
    """

    stix_type_map: dict[str, str] = _TABLE_MAP

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
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject auth headers (Basic or Bearer token)."""
        if self._api_key:
            self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username:
            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
        else:
            raise GNATClientError("ServiceNow SecOps: provide api_key or username + password")
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the security incidents table."""
        try:
            self.get(
                f"{_TABLE_BASE}/sn_si_incident",
                params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
            )
            return True
        except Exception as exc:
            raise GNATClientError(f"ServiceNow SecOps health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single SecOps record by ``sys_id``.

        Parameters
        ----------
        stix_type : str
            STIX type mapped to a SecOps table.
        object_id : str
            ServiceNow ``sys_id`` (32-char hex string).
        """
        table = self._resolve_table(stix_type)
        resp = self.get(f"{_TABLE_BASE}/{table}/{object_id}")
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str = "observed-data",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
        filters: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        List SecOps records with optional encoded query string.

        Parameters
        ----------
        stix_type : str
            STIX type to list (maps to a SecOps table).
        query : str
            ServiceNow encoded query (e.g. ``"state=1^priority=1"``).
        limit : int
            Maximum records to return.
        offset : int
            Pagination offset.
        filters : dict, optional
            Additional sysparm parameters.
        """
        table = self._resolve_table(stix_type)
        params: dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }
        if query:
            params["sysparm_query"] = query
        if filters:
            params.update(filters)
        resp = self.get(f"{_TABLE_BASE}/{table}", params=params)
        return resp.get("result", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: dict[str, Any],
        sys_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create or update a SecOps record.

        Parameters
        ----------
        stix_type : str
            STIX type mapped to a SecOps table.
        payload : dict
            Pre-built ServiceNow field dict or raw STIX SDO.
        sys_id : str, optional
            If provided, updates the existing record; otherwise creates new.
        """
        table = self._resolve_table(stix_type)
        sn_payload = self._to_sn_payload(stix_type, payload)
        if sys_id:
            resp = self.put(f"{_TABLE_BASE}/{table}/{sys_id}", json=sn_payload)
        else:
            resp = self.post(f"{_TABLE_BASE}/{table}", json=sn_payload)
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a SecOps record by ``sys_id``."""
        table = self._resolve_table(stix_type)
        self.delete(f"{_TABLE_BASE}/{table}/{object_id}")

    # ── Security Incident Response (SIR) helpers ─────────────────────────

    def create_security_incident(
        self,
        short_description: str,
        description: str = "",
        priority: str = "3",
        category: str = "threat-intelligence",
        work_notes: str = "",
    ) -> dict[str, Any]:
        """
        Create a new Security Incident Response (SIR) record.

        Parameters
        ----------
        short_description : str
            Brief summary of the incident (max 160 chars).
        description : str
            Full incident description.
        priority : str
            Incident priority: ``"1"`` (critical) – ``"4"`` (low).
        category : str
            Incident category.
        work_notes : str
            Initial work notes to attach.
        """
        payload: dict[str, Any] = {
            "short_description": short_description[:160],
            "description": description,
            "priority": priority,
            "category": category,
        }
        if work_notes:
            payload["work_notes"] = work_notes
        resp = self.post(f"{_TABLE_BASE}/sn_si_incident", json=payload)
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def annotate_incident(
        self,
        incident_sys_id: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Attach a STIX-derived work note to an existing security incident.

        Parameters
        ----------
        incident_sys_id : str
            ServiceNow ``sys_id`` of the target SIR incident.
        stix_obj : dict
            STIX 2.1 SDO whose key fields are embedded in the work note.
        """
        stix_type = stix_obj.get("type", "unknown")
        stix_id = stix_obj.get("id", "")
        name = stix_obj.get("name", stix_obj.get("description", stix_id))
        note = f"[GNAT] Linked STIX object\nType: {stix_type}\nID: {stix_id}\nName/Value: {name}"
        resp = self.put(
            f"{_TABLE_BASE}/sn_si_incident/{incident_sys_id}",
            json={"work_notes": note},
        )
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    # ── Investigation sub-API ────────────────────────────────────────────

    def get_incident_tasks(self, incident_sys_id: str) -> list[dict[str, Any]]:
        """
        Return security tasks linked to a SIR incident.

        Queries the ``sn_si_task`` table filtered by parent ``sys_id``.

        Parameters
        ----------
        incident_sys_id : str
            ServiceNow ``sys_id`` of the parent SIR incident.
        """
        resp = self.get(
            f"{_TABLE_BASE}/sn_si_task",
            params={
                "sysparm_query": f"parent={incident_sys_id}",
                "sysparm_limit": 200,
            },
        )
        return resp.get("result", []) if isinstance(resp, dict) else []

    def get_incident_observables(self, incident_sys_id: str) -> list[dict[str, Any]]:
        """
        Return threat intelligence observables linked to a SIR incident.

        Queries the ``sn_ti_observable`` table filtered by the incident
        reference field.

        Parameters
        ----------
        incident_sys_id : str
            ServiceNow ``sys_id`` of the parent SIR incident.
        """
        resp = self.get(
            f"{_TABLE_BASE}/sn_ti_observable",
            params={
                "sysparm_query": f"incident={incident_sys_id}",
                "sysparm_limit": 200,
            },
        )
        return resp.get("result", []) if isinstance(resp, dict) else []

    def search_indicators_by_value(self, value: str) -> list[dict[str, Any]]:
        """
        Search TIARA observables by value (IP, domain, hash, URL, etc.).

        Parameters
        ----------
        value : str
            Observable value to search for.
        """
        resp = self.get(
            f"{_TABLE_BASE}/sn_ti_observable",
            params={
                "sysparm_query": f"valueLIKE{value}",
                "sysparm_limit": 100,
            },
        )
        return resp.get("result", []) if isinstance(resp, dict) else []

    # ── Vulnerability Response (VR) helpers ──────────────────────────────

    def list_vulnerable_items(
        self,
        cve_id: str | None = None,
        state: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Vulnerability Response items, optionally filtered by CVE or state.

        Parameters
        ----------
        cve_id : str, optional
            Filter by CVE ID (e.g. ``"CVE-2021-44228"``).
        state : str, optional
            Lifecycle state filter (e.g. ``"open"``, ``"in_progress"``).
        limit : int
            Maximum records to return.
        """
        query_parts = []
        if cve_id:
            query_parts.append(f"vulnerability.cve={cve_id}")
        if state:
            query_parts.append(f"state={state}")
        query = "^".join(query_parts)
        params: dict[str, Any] = {"sysparm_limit": limit}
        if query:
            params["sysparm_query"] = query
        resp = self.get(f"{_TABLE_BASE}/sn_vr_vulnerable_item", params=params)
        return resp.get("result", []) if isinstance(resp, dict) else []

    # ── Threat Intelligence (TIARA) helpers ──────────────────────────────

    def create_observable(
        self,
        value: str,
        observable_type: str,
        description: str = "",
    ) -> dict[str, Any]:
        """
        Create a threat intelligence observable in ServiceNow TIARA.

        Parameters
        ----------
        value : str
            Observable value (IP, domain, hash, URL, etc.).
        observable_type : str
            ServiceNow observable type label (e.g. ``"IP Address"``, ``"Domain"``).
        description : str
            Human-readable description.
        """
        payload: dict[str, Any] = {
            "value": value,
            "type": observable_type,
            "description": description,
        }
        resp = self.post(f"{_TABLE_BASE}/sn_ti_observable", json=payload)
        return resp.get("result", {}) if isinstance(resp, dict) else {}

    def list_observables(
        self,
        observable_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List threat intelligence observables from ServiceNow TIARA.

        Parameters
        ----------
        observable_type : str, optional
            Filter by observable type.
        limit : int
            Maximum records to return.
        """
        params: dict[str, Any] = {"sysparm_limit": limit}
        if observable_type:
            params["sysparm_query"] = f"type={observable_type}"
        resp = self.get(f"{_TABLE_BASE}/sn_ti_observable", params=params)
        return resp.get("result", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a ServiceNow SecOps record to the appropriate STIX 2.1 object."""
        # Detect record type by table-specific fields
        if "vulnerability" in native or "sn_vr" in str(native.get("sys_class_name", "")):
            return self._vuln_item_to_stix(native)
        if "value" in native and "type" in native:
            return self._observable_to_stix(native)
        return self._incident_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX SDO to a ServiceNow SecOps field payload."""
        return self._to_sn_payload(stix_dict.get("type", "observed-data"), stix_dict)

    def _incident_to_stix(self, record: dict[str, Any]) -> dict[str, Any]:
        sys_id = record.get("sys_id", "")
        opened_at = record.get("opened_at", _now_ts())
        return {
            "type": "observed-data",
            "id": f"observed-data--{_uuid.uuid5(_STIX_NS, f'sn_secops:{sys_id}')}",
            "spec_version": "2.1",
            "created": opened_at,
            "modified": record.get("sys_updated_on", opened_at),
            "first_observed": opened_at,
            "last_observed": opened_at,
            "number_observed": 1,
            "object_refs": [],
            "name": record.get("short_description", ""),
            "description": record.get("description", ""),
            "x_sn_secops": {
                "sys_id": sys_id,
                "state": record.get("state", ""),
                "priority": record.get("priority", ""),
                "category": record.get("category", ""),
                "assigned_to": record.get("assigned_to", {}).get("value", ""),
                "table": "sn_si_incident",
            },
        }

    def _vuln_item_to_stix(self, record: dict[str, Any]) -> dict[str, Any]:
        sys_id = record.get("sys_id", "")
        cve = record.get("vulnerability", {})
        cve_id = cve.get("value", "") if isinstance(cve, dict) else str(cve)
        now = _now_ts()
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{_uuid.uuid5(_STIX_NS, f'sn_secops:{sys_id}')}",
            "spec_version": "2.1",
            "created": record.get("sys_created_on", now),
            "modified": record.get("sys_updated_on", now),
            "name": cve_id or record.get("short_description", "SN Vulnerability"),
            "description": record.get("description", ""),
            "external_references": [{"source_name": "servicenow", "external_id": sys_id}],
            "x_sn_secops": {
                "sys_id": sys_id,
                "cve_id": cve_id,
                "state": record.get("state", ""),
                "risk": record.get("risk", ""),
                "assigned_to": record.get("assigned_to", {}).get("value", ""),
                "table": "sn_vr_vulnerable_item",
            },
        }

    def _observable_to_stix(self, record: dict[str, Any]) -> dict[str, Any]:
        sys_id = record.get("sys_id", "")
        value = record.get("value", "")
        obs_type = record.get("type", "domain")
        type_map = {
            "IP Address": "ipv4-addr:value",
            "Domain": "domain-name:value",
            "URL": "url:value",
            "MD5": "file:hashes.MD5",
            "SHA-256": "file:hashes.'SHA-256'",
        }
        stix_prop = type_map.get(obs_type, "domain-name:value")
        now = _now_ts()
        return {
            "type": "indicator",
            "id": f"indicator--{_uuid.uuid5(_STIX_NS, f'sn_secops:{sys_id}')}",
            "spec_version": "2.1",
            "created": record.get("sys_created_on", now),
            "modified": record.get("sys_updated_on", now),
            "name": value,
            "description": record.get("description", ""),
            "pattern": f"[{stix_prop} = '{value}']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_sn_secops": {
                "sys_id": sys_id,
                "type": obs_type,
                "table": "sn_ti_observable",
            },
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_table(stix_type: str) -> str:
        """Map a STIX type to a ServiceNow SecOps table name."""
        table = _TABLE_MAP.get(stix_type)
        if not table:
            raise GNATClientError(
                f"ServiceNow SecOps: unsupported STIX type '{stix_type}'. "
                f"Supported: {sorted(_TABLE_MAP.keys())}"
            )
        return table

    @staticmethod
    def _to_sn_payload(stix_type: str, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a ServiceNow field payload from a STIX SDO."""
        name = stix_dict.get("name", stix_dict.get("id", ""))
        desc = stix_dict.get("description", "")
        if stix_type == "vulnerability":
            return {
                "short_description": name[:160],
                "description": desc,
                "work_notes": f"[GNAT] Ingested from STIX {stix_type}",
            }
        if stix_type == "indicator":
            return {
                "value": name,
                "description": desc,
                "type": stix_dict.get("x_observable_type", "Domain"),
            }
        # Default: security incident
        return {
            "short_description": name[:160],
            "description": desc,
            "category": "threat-intelligence",
            "work_notes": f"[GNAT] Ingested from STIX {stix_type}",
        }
