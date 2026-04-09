# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.xsoar.client
=================================

Palo Alto XSOAR 6 REST API connector.

INI config::

    [xsoar]
    host    = https://xsoar.example.com
    api_key = <key>
    auth_id = <auth-id>          ; optional for multi-tenant
    auth_type = api_key

STIX Type Mapping
-----------------
+--------------------+-----------------------------------+
| STIX Type          | XSOAR Resource                    |
+====================+===================================+
| indicator          | indicator (IOC)                    |
+--------------------+-----------------------------------+
| malware            | indicator                         |
+--------------------+-----------------------------------+
| threat-actor       | indicator                         |
+--------------------+-----------------------------------+
| vulnerability      | indicator                         |
+--------------------+-----------------------------------+
| observed-data      | incident                          |
+--------------------+-----------------------------------+

Investigation Linking
---------------------
Use :meth:`link_incident` to associate a STIX indicator with an existing
XSOAR incident, or pass ``incident_id`` to :meth:`upsert_object` to link
automatically on write::

    client.link_incident("1234", stix_indicator)
    client.upsert_object("indicator", payload, incident_id="1234")
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

# Map XSOAR native indicator_type (lowercase) → STIX object-path prefix
_XSOAR_TYPE_TO_STIX: dict[str, str] = {
    "ip":              "ipv4-addr:value",
    "ipv4":            "ipv4-addr:value",
    "ip address":      "ipv4-addr:value",
    "ipv6":            "ipv6-addr:value",
    "ipv6 address":    "ipv6-addr:value",
    "domain":          "domain-name:value",
    "hostname":        "domain-name:value",
    "fqdn":            "domain-name:value",
    "url":             "url:value",
    "file":            "file:hashes.MD5",
    "file sha-256":    "file:hashes.SHA-256",
    "file sha-1":      "file:hashes.SHA-1",
    "file sha1":       "file:hashes.SHA-1",
    "file md5":        "file:hashes.MD5",
    "md5":             "file:hashes.MD5",
    "sha256":          "file:hashes.SHA-256",
    "sha-256":         "file:hashes.SHA-256",
    "sha1":            "file:hashes.SHA-1",
    "sha-1":           "file:hashes.SHA-1",
    "email":           "email-addr:value",
    "email address":   "email-addr:value",
}


class XSOARClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the XSOAR 6 REST API.

    Supports both indicator (threat intel) and incident (investigation)
    resources.  Pass ``stix_type="observed-data"`` to CRUD methods to
    interact with the incident sub-API.

    Parameters
    ----------
    host : str
        XSOAR base URL, e.g. ``"https://xsoar.example.com"``.
    api_key : str
        XSOAR API key.
    auth_id : str
        Multi-tenant auth ID header (optional).
    verify_ssl : bool
        TLS certificate verification.  Default ``True``.
    """
    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/xsoar"
    COST_UNIT: int = 1



    stix_type_map: dict[str, str] = {
        "indicator":     "indicator",
        "malware":       "indicator",
        "threat-actor":  "indicator",
        "vulnerability": "indicator",
        "observed-data": "incident",
    }

    def __init__(
        self,
        host: str,
        api_key: str = "",
        auth_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize XSOARClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._auth_id = auth_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the XSOAR API key (and optional multi-tenant auth-id) headers."""
        self._auth_headers["Authorization"] = self._api_key
        if self._auth_id:
            self._auth_headers["x-xdr-auth-id"] = self._auth_id

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Return True if the XSOAR instance is reachable."""
        self.get("/health")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single XSOAR object by type and id.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` to fetch an incident, any other supported
            type to search indicators.
        object_id : str
            XSOAR incident id (numeric string) or indicator id.
        """
        if stix_type == "observed-data":
            resp = self.get(f"/incident/{object_id}")
            return resp if isinstance(resp, dict) else {}
        # Indicator path
        resp = self.post("/indicators/search", json={
            "query": f"id:{object_id}", "size": 1
        })
        items = resp.get("iocObjects", []) if isinstance(resp, dict) else []
        return items[0] if items else {}

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List XSOAR objects of a given STIX type.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` to list incidents, other types to list
            indicators.
        filters : dict, optional
            For indicators: ``{"query": "type:IP"}`` free-text query.
            For incidents: ``{"query": "status:0"}`` XSOAR query string.
        page : int
            1-based page number.
        page_size : int
            Records per page.
        """
        query = (filters or {}).get("query", "")
        if stix_type == "observed-data":
            resp = self.post("/incidents/search", json={
                "query":  query,
                "size":   page_size,
                "page":   page - 1,
            })
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Indicator path
        resp = self.post("/indicators/search", json={
            "query": query, "size": page_size, "page": page - 1
        })
        return resp.get("iocObjects", []) if isinstance(resp, dict) else []

    def upsert_object(
        self,
        stix_type: str,
        payload: dict[str, Any],
        incident_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create or update an XSOAR object.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` to create/update an incident, other types
            for indicators.
        payload : dict
            Object fields.  An ``"id"`` key in the payload triggers an update
            (PUT) for incidents.
        incident_id : str, optional
            For indicator writes only: if provided, the indicator is linked
            to this incident after upsert via :meth:`link_incident`.
        """
        if stix_type == "observed-data":
            inc_id = payload.pop("id", None)
            if inc_id:
                return self.put(f"/incident/{inc_id}", json=payload)
            return self.post("/incident", json=payload)
        # Indicator path
        result = self.post("/indicators/edit", json=payload)
        if incident_id:
            self.link_incident(incident_id, payload)
        return result

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Delete an XSOAR object.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` to delete an incident, other types for
            indicators.
        object_id : str
            XSOAR id of the object to remove.
        """
        if stix_type == "observed-data":
            self.delete(f"/incident/{object_id}")
        else:
            self.post("/indicators/delete", json={
                "id": object_id, "doNotWhitelist": False
            })

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate an XSOAR native object to STIX 2.1.

        Dispatches to :meth:`_indicator_to_stix` for indicator records and
        :meth:`_incident_to_stix` for incident records (detected by the
        presence of ``"CustomFields"`` or ``"type"`` == ``"incident"`` in
        the payload).

        Parameters
        ----------
        native : dict
            Raw XSOAR API response (indicator or incident record).
        """
        if native.get("type") == "incident" or "CustomFields" in native:
            return self._incident_to_stix(native)
        return self._indicator_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX object to an XSOAR API payload.

        Dispatches on STIX type: ``observed-data`` → incident payload,
        everything else → indicator payload.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 SDO.
        """
        if stix_dict.get("type") == "observed-data":
            return {
                "name":        stix_dict.get("name", ""),
                "description": stix_dict.get("description", ""),
                "type":        "incident",
            }
        return {
            "value":          stix_dict.get("name", ""),
            "indicator_type": self._infer_xsoar_type(stix_dict.get("pattern", "")),
            "score":          self._confidence_to_score(stix_dict.get("confidence", 50)),
        }

    # ── Investigation linking ─────────────────────────────────────────────

    def link_incident(
        self,
        incident_id: str,
        stix_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Link a STIX indicator to an existing XSOAR incident.

        Calls ``POST /incident/{incident_id}/linkedIncidents`` with a
        minimal indicator payload derived from *stix_obj*.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID (numeric string).
        stix_obj : dict
            STIX indicator dict (or any dict with a ``name`` / ``value`` field).

        Returns
        -------
        dict
            Raw XSOAR API response.
        """
        indicator_value = stix_obj.get("name", stix_obj.get("value", ""))
        payload = {
            "incidentId": incident_id,
            "indicators": [{"value": indicator_value}],
        }
        return self.post(f"/incident/{incident_id}/linkedIncidents", json=payload)

    # ── Evidence expansion ────────────────────────────────────────────────

    def get_incident_alerts(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Return alerts linked to an XSOAR incident.

        Calls ``POST /alerts/search`` with ``incidentId`` filter.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID (numeric string).

        Returns
        -------
        list of dict
            Raw XSOAR alert records.
        """
        resp = self.post("/alerts/search", json={
            "filter": {"incidentId": incident_id},
            "size":   100,
        })
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_incident_tasks(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Return tasks associated with an XSOAR incident.

        Calls ``GET /tasks`` with ``incidentId`` query parameter.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.

        Returns
        -------
        list of dict
            Raw XSOAR task records.
        """
        resp = self.get("/tasks", params={"incidentId": incident_id, "size": 100})
        # Response shape varies; handle both list and dict-with-data
        if isinstance(resp, list):
            return resp
        if isinstance(resp, dict):
            return resp.get("data", resp.get("tasks", []))
        return []

    def get_incident_timeline(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Return timeline entries (war-room entries) for an XSOAR incident.

        Calls ``POST /entry/search`` filtered by incident ID.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.

        Returns
        -------
        list of dict
            Raw XSOAR war-room entry records.
        """
        resp = self.post("/entry/search", json={
            "filter": {"id": incident_id},
            "size":   200,
        })
        if isinstance(resp, list):
            return resp
        if isinstance(resp, dict):
            return resp.get("data", resp.get("entries", []))
        return []

    def search_indicators_by_value(self, value: str) -> list[dict[str, Any]]:
        """
        Search XSOAR indicators by exact or partial value.

        Parameters
        ----------
        value : str
            Indicator value to search for (IP, domain, hash, …).

        Returns
        -------
        list of dict
            Raw XSOAR indicator (iocObject) records.
        """
        resp = self.post("/indicators/search", json={"query": f'value:"{value}"', "size": 50})
        return resp.get("iocObjects", []) if isinstance(resp, dict) else []

    # ── Incident lifecycle ────────────────────────────────────────────────

    def close_incident(
        self,
        incident_id: str,
        close_reason: str = "Resolved",
        close_notes: str = "",
    ) -> dict[str, Any]:
        """
        Close an XSOAR incident.

        Calls ``POST /incident/close/{incident_id}``.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID (numeric string).
        close_reason : str
            Closure reason label shown in XSOAR.  Default ``"Resolved"``.
        close_notes : str
            Optional notes added to the incident on close.
        """
        return self.post(f"/incident/close/{incident_id}", json={
            "closeReason": close_reason,
            "closeNotes":  close_notes,
            "id":          incident_id,
        })

    def reopen_incident(self, incident_id: str) -> dict[str, Any]:
        """
        Reopen a previously closed XSOAR incident.

        Calls ``POST /incident/reopen/{incident_id}``.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID (numeric string).
        """
        return self.post(f"/incident/reopen/{incident_id}", json={"id": incident_id})

    def get_incident_indicators(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Return all indicators (IOCs) linked to an XSOAR incident.

        Calls ``GET /incident/{incident_id}/indicators``.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.
        """
        resp = self.get(f"/incident/{incident_id}/indicators")
        if isinstance(resp, list):
            return resp
        return resp.get("indicators", resp.get("data", [])) if isinstance(resp, dict) else []

    def add_incident_comment(
        self,
        incident_id: str,
        comment: str,
    ) -> dict[str, Any]:
        """
        Add a war-room entry (comment) to an XSOAR incident.

        Calls ``POST /entry`` with the given *incident_id* and *comment*
        content.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.
        comment : str
            Comment text to post.
        """
        return self.post("/entry", json={
            "incidentId": incident_id,
            "data":       comment,
            "markdown":   True,
        })

    def assign_incident(
        self,
        incident_id: str,
        owner: str,
    ) -> dict[str, Any]:
        """
        Assign an XSOAR incident to a specific user.

        Calls ``PUT /incident/{incident_id}`` with the owner field.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.
        owner : str
            Username of the user to assign the incident to.
        """
        return self.put(f"/incident/{incident_id}", json={"owner": owner, "id": incident_id})

    # ── Indicator operations ──────────────────────────────────────────────

    def get_indicator_reputation(self, value: str) -> dict[str, Any]:
        """
        Query the reputation (score) of an indicator value across all feeds.

        Calls ``POST /indicator/reputation``.

        Parameters
        ----------
        value : str
            Indicator value to query (IP, domain, URL, hash, …).
        """
        resp = self.post("/indicator/reputation", json={"value": value})
        return resp if isinstance(resp, dict) else {}

    def bulk_create_indicators(
        self,
        indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Create multiple XSOAR indicators in a single API call.

        Calls ``POST /indicators/bulkCreate``.  Each item in *indicators*
        must have at minimum ``value`` and ``indicator_type``.

        Parameters
        ----------
        indicators : list of dict
            List of indicator payloads.
        """
        resp = self.post("/indicators/bulkCreate", json={"iocObjects": indicators})
        return resp if isinstance(resp, dict) else {}

    def export_indicators(
        self,
        query: str = "",
        export_format: str = "json",
        page_size: int = 5000,
    ) -> dict[str, Any]:
        """
        Export XSOAR indicators matching a query.

        Calls ``POST /indicators/export``.

        Parameters
        ----------
        query : str
            XSOAR indicator query (e.g. ``"type:IP and score:3"``).
        export_format : str
            Export format: ``"json"`` or ``"csv"``.  Default ``"json"``.
        page_size : int
            Maximum number of indicators to export.  Default ``5000``.
        """
        resp = self.post("/indicators/export", json={
            "query":  query,
            "format": export_format,
            "size":   page_size,
        })
        return resp if isinstance(resp, dict) else {}

    def expire_indicator(self, indicator_id: str) -> dict[str, Any]:
        """
        Mark an XSOAR indicator as expired.

        Calls ``POST /indicators/expire`` with the indicator ID.

        Parameters
        ----------
        indicator_id : str
            XSOAR indicator ID.
        """
        return self.post("/indicators/expire", json={"id": indicator_id})

    # ── Playbook / automation ─────────────────────────────────────────────

    def run_playbook(
        self,
        incident_id: str,
        playbook_id: str = "",
    ) -> dict[str, Any]:
        """
        Trigger a playbook run on an XSOAR incident.

        Calls ``POST /playbook/run``.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID to run the playbook against.
        playbook_id : str, optional
            Playbook ID or name.  If omitted the incident's default
            playbook is used.
        """
        payload: dict[str, Any] = {"incidentId": incident_id}
        if playbook_id:
            payload["playbookId"] = playbook_id
        return self.post("/playbook/run", json=payload)

    def search_automations(
        self,
        query: str = "",
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search XSOAR automation scripts by name or query.

        Calls ``POST /automation/search``.

        Parameters
        ----------
        query : str
            Free-text or Lucene-style query to filter scripts by name,
            tag, or description.
        page_size : int
            Maximum number of results.  Default ``100``.
        """
        resp = self.post("/automation/search", json={"query": query, "size": page_size})
        return resp.get("scripts", []) if isinstance(resp, dict) else []

    def search_integrations(
        self,
        query: str = "",
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search XSOAR integration instances by name or query.

        Calls ``POST /settings/integration/search``.

        Parameters
        ----------
        query : str
            Filter query.
        page_size : int
            Maximum number of results.  Default ``100``.
        """
        resp = self.post("/settings/integration/search", json={
            "query": query,
            "size":  page_size,
        })
        return resp.get("configurations", []) if isinstance(resp, dict) else []

    def get_playbook_tasks(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Return the playbook task tree for an XSOAR incident.

        Calls ``GET /playbook/tasks?incidentId={incident_id}``.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID.
        """
        resp = self.get("/playbook/tasks", params={"incidentId": incident_id})
        if isinstance(resp, list):
            return resp
        return resp.get("tasks", []) if isinstance(resp, dict) else []

    def complete_task(
        self,
        task_id: str,
        incident_id: str,
        answer: str = "",
    ) -> dict[str, Any]:
        """
        Mark an XSOAR playbook task as complete.

        Calls ``POST /task/complete``.

        Parameters
        ----------
        task_id : str
            XSOAR task ID.
        incident_id : str
            Parent incident ID.
        answer : str, optional
            Answer string for tasks with a manual response prompt.
        """
        return self.post("/task/complete", json={
            "id":         task_id,
            "incidentId": incident_id,
            "answer":     answer,
        })

    # ── User / administration ─────────────────────────────────────────────

    def list_users(self, page_size: int = 200) -> list[dict[str, Any]]:
        """
        Return all XSOAR users.

        Calls ``GET /user/list``.

        Parameters
        ----------
        page_size : int
            Maximum users to return.  Default ``200``.
        """
        resp = self.get("/user/list", params={"size": page_size})
        if isinstance(resp, list):
            return resp
        return resp.get("users", []) if isinstance(resp, dict) else []

    def get_server_config(self) -> dict[str, Any]:
        """
        Retrieve XSOAR server configuration and licence information.

        Calls ``GET /account``.
        """
        resp = self.get("/account")
        return resp if isinstance(resp, dict) else {}

    def list_incident_types(self) -> list[dict[str, Any]]:
        """
        Return all configured XSOAR incident types.

        Calls ``GET /incidenttype``.
        """
        resp = self.get("/incidenttype")
        if isinstance(resp, list):
            return resp
        return resp.get("incidentTypes", []) if isinstance(resp, dict) else []

    def list_indicator_types(self) -> list[dict[str, Any]]:
        """
        Return all configured XSOAR indicator types.

        Calls ``GET /indicatorType``.
        """
        resp = self.get("/indicatorType")
        if isinstance(resp, list):
            return resp
        return resp.get("indicatorTypes", []) if isinstance(resp, dict) else []

    def get_dashboard(self, dashboard_id: str) -> dict[str, Any]:
        """
        Retrieve a specific XSOAR dashboard by ID.

        Calls ``GET /dashboard/{dashboard_id}``.

        Parameters
        ----------
        dashboard_id : str
            XSOAR dashboard ID.
        """
        resp = self.get(f"/dashboard/{dashboard_id}")
        return resp if isinstance(resp, dict) else {}

    def list_reports(self) -> list[dict[str, Any]]:
        """
        List available XSOAR report definitions.

        Calls ``GET /reports``.
        """
        resp = self.get("/reports")
        if isinstance(resp, list):
            return resp
        return resp.get("reports", []) if isinstance(resp, dict) else []

    # ── Private helpers ────────────────────────────────────────────────────

    def _indicator_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Map an XSOAR indicator dict to a STIX Indicator SDO."""
        xsoar_type = str(native.get("indicator_type", "")).lower()
        stix_path  = _XSOAR_TYPE_TO_STIX.get(xsoar_type, "unknown:value")
        value      = native.get("value", "")
        pattern    = f"[{stix_path} = '{value}']" if value else ""
        return {
            "type":            "indicator",
            "id":              f"indicator--{native.get('id', '')}",
            "name":            value,
            "pattern":         pattern,
            "pattern_type":    "stix",
            "created":         native.get("timestamp", ""),
            "modified":        native.get("modified", ""),
            "indicator_types": [native.get("indicator_type", "unknown")],
            "confidence":      self._score_to_confidence(native.get("score", 0)),
        }

    @staticmethod
    def _incident_to_stix(native: dict[str, Any]) -> dict[str, Any]:
        """Map an XSOAR incident dict to a STIX ``observed-data`` SDO."""
        inc_id    = str(native.get("id", ""))
        opened_at = native.get("occurred", native.get("created", ""))
        modified  = native.get("modified", opened_at)
        custom    = native.get("CustomFields", {})
        if not isinstance(custom, dict):
            custom = {}
        return {
            "type":                "observed-data",
            "id":                  f"observed-data--{inc_id}",
            "created":             opened_at,
            "modified":            modified,
            "first_observed":      opened_at,
            "last_observed":       modified,
            "number_observed":     1,
            "object_refs":         [],
            "name":                native.get("name", ""),
            "description":         native.get("details", ""),
            "x_xsoar_incident_id": inc_id,
            "x_xsoar_severity":    native.get("severity", 0),
            "x_xsoar_status":      native.get("status", 0),
            "x_xsoar_owner":       native.get("owner", ""),
            "x_xsoar_type":        native.get("type", ""),
            "x_xsoar_labels": [
                lbl.get("value", "") for lbl in native.get("labels", [])
                if isinstance(lbl, dict)
            ],
            "x_xsoar_custom": custom,
        }

    @staticmethod
    def _infer_xsoar_type(pattern: str) -> str:
        """Infer the XSOAR indicator type from a STIX pattern string."""
        p = pattern.lower()
        if "ipv4-addr"   in p:
            return "IP"
        if "ipv6-addr"   in p:
            return "IPv6"
        if "domain-name" in p:
            return "Domain"
        if "url:"        in p:
            return "URL"
        if "sha-256"     in p:
            return "File SHA-256"
        if "sha-1"       in p:
            return "File SHA-1"
        if "md5"         in p:
            return "File MD5"
        if "email-addr"  in p:
            return "Email"
        return "Unclassified"

    @staticmethod
    def _score_to_confidence(score: int) -> int:
        """Convert XSOAR severity score (0-3) to STIX confidence (0-100)."""
        return min(100, max(0, score * 33))

    @staticmethod
    def _confidence_to_score(confidence: int) -> int:
        """Convert STIX confidence (0-100) to XSOAR score (0-3)."""
        if confidence >= 67:
            return 3
        if confidence >= 34:
            return 2
        if confidence >= 1:
            return 1
        return 0
