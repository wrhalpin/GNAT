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
