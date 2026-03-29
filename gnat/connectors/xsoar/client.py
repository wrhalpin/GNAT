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
"""

from typing import Any, Dict, List, Optional
from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class XSOARClient(BaseClient, ConnectorMixin):
    """HTTP client for the XSOAR 6 REST API."""

    stix_type_map: Dict[str, str] = {
        "indicator":     "indicator",
        "malware":       "indicator",
        "threat-actor":  "indicator",
        "vulnerability": "indicator",
    }

    def __init__(self, host: str, api_key: str = "",
                 auth_id: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._auth_id = auth_id

    def authenticate(self) -> None:
        """Inject the XSOAR API key header."""
        self._auth_headers["Authorization"] = self._api_key
        if self._auth_id:
            self._auth_headers["x-xdr-auth-id"] = self._auth_id

    def health_check(self) -> bool:
        self.get("/health")
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resp = self.post("/indicators/search", json={
            "query": f"id:{object_id}", "size": 1
        })
        items = resp.get("iocObjects", []) if isinstance(resp, dict) else []
        return items[0] if items else {}

    def list_objects(self, stix_type: str, filters: Optional[Dict[str, Any]] = None,
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        query = filters.get("query", "") if filters else ""
        resp = self.post("/indicators/search", json={
            "query": query, "size": page_size, "page": page - 1
        })
        return resp.get("iocObjects", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: Dict[str, Any],
                      incident_id: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        """Create or update an indicator. If *incident_id* is given, the
        indicator is linked to that incident after upsert."""
        result = self.post("/indicators/edit", json=payload)
        if incident_id:
            self.link_incident(incident_id, payload)
        return result

    def delete_object(self, stix_type: str, object_id: str) -> None:
        self.post("/indicators/delete", json={"id": object_id, "doNotWhitelist": False})

    def link_incident(self, incident_id: str, stix_obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Link a STIX indicator to an existing XSOAR incident.

        Calls ``POST /incident/{incident_id}/linkedIncidents`` with a
        minimal indicator payload derived from *stix_obj*.

        Parameters
        ----------
        incident_id : str
            XSOAR incident ID (numeric string).
        stix_obj : dict
            STIX indicator dict (or any dict with a ``name`` / ``pattern`` field).

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

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{native.get('value', '')}']",
            "pattern_type": "stix",
            "created": native.get("timestamp", ""),
            "modified": native.get("modified", ""),
            "indicator_types": [native.get("indicator_type", "unknown")],
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "value": stix_dict.get("name", ""),
            "indicator_type": "IP",
            "score": 2,
        }
