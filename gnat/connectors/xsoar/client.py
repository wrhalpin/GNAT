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
from gnat.clients.base import BaseClient, SAKClientError
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

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.post("/indicators/edit", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        self.post("/indicators/delete", json={"id": object_id, "doNotWhitelist": False})

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
