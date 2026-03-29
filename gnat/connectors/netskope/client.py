"""
gnat.connectors.netskope.client
====================================

Netskope REST API v2 connector.

INI config::

    [netskope]
    host      = https://<tenant>.goskope.com
    api_token = <token>
    auth_type = token
"""

from typing import Any, Dict, List, Optional
from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class NetskopeClient(BaseClient, ConnectorMixin):
    """HTTP client for the Netskope REST API v2."""

    stix_type_map: Dict[str, str] = {
        "indicator": "urllist",
        "malware":   "malware",
    }

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    def authenticate(self) -> None:
        """Inject Netskope API token header."""
        self._auth_headers["Netskope-Api-Token"] = self._api_token

    def health_check(self) -> bool:
        self.get("/api/v2/policy/urllist", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/policy/urllist/{object_id}")

    def list_objects(self, stix_type: str, filters: Optional[Dict[str, Any]] = None,
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": page_size, "skip": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = self.get("/api/v2/policy/urllist", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        list_id = payload.pop("id", None)
        if list_id:
            return self.patch(f"/api/v2/policy/urllist/{list_id}", json=payload)
        return self.post("/api/v2/policy/urllist", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        self.delete(f"/api/v2/policy/urllist/{object_id}")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("name", ""),
            "created": native.get("modify_by", ""),
            "modified": native.get("modify_by", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": stix_dict.get("name", ""), "type": "exact", "data": {"urls": []}}
