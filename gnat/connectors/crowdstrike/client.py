"""
ctm_sak.connectors.crowdstrike.client
======================================

CrowdStrike Falcon Platform connector (OAuth2 client-credentials).

INI config::

    [crowdstrike]
    host          = https://api.crowdstrike.com
    client_id     = <CID>
    client_secret = <secret>
    auth_type     = oauth2
"""

from typing import Any, Dict, List, Optional
from ctm_sak.clients.base import BaseClient, SAKClientError
from ctm_sak.connectors.base_connector import ConnectorMixin


class CrowdStrikeClient(BaseClient, ConnectorMixin):
    """HTTP client for the CrowdStrike Falcon REST API."""

    stix_type_map: Dict[str, str] = {
        "indicator":     "iocs",
        "malware":       "detections",
        "vulnerability": "vulnerabilities",
    }

    def __init__(self, host: str, client_id: str = "", client_secret: str = "", **kwargs: Any):
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
            raise SAKClientError("CrowdStrike: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    def health_check(self) -> bool:
        self.get("/sensors/queries/installers/v1", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        resp = self.get(f"/indicators/entities/{resource}/v1", params={"ids": object_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def list_objects(self, stix_type: str, filters: Optional[Dict[str, Any]] = None,
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        params: Dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if filters:
            params["filter"] = " + ".join(f"{k}:'{v}'" for k, v in filters.items())
        resp = self.get(f"/indicators/queries/{resource}/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.post("/indicators/entities/iocs/v1", json={"indicators": [payload]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        self.delete(f"/indicators/entities/iocs/v1?ids={object_id}")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{native.get('value', '')}']",
            "pattern_type": "stix",
            "created": native.get("created_timestamp", ""),
            "modified": native.get("modified_timestamp", ""),
            "indicator_types": [native.get("type", "unknown")],
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "ipv4",
            "value": stix_dict.get("name", ""),
            "action": "detect",
            "severity": "medium",
        }
