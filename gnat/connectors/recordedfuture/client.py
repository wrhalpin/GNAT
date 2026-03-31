"""
gnat.connectors.recordedfuture.client
==========================================

Recorded Future Connect API connector.

INI config::

    [recordedfuture]
    host      = https://api.recordedfuture.com
    api_token = <token>
    auth_type = token
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class RecordedFutureClient(BaseClient, ConnectorMixin):
    """HTTP client for the Recorded Future Connect API v2."""

    stix_type_map: dict[str, str] = {
        "indicator":    "ip",
        "malware":      "malware",
        "threat-actor": "threat-actor",
        "vulnerability":"vulnerability",
    }

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    def authenticate(self) -> None:
        """Inject the RF API token header."""
        self._auth_headers["X-RFToken"] = self._api_token

    def health_check(self) -> bool:
        self.get("/v2/ip/search", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        resp = self.get(
            f"/v2/{resource}/{object_id}",
            params={"fields": "entity,risk,timestamps,relatedEntities"},
        )
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(self, stix_type: str, filters: Optional[dict[str, Any]] = None,
                     page: int = 1, page_size: int = 100) -> list[dict[str, Any]]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        params: dict[str, Any] = {"limit": page_size, "from": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = self.get(f"/v2/{resource}/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Recorded Future API is read-only -- upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Recorded Future API is read-only -- delete not supported.")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        entity = native.get("entity", {})
        risk   = native.get("risk", {})
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{entity.get('id', '')}",
            "name": entity.get("name", ""),
            "pattern": f"[ipv4-addr:value = '{entity.get('name', '')}']",
            "pattern_type": "stix",
            "created": native.get("timestamps", {}).get("firstSeen", ""),
            "modified": native.get("timestamps", {}).get("lastSeen", ""),
            "x_rf_risk_score": risk.get("score", 0),
            "x_rf_criticality": risk.get("criticalityLabel", ""),
        }
        # Targeted industries from relatedEntities (type == "Industry")
        # Returned when ?fields=...relatedEntities is included in the request.
        sectors = [
            r.get("entity", {}).get("name", "")
            for r in native.get("relatedEntities", [])
            if r.get("type") == "Industry"
        ]
        sectors = [s for s in sectors if s]
        if sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {"entity": stix_dict.get("name", "")}
