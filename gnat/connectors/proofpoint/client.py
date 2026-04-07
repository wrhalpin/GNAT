# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.proofpoint.client
======================================

Proofpoint Targeted Attack Protection (TAP) API connector.

INI config::

    [proofpoint]
    host          = https://tap-api-v2.proofpoint.com
    service_principal = <sp>
    secret        = <secret>
    auth_type     = basic
"""

import base64
from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class ProofpointClient(BaseClient, ConnectorMixin):
    """HTTP client for the Proofpoint TAP v2 REST API."""

    stix_type_map: dict[str, str] = {
        "indicator": "threat",
        "malware": "malware",
    }

    def __init__(self, host: str, service_principal: str = "", secret: str = "", **kwargs: Any):
        """Initialize ProofpointClient."""
        super().__init__(host=host, **kwargs)
        self._sp = service_principal
        self._secret = secret

    def authenticate(self) -> None:
        """Inject HTTP Basic credentials into auth headers."""
        raw = f"{self._sp}:{self._secret}".encode()
        encoded = base64.b64encode(raw).decode()
        self._auth_headers["Authorization"] = f"Basic {encoded}"

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        self.get("/v2/siem/all", params={"format": "json", "sinceSeconds": 60})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        resp = self.get("/v2/forensics", params={"threatId": object_id})
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        params: dict[str, Any] = {"format": "json", "sinceSeconds": 3600}
        if filters:
            params.update(filters)
        resp = self.get("/v2/siem/all", params=params)
        return resp.get("messagesDelivered", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Proofpoint TAP API does not support object creation.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Proofpoint TAP API does not support object deletion.")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert this object to STIX format."""
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', native.get('threatId', ''))}",
            "name": native.get("subject", native.get("url", "")),
            "pattern_type": "stix",
            "created": native.get("messageTime", ""),
            "modified": native.get("messageTime", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {"threatId": stix_dict.get("id", "").split("--")[-1]}
