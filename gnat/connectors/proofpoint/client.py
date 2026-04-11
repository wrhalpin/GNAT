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

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = ""

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

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_messages_delivered(
        self, since_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """Return messages delivered to end users within the window."""
        resp = self.get(
            "/v2/siem/messages/delivered",
            params={"format": "json", "sinceSeconds": int(since_seconds)},
        )
        return resp.get("messagesDelivered", []) if isinstance(resp, dict) else []

    def list_messages_blocked(
        self, since_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """Return messages blocked by TAP within the window."""
        resp = self.get(
            "/v2/siem/messages/blocked",
            params={"format": "json", "sinceSeconds": int(since_seconds)},
        )
        return resp.get("messagesBlocked", []) if isinstance(resp, dict) else []

    def list_clicks_permitted(
        self, since_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """Return URL clicks that were permitted (URL was clean at click time)."""
        resp = self.get(
            "/v2/siem/clicks/permitted",
            params={"format": "json", "sinceSeconds": int(since_seconds)},
        )
        return resp.get("clicksPermitted", []) if isinstance(resp, dict) else []

    def list_clicks_blocked(
        self, since_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """Return URL clicks that were blocked by the URL Defense rewrite."""
        resp = self.get(
            "/v2/siem/clicks/blocked",
            params={"format": "json", "sinceSeconds": int(since_seconds)},
        )
        return resp.get("clicksBlocked", []) if isinstance(resp, dict) else []

    def list_issues(
        self, since_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """Return all issues (delivered + clicked-permitted) in the window."""
        resp = self.get(
            "/v2/siem/issues",
            params={"format": "json", "sinceSeconds": int(since_seconds)},
        )
        out: list[dict[str, Any]] = []
        if isinstance(resp, dict):
            for key in ("messagesDelivered", "clicksPermitted"):
                val = resp.get(key, [])
                if isinstance(val, list):
                    out.extend(r for r in val if isinstance(r, dict))
        return out

    def get_forensics(self, threat_id: str) -> dict[str, Any]:
        """Return forensic detail for a specific threatId."""
        resp = self.get("/v2/forensics", params={"threatId": threat_id})
        return resp if isinstance(resp, dict) else {}

    def list_top_clickers(self, window: str = "14") -> list[dict[str, Any]]:
        """Return the People (top clickers) report for the given window."""
        resp = self.get("/v2/people/top-clickers", params={"window": window})
        return resp.get("users", []) if isinstance(resp, dict) else []

    def decode_url(self, url: str) -> dict[str, Any]:
        """Decode a TAP URL Defense rewritten URL back to the original."""
        resp = self.post("/v2/url/decode", json={"urls": [url]})
        return resp if isinstance(resp, dict) else {}

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
