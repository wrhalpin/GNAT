"""
gnat.connectors.wiz.client
==========================

Wiz CNAPP (Cloud Native Application Protection Platform) connector -- full client.

Authentication
--------------
OAuth2 Client Credentials (service account Client ID + Secret).

    [wiz]
    host          = https://api.us1.app.wiz.io          # region: us1, us2, eu1, eu2, etc.
    client_id     = <wiz-client-id>
    client_secret = <wiz-client-secret>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Wiz Resource                     |
+================+==================================+
| vulnerability  | Vulnerability findings           |
+----------------+----------------------------------+
| report         | Issues, toxic combinations, config findings, resources |
+----------------+----------------------------------+

Key Endpoint
------------
* `/graphql` -- single GraphQL POST endpoint

Notes
-----
* Region-specific host (check Tenant Info in Wiz portal).
* Common scopes: read:issues, read:vulnerabilities, read:cloud_configuration, etc.
* Expand queries as needed via the _graphql_query helper.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b9c8d7e6-f5a4-3b2c-1d0e-9f8a7b6c5d4e")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class WizClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Wiz GraphQL API.

    Parameters
    ----------
    host : str
        Region-specific base URL (e.g. "https://api.us1.app.wiz.io").
    client_id : str
        Service account client ID.
    client_secret : str
        Service account client secret.
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "vulnerabilityFindings",
        "report":        "issues",  # covers toxic combinations, misconfigs, etc.
    }

    def __init__(self, host: str = "https://api.us1.app.wiz.io", client_id: str = "", client_secret: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None
        self._auth_host = "https://auth.app.wiz.io"  # usually fixed; can be auth.wiz.io for some tenants

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """OAuth2 Client Credentials flow."""
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "audience": "wiz-api",
        }
        # Use base client for token request (auth headers not yet set)
        resp = self.post(f"{self._auth_host}/oauth/token", json=payload)
        if not isinstance(resp, dict) or "access_token" not in resp:
            raise GNATClientError(f"Failed to obtain Wiz token: {resp}")
        self._token = resp["access_token"]
        self._auth_headers["Authorization"] = f"Bearer {self._token}"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin -- CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Simple introspection-style query."""
        query = "query { __schema { queryType { name } } }"
        self._graphql_query(query)
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        raise GNATClientError("Wiz get_object by single ID not directly supported; use filtered list_objects.")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> List[Dict[str, Any]]:
        """List Wiz vulnerability findings or issues."""
        filters = dict(filters or {})
        if stix_type == "vulnerability":
            query = """
            query VulnerabilityFindings($first: Int) {
              vulnerabilityFindings(first: $first) {
                nodes { id name severity status cve { id } asset { id name } }
              }
            }
            """
            data = self._graphql_query(query, variables={"first": page_size})
            return data.get("vulnerabilityFindings", {}).get("nodes", [])
        # Default: issues
        query = """
        query Issues($first: Int) {
          issues(first: $first) {
            nodes { id title severity status type createdAt }
          }
        }
        """
        data = self._graphql_query(query, variables={"first": page_size})
        return data.get("issues", {}).get("nodes", [])

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError("Wiz is read-only — upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Wiz is read-only — delete not supported.")

    # ── STIX conversion ───────────────────────────────────────────────────

    def to_stix(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Map a Wiz finding/issue dict to a STIX object."""
        obj_id = str(obj.get("id", _uuid.uuid4()))
        # Vulnerability finding → STIX vulnerability
        if "cve" in obj:
            cve_id = (obj.get("cve") or {}).get("id", "")
            name = obj.get("name", cve_id or obj_id)
            return {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{_uuid.uuid5(_STIX_NS, obj_id)}",
                "name": name,
                "x_wiz_severity": obj.get("severity", ""),
                "x_wiz_status": obj.get("status", ""),
                "external_references": [{"source_name": "cve", "external_id": cve_id}] if cve_id else [],
            }
        # Issue → STIX report
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{_uuid.uuid5(_STIX_NS, obj_id)}",
            "name": obj.get("title", obj_id),
            "published": obj.get("createdAt", _now_ts()),
            "object_refs": [],
            "x_wiz_severity": obj.get("severity", ""),
            "x_wiz_status": obj.get("status", ""),
            "x_wiz_type": obj.get("type", ""),
            "x_wiz_raw": obj,
        }

    def from_stix(self, stix_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Wiz is read-only — from_stix not supported."""
        raise GNATClientError("Wiz is read-only — from_stix not supported.")

    # ── Private helpers ───────────────────────────────────────────────────

    def _graphql_query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a GraphQL query against /graphql and return the ``data`` dict."""
        payload: Dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = self.post("/graphql", json=payload)
        if not isinstance(resp, dict):
            raise GNATClientError(f"Unexpected Wiz GraphQL response type: {type(resp)}")
        if "errors" in resp:
            raise GNATClientError(f"Wiz GraphQL error: {resp['errors']}")
        return resp.get("data", {})
