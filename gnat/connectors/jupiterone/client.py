"""
gnat.connectors.jupiterone.client
=================================

JupiterOne (Cyber Asset Analysis / CAASM Graph Platform) connector — full client.

Authentication
--------------
API Key via `Authorization: Bearer` header (account-level token)::

    [jupiterone]
    host  = https://graphql.us.jupiterone.io          # or https://graphql.eu.jupiterone.io for EU tenants
    api_key = <your-jupiterone-api-key>

Generate the key via the JupiterOne dashboard (Account Settings → API Tokens) or via the GraphQL `createToken` mutation.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | JupiterOne Resource              |
+================+==================================+
| report         | Assets / Entities (devices, repos, users, etc.) |
+----------------+----------------------------------+
| vulnerability  | Findings / Vulnerabilities       |
+----------------+----------------------------------+

Key Endpoint
------------
* `/` (POST) — single GraphQL endpoint for all queries and mutations

Notes
-----
* GraphQL-heavy: use the `_graphql_query` helper with typed queries.
* Excellent for relationship mapping and unified asset context across your other connectors.
* Read-heavy; supports mutations for custom entities if needed.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e9f0a1b2-c3d4-5e6f-7a8b-9c0d1e2f3a4b")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class JupiterOneClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for JupiterOne GraphQL API.

    Parameters
    ----------
    host : str
        GraphQL endpoint (e.g. "https://graphql.us.jupiterone.io").
    api_key : str
        JupiterOne account-level API key.
    """

    stix_type_map: dict[str, str] = {
        "report": "entities",
        "vulnerability": "findings",
    }

    def __init__(
        self, host: str = "https://graphql.us.jupiterone.io", api_key: str = "", **kwargs: Any
    ):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"] = "application/json"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Simple introspection query to verify connectivity."""
        query = "query { __schema { queryType { name } } }"
        self._graphql_query(query)
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single entity or finding by ID (via GraphQL)."""
        if stix_type == "report":
            query = """
            query GetEntity($id: ID!) {
              entity(id: $id) { id _type displayName createdOn ... on Asset { class tags } }
            }
            """
            variables = {"id": object_id}
            data = self._graphql_query(query, variables)
            return data.get("entity") or {}
        if stix_type == "vulnerability":
            query = """
            query GetFinding($id: ID!) {
              finding(id: $id) { id _type displayName severity createdOn }
            }
            """
            variables = {"id": object_id}
            data = self._graphql_query(query, variables)
            return data.get("finding") or {}
        raise GNATClientError(f"Unsupported STIX type for JupiterOne: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        limit = page_size

        if stix_type == "vulnerability":
            return self.fetch_findings(limit=limit, **filters)
        # Default: entities/assets as reports
        return self.fetch_entities(limit=limit, **filters)

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        # JupiterOne supports mutations for custom entities; stub for now
        raise GNATClientError(
            "JupiterOne upsert via GraphQL mutation not implemented in this connector yet."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion via GraphQL not implemented in this connector.")

    # ── GraphQL Core Helper ─────────────────────────────────────────────
