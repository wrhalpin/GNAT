# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.opencti.client
=====================================

OpenCTI threat intelligence platform connector.

Authentication
--------------
API key via ``Authorization: Bearer <token>`` header::

    [opencti]
    host    = https://opencti.corp.example.com
    api_key = <opencti-api-key>

API keys are generated in OpenCTI:
Settings → Security → API Access → Generate API key.

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | OpenCTI Resource                 |
+====================+==================================+
| indicator          | indicators                       |
+--------------------+----------------------------------+
| threat-actor       | threat-actors-group              |
+--------------------+----------------------------------+
| malware            | malwares                         |
+--------------------+----------------------------------+
| attack-pattern     | attack-patterns (MITRE TTPs)     |
+--------------------+----------------------------------+
| vulnerability      | vulnerabilities (CVEs)           |
+--------------------+----------------------------------+
| report             | reports                          |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``/graphql``         — GraphQL API (primary interface)
* ``/health``          — platform health check

Notes
-----
* OpenCTI's primary API is GraphQL.  This connector uses a simplified
  REST-like wrapper; for full GraphQL support use the official
  ``pycti`` SDK.
* Both read and write operations are supported.
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class OpenCTIClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the OpenCTI GraphQL/REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://opencti.corp.example.com"``.
    api_key : str
        OpenCTI API key.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "indicators",
        "threat-actor": "threat-actors-group",
        "malware": "malwares",
        "attack-pattern": "attack-patterns",
        "vulnerability": "vulnerabilities",
        "report": "reports",
    }

    # GraphQL type names for list queries
    _GQL_TYPES: dict[str, str] = {
        "indicator": "Indicators",
        "threat-actor": "ThreatActors",
        "malware": "Malwares",
        "attack-pattern": "AttackPatterns",
        "vulnerability": "Vulnerabilities",
        "report": "Reports",
    }

    def __init__(self, host: str, api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the OpenCTI Bearer token."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the OpenCTI health endpoint."""
        self.get("/health")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single OpenCTI object by STIX id via GraphQL.

        Parameters
        ----------
        stix_type : str
            STIX type (e.g. ``"indicator"``).
        object_id : str
            STIX id (e.g. ``"indicator--uuid"``).
        """
        query = """
        query GetObject($id: String!) {
          stixObjectOrStixRelationship(id: $id) {
            ... on BasicObject { id entity_type }
            ... on Indicator { name pattern confidence }
            ... on Malware { name description }
            ... on ThreatActor { name description }
            ... on AttackPattern { name description x_mitre_id }
            ... on Vulnerability { name description x_opencti_cvss_base_score }
          }
        }
        """
        resp = self.post(
            "/graphql",
            json={"query": query, "variables": {"id": object_id}},
        )
        if isinstance(resp, dict):
            data = resp.get("data", {})
            return data.get("stixObjectOrStixRelationship", {})
        return {}

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List OpenCTI objects of a given STIX type via GraphQL.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:

            * ``search``    — text search string
            * ``orderBy``   — field to sort by
            * ``orderMode`` — ``"asc"`` or ``"desc"``
        """
        filters = dict(filters or {})
        gql_type = self._GQL_TYPES.get(stix_type)
        if not gql_type:
            raise GNATClientError(f"OpenCTI: unsupported STIX type '{stix_type}'")
        search = filters.pop("search", None)
        order_by = filters.pop("orderBy", "created_at")
        order_mode = filters.pop("orderMode", "desc")
        first = page_size
        _after = None  # cursor-based pagination not implemented here

        query = f"""
        query List{gql_type}($first: Int, $orderBy: String, $orderMode: OrderingMode, $search: String) {{
          {gql_type[0].lower() + gql_type[1:]}(
            first: $first
            orderBy: $orderBy
            orderMode: $orderMode
            search: $search
          ) {{
            edges {{
              node {{
                id entity_type
                ... on Indicator {{ name pattern confidence created modified }}
                ... on Malware {{ name description first_seen last_seen }}
                ... on ThreatActor {{ name description }}
                ... on AttackPattern {{ name description x_mitre_id }}
                ... on Vulnerability {{ name description x_opencti_cvss_base_score }}
              }}
            }}
          }}
        }}
        """
        variables: dict[str, Any] = {
            "first": first,
            "orderBy": order_by,
            "orderMode": order_mode.upper(),
        }
        if search:
            variables["search"] = search

        resp = self.post("/graphql", json={"query": query, "variables": variables})
        if isinstance(resp, dict):
            data = resp.get("data", {})
            key = gql_type[0].lower() + gql_type[1:]
            edges = data.get(key, {}).get("edges", [])
            return [e.get("node", {}) for e in edges]
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update an OpenCTI object via GraphQL import.

        Wraps the payload in a STIX bundle and calls the import endpoint.
        """
        bundle = {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [payload],
        }
        resp = self.post(
            "/graphql",
            json={
                "query": "mutation ImportBundle($file: Upload!) { importPush(file: $file) }",
                "variables": {"bundle": bundle},
            },
        )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an OpenCTI object by STIX id."""
        mutation = """
        mutation DeleteObject($id: ID!) {
          stixObjectOrStixRelationshipEdit(id: $id) {
            delete
          }
        }
        """
        self.post(
            "/graphql",
            json={"query": mutation, "variables": {"id": object_id}},
        )

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate an OpenCTI GraphQL node to a STIX 2.1 object.

        OpenCTI objects map closely to STIX; this method normalises
        field names and returns a valid STIX dict.
        """
        entity_type = native.get("entity_type", "")
        obj_id = native.get("id", "")

        if entity_type == "Indicator":
            return {
                "type": "indicator",
                "id": obj_id,
                "name": native.get("name", ""),
                "pattern": native.get("pattern", ""),
                "pattern_type": "stix",
                "created": native.get("created", ""),
                "modified": native.get("modified", ""),
                "indicator_types": ["malicious-activity"],
                "confidence": native.get("confidence", 50),
            }

        if entity_type in ("Malware",):
            return {
                "type": "malware",
                "id": obj_id,
                "name": native.get("name", ""),
                "description": native.get("description", ""),
                "is_family": False,
            }

        if entity_type in ("ThreatActor", "ThreatActorGroup"):
            return {
                "type": "threat-actor",
                "id": obj_id,
                "name": native.get("name", ""),
                "description": native.get("description", ""),
            }

        if entity_type == "AttackPattern":
            return {
                "type": "attack-pattern",
                "id": obj_id,
                "name": native.get("name", ""),
                "description": native.get("description", ""),
                "x_mitre_id": native.get("x_mitre_id", ""),
            }

        if entity_type == "Vulnerability":
            return {
                "type": "vulnerability",
                "id": obj_id,
                "name": native.get("name", ""),
                "description": native.get("description", ""),
                "x_cvss_score": native.get("x_opencti_cvss_base_score"),
            }

        # Generic passthrough
        return dict(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX object to an OpenCTI GraphQL input dict.

        Returns a dict suitable for ``upsert_object()``.
        """
        return stix_dict
