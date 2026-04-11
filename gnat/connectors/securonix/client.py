# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.securonix.client
====================================

Securonix cloud-native SIEM / UEBA connector.

Authentication
--------------
Username / password → session token via ``/ws/token/generate``::

    [securonix]
    host     = https://YOUR_TENANT.securonix.com
    username = svc_gnat
    password = ...

Key endpoints
-------------
* ``GET /ws/token/generate``              — session token exchange
* ``GET /ws/incident/actions``            — incident list + actions
* ``GET /ws/incident/get``                — single incident detail
* ``GET /ws/spotter/index/search``        — Spotter SPL-like search
* ``GET /ws/sccresource/users``           — user risk profiles
* ``GET /ws/sccresource/policies``        — detection policies
* ``GET /ws/sccresource/violations``      — policy violations
* ``GET /ws/sccresource/threats``         — threat models / chains
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_SECURONIX = uuid.UUID("5ec710a1-0001-4a1e-9b1e-5ec710a1c0fe")


class SecuronixClient(BaseClient, ConnectorMixin):
    """HTTP client for Securonix Snypr / SNYPR."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/ws"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incident/actions",
        "user-account": "sccresource/users",
    }

    def __init__(
        self,
        host: str = "",
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SecuronixClient."""
        super().__init__(host=host, **kwargs)
        self.username = username
        self.password = password

    def authenticate(self) -> None:
        """Exchange username/password for a Securonix session token."""
        if not self.username or not self.password:
            raise GNATClientError(
                "Securonix connector requires username and password."
            )
        resp = self.get(
            "/ws/token/generate",
            params={"username": self.username, "password": self.password},
        )
        # Securonix returns the token either as a bare string or a dict
        token = ""
        if isinstance(resp, str):
            token = resp.strip().strip('"')
        elif isinstance(resp, dict):
            token = resp.get("token") or resp.get("access_token", "")
        if not token:
            raise GNATClientError(
                "Securonix authentication failed — empty token response"
            )
        self._auth_headers["token"] = token
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Call ``/ws/sccresource/users`` with a tiny limit as a liveness probe."""
        try:
            self.get("/ws/sccresource/users", params={"max": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Securonix record by id."""
        if not object_id:
            raise GNATClientError("Securonix get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(
                "/ws/incident/get", params={"incidentId": object_id}
            )
            kind = "incident"
        elif stix_type == "user-account":
            resp = self.get(f"/ws/sccresource/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(
                f"Securonix get_object does not support stix_type={stix_type!r}"
            )
        if isinstance(resp, dict):
            return dict(resp, _snx_kind=kind)
        if isinstance(resp, list) and resp:
            return dict(resp[0], _snx_kind=kind)
        raise GNATClientError(
            f"Securonix returned unexpected payload for {object_id!r}"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Securonix records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"max": int(page_size)}
        for key in ("query", "status", "from", "to"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "incidents").lower()
            if kind == "violations":
                resp = self.get(
                    "/ws/sccresource/violations", params=params
                )
                tag = "violation"
            elif kind == "threats":
                resp = self.get("/ws/sccresource/threats", params=params)
                tag = "threat"
            elif kind == "spotter":
                resp = self.get(
                    "/ws/spotter/index/search", params=params
                )
                tag = "spotter_hit"
            else:
                resp = self.get("/ws/incident/actions", params=params)
                tag = "incident"
        elif stix_type == "user-account":
            resp = self.get("/ws/sccresource/users", params=params)
            tag = "user"
        elif stix_type == "x-securonix-policy":
            resp = self.get("/ws/sccresource/policies", params=params)
            tag = "policy"
        else:
            raise GNATClientError(
                f"Securonix list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _snx_kind=tag) for r in _extract_securonix_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Securonix connector is read-only in Phase 2."""
        raise GNATClientError(
            "Securonix connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Securonix connector is read-only in Phase 2."""
        raise GNATClientError(
            "Securonix connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_incidents(
        self, status: str = "", since: str = ""
    ) -> list[dict[str, Any]]:
        """Return Securonix incidents."""
        filters: dict[str, Any] = {}
        if status:
            filters["status"] = status
        if since:
            filters["from"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single incident by id."""
        return self.get_object("observed-data", incident_id)

    def list_violations(self) -> list[dict[str, Any]]:
        """Return policy violations."""
        return self.list_objects(
            "observed-data", filters={"kind": "violations"}, page_size=500
        )

    def list_threats(self) -> list[dict[str, Any]]:
        """Return threat models / chains."""
        return self.list_objects(
            "observed-data", filters={"kind": "threats"}, page_size=500
        )

    def search_spotter(self, query: str) -> list[dict[str, Any]]:
        """Run a Spotter search (Securonix's SPL-like query language)."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "spotter", "query": query},
            page_size=1000,
        )

    def list_users(self) -> list[dict[str, Any]]:
        """Return user risk profiles."""
        return self.list_objects("user-account", page_size=500)

    def list_policies(self) -> list[dict[str, Any]]:
        """Return detection policies."""
        return self.list_objects("x-securonix-policy", page_size=500)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Securonix record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Securonix to_stix expects a dict input")

        kind = native.get("_snx_kind") or "incident"

        if kind == "user":
            user_id = native.get("userId") or native.get("username", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_SECURONIX, f"user-account|{user_id}"
            )
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": "2.1",
                "account_login": native.get("username") or native.get("userId"),
                "display_name": native.get("fullName") or native.get("firstName"),
                "account_type": "domain",
                "x_securonix": {
                    "risk_score": native.get("riskScore"),
                    "department": native.get("department"),
                    "title": native.get("title"),
                    "raw": native,
                },
            }

        if kind == "policy":
            pol_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_SECURONIX, f"x-securonix-policy|{pol_id}"
            )
            return {
                "type": "x-securonix-policy",
                "id": f"x-securonix-policy--{stix_uuid}",
                "spec_version": "2.1",
                "name": native.get("name") or str(pol_id),
                "enabled": native.get("enabled"),
                "x_securonix": {"raw": native},
            }

        # observed-data envelope
        refs: list[str] = []
        user = native.get("accountName") or native.get("username") or native.get("user")
        if isinstance(user, dict):
            user = user.get("username") or user.get("id")
        if user:
            user_uuid = uuid.uuid5(
                _NAMESPACE_SECURONIX, f"user-account|{user}"
            )
            refs.append(f"user-account--{user_uuid}")

        first = (
            native.get("generationtime")
            or native.get("eventTime")
            or native.get("createdAt")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="securonix",
            x_extensions={
                "securonix": {
                    "kind": kind,
                    "incident_id": native.get("id") or native.get("incidentId"),
                    "status": native.get("status"),
                    "priority": native.get("priority"),
                    "risk_score": native.get("riskScore"),
                    "category": native.get("category"),
                    "reason": native.get("reason") or native.get("description"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Securonix connector is read-only."""
        return {
            "note": (
                "Securonix connector is read-only. Use list_incidents, "
                "get_incident, list_violations, list_threats, "
                "search_spotter, list_users, or list_policies to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_securonix_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Securonix response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("items", "data", "results", "incidents", "violations", "threats", "users", "policies", "events"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    # Securonix sometimes wraps results in totalDocuments/items structure
    total = resp.get("totalDocuments")
    if isinstance(total, dict):
        events = total.get("events")
        if isinstance(events, list):
            return [r for r in events if isinstance(r, dict)]
    return []
