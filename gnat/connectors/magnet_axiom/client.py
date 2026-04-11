# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.magnet_axiom.client
=======================================

Magnet AXIOM Cyber — remote forensic acquisition and DFIR.

Authentication
--------------
API key in the ``X-API-Key`` header (issued from the AXIOM Cyber
admin console)::

    [magnet_axiom]
    host    = https://axiom.example.com
    api_key = ax_...

Key endpoints
-------------
* ``GET  /api/v1/cases``                  — investigation cases
* ``GET  /api/v1/cases/{id}``
* ``POST /api/v1/cases``                  — create a case (write helper)
* ``GET  /api/v1/cases/{id}/evidence``    — evidence sources for a case
* ``GET  /api/v1/cases/{id}/artifacts``   — extracted artifacts
* ``GET  /api/v1/agents``                 — deployed AXIOM Cyber agents
* ``POST /api/v1/collections``            — start a remote collection
* ``GET  /api/v1/collections/{id}``
* ``GET  /api/v1/users``                  — examiner accounts
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_AXIOM = uuid.UUID("a4101055-0001-4a1e-9b1e-a4101055c0fe")


class MagnetAxiomClient(BaseClient, ConnectorMixin):
    """HTTP client for Magnet AXIOM Cyber."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 2

    stix_type_map: dict[str, str] = {
        "observed-data": "cases",
        "x-axiom-agent": "agents",
        "x-axiom-collection": "collections",
        "user-account": "users",
    }

    def __init__(
        self,
        host: str = "https://axiom.example.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize MagnetAxiomClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    def authenticate(self) -> None:
        """Set the X-API-Key header from the configured api_key."""
        if not self.api_key:
            raise GNATClientError(
                "Magnet AXIOM connector requires api_key in config."
            )
        self._auth_headers["X-API-Key"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query a tiny page of cases as a liveness probe."""
        try:
            self.get("/api/v1/cases", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single AXIOM record by id."""
        if not object_id:
            raise GNATClientError("Magnet AXIOM get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v1/cases/{object_id}")
            kind = "case"
        elif stix_type == "x-axiom-agent":
            resp = self.get(f"/api/v1/agents/{object_id}")
            kind = "agent"
        elif stix_type == "x-axiom-collection":
            resp = self.get(f"/api/v1/collections/{object_id}")
            kind = "collection"
        elif stix_type == "user-account":
            resp = self.get(f"/api/v1/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(
                f"Magnet AXIOM get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Magnet AXIOM returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _ax_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List AXIOM Cyber records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        for key in ("status", "case_id", "agent_id", "examiner"):
            if filters.get(key):
                params[key] = filters[key]
        kind = (filters.get("kind") or "").lower()

        if stix_type == "observed-data":
            if kind == "evidence":
                case_id = filters.get("case_id")
                if not case_id:
                    raise GNATClientError(
                        "Magnet AXIOM evidence listing requires 'case_id'"
                    )
                resp = self.get(
                    f"/api/v1/cases/{case_id}/evidence", params=params
                )
                tag = "evidence"
            elif kind == "artifacts":
                case_id = filters.get("case_id")
                if not case_id:
                    raise GNATClientError(
                        "Magnet AXIOM artifact listing requires 'case_id'"
                    )
                resp = self.get(
                    f"/api/v1/cases/{case_id}/artifacts", params=params
                )
                tag = "artifact"
            else:
                resp = self.get("/api/v1/cases", params=params)
                tag = "case"
        elif stix_type == "x-axiom-agent":
            resp = self.get("/api/v1/agents", params=params)
            tag = "agent"
        elif stix_type == "x-axiom-collection":
            resp = self.get("/api/v1/collections", params=params)
            tag = "collection"
        elif stix_type == "user-account":
            resp = self.get("/api/v1/users", params=params)
            tag = "user"
        else:
            raise GNATClientError(
                f"Magnet AXIOM list_objects does not support stix_type={stix_type!r}"
            )
        items = _extract_axiom_list(resp)
        return [dict(r, _ax_kind=tag) for r in items if isinstance(r, dict)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Magnet AXIOM connector is read-only via CRUD."""
        raise GNATClientError(
            "Magnet AXIOM connector is read-only via CRUD — use the "
            "create_case() or start_collection() domain helpers."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Magnet AXIOM connector is read-only."""
        raise GNATClientError(
            "Magnet AXIOM connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_cases(self, status: str = "") -> list[dict[str, Any]]:
        """Return investigation cases."""
        filters: dict[str, Any] = {}
        if status:
            filters["status"] = status
        return self.list_objects(
            "observed-data", filters=filters, page_size=500
        )

    def get_case(self, case_id: str) -> dict[str, Any]:
        """Fetch a single investigation case by id."""
        return self.get_object("observed-data", case_id)

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        """Return evidence sources attached to a case."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "evidence", "case_id": case_id},
            page_size=500,
        )

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        """Return extracted artifacts for a case."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "artifacts", "case_id": case_id},
            page_size=1000,
        )

    def list_agents(self) -> list[dict[str, Any]]:
        """Return deployed AXIOM Cyber agents."""
        return self.list_objects("x-axiom-agent", page_size=500)

    def list_collections(self) -> list[dict[str, Any]]:
        """Return remote-collection jobs."""
        return self.list_objects("x-axiom-collection", page_size=500)

    def list_users(self) -> list[dict[str, Any]]:
        """Return examiner / analyst accounts."""
        return self.list_objects("user-account", page_size=500)

    def create_case(
        self, name: str, description: str = "", examiner: str = ""
    ) -> dict[str, Any]:
        """Create a new investigation case."""
        body: dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        if examiner:
            body["examiner"] = examiner
        resp = self.post("/api/v1/cases", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    def start_collection(
        self,
        agent_id: str,
        case_id: str,
        artifacts: list[str] | None = None,
    ) -> dict[str, Any]:
        """Trigger a remote collection from an AXIOM Cyber agent."""
        body: dict[str, Any] = {
            "agent_id": agent_id,
            "case_id": case_id,
        }
        if artifacts:
            body["artifacts"] = list(artifacts)
        resp = self.post("/api/v1/collections", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Magnet AXIOM record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Magnet AXIOM to_stix expects a dict input")

        kind = native.get("_ax_kind") or "case"

        if kind == "agent":
            agent_id = native.get("id") or native.get("agent_id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_AXIOM, f"x-axiom-agent|{agent_id}")
            return {
                "type": "x-axiom-agent",
                "id": f"x-axiom-agent--{stix_uuid}",
                "spec_version": "2.1",
                "agent_id": agent_id,
                "hostname": native.get("hostname") or native.get("name"),
                "platform": native.get("platform") or native.get("os"),
                "status": native.get("status"),
                "x_axiom": {"raw": native},
            }

        if kind == "collection":
            col_id = native.get("id") or native.get("collection_id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_AXIOM, f"x-axiom-collection|{col_id}")
            return {
                "type": "x-axiom-collection",
                "id": f"x-axiom-collection--{stix_uuid}",
                "spec_version": "2.1",
                "collection_id": col_id,
                "case_id": native.get("case_id"),
                "agent_id": native.get("agent_id"),
                "status": native.get("status"),
                "started_at": native.get("started_at"),
                "x_axiom": {"raw": native},
            }

        if kind == "user":
            user_id = native.get("id") or native.get("username", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_AXIOM, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": "2.1",
                "account_login": native.get("username") or native.get("email"),
                "display_name": native.get("name") or native.get("displayName"),
                "account_type": "axiom_cyber",
                "x_axiom": {
                    "user_id": user_id,
                    "role": native.get("role"),
                    "raw": native,
                },
            }

        # case / evidence / artifact → observed-data envelope
        refs: list[str] = []
        examiner = native.get("examiner") or native.get("created_by")
        if examiner:
            ex_uuid = uuid.uuid5(_NAMESPACE_AXIOM, f"user-account|{examiner}")
            refs.append(f"user-account--{ex_uuid}")
        agent_id = native.get("agent_id")
        if agent_id:
            agent_uuid = uuid.uuid5(_NAMESPACE_AXIOM, f"x-axiom-agent|{agent_id}")
            refs.append(f"x-axiom-agent--{agent_uuid}")

        first = (
            native.get("created_at")
            or native.get("collected_at")
            or native.get("timestamp")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=native.get("updated_at") or first,
            number_observed=1,
            object_refs=refs,
            source_name="magnet_axiom",
            x_extensions={
                "magnet_axiom": {
                    "kind": kind,
                    "case_id": native.get("case_id") or native.get("id"),
                    "name": native.get("name") or native.get("title"),
                    "status": native.get("status"),
                    "examiner": examiner,
                    "artifact_type": native.get("artifact_type"),
                    "evidence_type": native.get("evidence_type"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Magnet AXIOM connector is read-only via CRUD."""
        return {
            "note": (
                "Magnet AXIOM connector is read-only via CRUD. Use "
                "list_cases, get_case, list_evidence, list_artifacts, "
                "list_agents, list_collections, list_users, create_case, "
                "or start_collection to interact with the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_axiom_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Magnet AXIOM response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "cases", "agents", "collections", "users", "evidence", "artifacts"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
