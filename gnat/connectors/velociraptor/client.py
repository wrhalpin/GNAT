# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.velociraptor.client
=======================================

Velociraptor — open-source endpoint visibility and DFIR collection.

Velociraptor is primarily controlled by VQL (Velociraptor Query
Language) executed via the gRPC API. The OSS server also exposes a
REST/gRPC-Web bridge at ``/api/v1/`` which this connector wraps for
the most common DFIR operations.

Authentication
--------------
Velociraptor uses **mTLS** by default — the configuration generator
issues an admin client certificate that must be presented on every
call. For HTTP environments behind a reverse proxy, an API key /
Bearer token may also be configured. The connector supports both::

    [velociraptor]
    host        = https://velociraptor.example.com:8000
    api_token   = vr_admin_token            # for proxied deployments
    cert_path   = /etc/gnat/vr-admin.pem    # for mTLS deployments
    key_path    = /etc/gnat/vr-admin.key

Key endpoints
-------------
* ``GET  /api/v1/clients``            — enumerated agents
* ``GET  /api/v1/clients/{client_id}``
* ``POST /api/v1/vql``                — execute a VQL query
* ``GET  /api/v1/hunts``              — running / completed hunts
* ``GET  /api/v1/hunts/{hunt_id}``
* ``POST /api/v1/hunts``              — create a new hunt
* ``GET  /api/v1/flows/{client_id}``  — collected flows for an agent
* ``GET  /api/v1/artifacts``          — artifact catalog

The connector is read-only via CRUD; ``run_hunt`` and ``run_vql`` are
exposed as domain helpers, not as ``upsert_object``.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_VR = uuid.UUID("0e10c1a7-0001-4a1e-9b1e-0e10c1a7c0fe")


class VelociraptorClient(BaseClient, ConnectorMixin):
    """HTTP client for Velociraptor DFIR server."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "flows",
        "x-velociraptor-client": "clients",
        "x-velociraptor-hunt": "hunts",
        "x-velociraptor-artifact": "artifacts",
    }

    def __init__(
        self,
        host: str = "https://velociraptor.example.com:8000",
        api_token: str = "",
        cert_path: str = "",
        key_path: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize VelociraptorClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token
        self.cert_path = cert_path
        self.key_path = key_path

    def authenticate(self) -> None:
        """Set Bearer header (or rely on mTLS via cert/key paths)."""
        if not self.api_token and not (self.cert_path and self.key_path):
            raise GNATClientError(
                "Velociraptor connector requires either api_token or "
                "cert_path + key_path."
            )
        if self.api_token:
            self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query the artifact catalog as a liveness probe."""
        try:
            self.get("/api/v1/artifacts", params={"count": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Velociraptor record by id."""
        if not object_id:
            raise GNATClientError("Velociraptor get_object requires a non-empty id")
        if stix_type == "x-velociraptor-client":
            resp = self.get(f"/api/v1/clients/{object_id}")
            kind = "client"
        elif stix_type == "x-velociraptor-hunt":
            resp = self.get(f"/api/v1/hunts/{object_id}")
            kind = "hunt"
        elif stix_type == "observed-data":
            resp = self.get(f"/api/v1/flows/{object_id}")
            kind = "flow"
        else:
            raise GNATClientError(
                f"Velociraptor get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Velociraptor returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _vr_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Velociraptor records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"count": int(page_size), "offset": int((page - 1) * page_size)}
        for key in ("query", "search", "labels", "client_id"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "x-velociraptor-client":
            resp = self.get("/api/v1/clients", params=params)
            items = resp.get("items", []) if isinstance(resp, dict) else []
            tag = "client"
        elif stix_type == "x-velociraptor-hunt":
            resp = self.get("/api/v1/hunts", params=params)
            items = resp.get("items", []) if isinstance(resp, dict) else []
            tag = "hunt"
        elif stix_type == "x-velociraptor-artifact":
            resp = self.get("/api/v1/artifacts", params=params)
            items = (
                resp.get("items", [])
                if isinstance(resp, dict)
                else (resp if isinstance(resp, list) else [])
            )
            tag = "artifact"
        elif stix_type == "observed-data":
            client_id = filters.get("client_id")
            if not client_id:
                raise GNATClientError(
                    "Velociraptor flow listing requires a 'client_id' filter"
                )
            resp = self.get(f"/api/v1/flows/{client_id}", params=params)
            items = resp.get("items", []) if isinstance(resp, dict) else []
            tag = "flow"
        else:
            raise GNATClientError(
                f"Velociraptor list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _vr_kind=tag) for r in items if isinstance(r, dict)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Velociraptor connector is read-only via CRUD."""
        raise GNATClientError(
            "Velociraptor connector is read-only via CRUD — use the "
            "run_hunt() or run_vql() domain helpers to write."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Velociraptor connector is read-only."""
        raise GNATClientError(
            "Velociraptor connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_clients(
        self, search: str = "", labels: str = ""
    ) -> list[dict[str, Any]]:
        """Return all enrolled Velociraptor agents."""
        filters: dict[str, Any] = {}
        if search:
            filters["search"] = search
        if labels:
            filters["labels"] = labels
        return self.list_objects(
            "x-velociraptor-client", filters=filters, page_size=500
        )

    def get_client(self, client_id: str) -> dict[str, Any]:
        """Fetch a single agent by id."""
        return self.get_object("x-velociraptor-client", client_id)

    def list_hunts(self) -> list[dict[str, Any]]:
        """Return running and completed hunts."""
        return self.list_objects("x-velociraptor-hunt", page_size=500)

    def get_hunt(self, hunt_id: str) -> dict[str, Any]:
        """Fetch a single hunt by id."""
        return self.get_object("x-velociraptor-hunt", hunt_id)

    def list_flows(self, client_id: str) -> list[dict[str, Any]]:
        """Return collected flows for a single agent."""
        return self.list_objects(
            "observed-data", filters={"client_id": client_id}, page_size=500
        )

    def list_artifacts(self) -> list[dict[str, Any]]:
        """Return the artifact catalog."""
        return self.list_objects("x-velociraptor-artifact", page_size=1000)

    def run_vql(self, vql: str) -> dict[str, Any]:
        """Execute an arbitrary VQL query."""
        if not vql:
            raise GNATClientError("Velociraptor run_vql requires a query string")
        resp = self.post("/api/v1/vql", json={"Query": [{"Name": "GNAT", "VQL": vql}]})
        return resp if isinstance(resp, dict) else {"raw": resp}

    def run_hunt(
        self,
        artifact: str,
        clients: list[str] | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        """Create and start a hunt for an artifact."""
        body: dict[str, Any] = {
            "artifact": artifact,
            "description": description or f"GNAT hunt: {artifact}",
        }
        if clients:
            body["client_ids"] = list(clients)
        resp = self.post("/api/v1/hunts", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Velociraptor record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Velociraptor to_stix expects a dict input")

        kind = native.get("_vr_kind") or "client"

        if kind == "client":
            client_id = native.get("client_id") or native.get("id", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_VR, f"x-velociraptor-client|{client_id}"
            )
            return {
                "type": "x-velociraptor-client",
                "id": f"x-velociraptor-client--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "client_id": client_id,
                "hostname": native.get("os_info", {}).get("hostname")
                if isinstance(native.get("os_info"), dict)
                else native.get("hostname"),
                "platform": native.get("os_info", {}).get("system")
                if isinstance(native.get("os_info"), dict)
                else native.get("platform"),
                "labels": native.get("labels") or [],
                "x_velociraptor": {"raw": native},
            }

        if kind == "hunt":
            hunt_id = native.get("hunt_id") or native.get("id", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_VR, f"x-velociraptor-hunt|{hunt_id}"
            )
            return {
                "type": "x-velociraptor-hunt",
                "id": f"x-velociraptor-hunt--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "hunt_id": hunt_id,
                "state": native.get("state"),
                "creator": native.get("creator"),
                "artifact": native.get("artifacts", [None])[0]
                if isinstance(native.get("artifacts"), list)
                else native.get("artifact"),
                "client_count": native.get("client_count"),
                "x_velociraptor": {"raw": native},
            }

        if kind == "artifact":
            name = native.get("name") or native.get("artifact", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_VR, f"x-velociraptor-artifact|{name}"
            )
            return {
                "type": "x-velociraptor-artifact",
                "id": f"x-velociraptor-artifact--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": name,
                "description": native.get("description"),
                "x_velociraptor": {"raw": native},
            }

        # flow → observed-data envelope
        refs: list[str] = []
        client_id = native.get("client_id") or native.get("ClientId")
        if client_id:
            client_uuid = uuid.uuid5(
                _NAMESPACE_VR, f"x-velociraptor-client|{client_id}"
            )
            refs.append(f"x-velociraptor-client--{client_uuid}")
        first = (
            native.get("create_time")
            or native.get("active_time")
            or native.get("timestamp")
            or utcnow()
        )
        return make_observed_data_envelope(
            first_observed=first,
            last_observed=native.get("active_time") or first,
            number_observed=1,
            object_refs=refs,
            source_name="velociraptor",
            x_extensions={
                "velociraptor": {
                    "session_id": native.get("session_id") or native.get("id"),
                    "artifacts": native.get("artifacts") or [],
                    "state": native.get("state"),
                    "client_id": client_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Velociraptor connector is read-only via CRUD."""
        return {
            "note": (
                "Velociraptor connector is read-only via CRUD. Use "
                "list_clients, get_client, list_hunts, get_hunt, list_flows, "
                "list_artifacts, run_vql, or run_hunt to interact."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
