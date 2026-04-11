# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.picus.client
================================

Picus Security Validation Platform connector.

Authentication
--------------
Refresh token exchanged for a Bearer token on first request::

    [picus]
    host          = https://api.picussecurity.com
    refresh_token = picus_refresh_...

Key endpoints
-------------
* ``POST /v1/refresh-token``    — exchange refresh token for access token
* ``GET  /v1/attacks``          — Picus attack catalog (threat library)
* ``GET  /v1/simulations``      — simulation runs
* ``GET  /v1/simulations/{id}``
* ``GET  /v1/results``          — per-simulation results
* ``GET  /v1/threat-library``   — curated threat library entries
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_PICUS = uuid.UUID("91cc55e1-0001-4a1e-9c1e-91cc55e1cafe")


class PicusClient(BaseClient, ConnectorMixin):
    """HTTP client for Picus Security."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "simulations",
        "attack-pattern": "attacks",
    }

    def __init__(
        self,
        host: str = "https://api.picussecurity.com",
        refresh_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize PicusClient."""
        super().__init__(host=host, **kwargs)
        self.refresh_token = refresh_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange the refresh token for an access token."""
        if not self.refresh_token:
            raise GNATClientError(
                "Picus connector requires refresh_token in config."
            )
        resp = self.post(
            "/v1/refresh-token", json={"refresh_token": self.refresh_token}
        )
        token = ""
        if isinstance(resp, dict):
            token = (
                resp.get("access_token")
                or resp.get("token")
                or (resp.get("data") or {}).get("access_token")
                or ""
            )
        if not token:
            raise GNATClientError(
                "Picus authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/v1/attacks`` as a liveness probe."""
        try:
            self.get("/v1/attacks", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Picus resource by id."""
        if not object_id:
            raise GNATClientError("Picus get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/simulations/{object_id}")
            kind = "simulation"
        elif stix_type == "attack-pattern":
            resp = self.get(f"/v1/attacks/{object_id}")
            kind = "attack"
        else:
            raise GNATClientError(
                f"Picus get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Picus returned unexpected payload for {object_id!r}"
            )
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        return dict(data, _pc_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Picus records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        kind = (filters.get("kind") or "simulations").lower()

        if stix_type == "observed-data":
            if kind == "results":
                resp = self.get("/v1/results", params=params)
                tag = "result"
            elif kind == "threat-library":
                resp = self.get("/v1/threat-library", params=params)
                tag = "threat"
            else:
                resp = self.get("/v1/simulations", params=params)
                tag = "simulation"
        elif stix_type == "attack-pattern":
            resp = self.get("/v1/attacks", params=params)
            tag = "attack"
        else:
            raise GNATClientError(
                f"Picus list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _pc_kind=tag) for r in _extract_picus_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Picus connector is read-only."""
        raise GNATClientError(
            "Picus connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Picus connector is read-only."""
        raise GNATClientError(
            "Picus connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_attacks(self) -> list[dict[str, Any]]:
        """Return the Picus attack catalog (MITRE ATT&CK-aligned)."""
        return self.list_objects("attack-pattern", page_size=1000)

    def list_simulations(self) -> list[dict[str, Any]]:
        """Return simulation runs."""
        return self.list_objects("observed-data", page_size=1000)

    def list_results(self) -> list[dict[str, Any]]:
        """Return per-simulation results."""
        return self.list_objects(
            "observed-data", filters={"kind": "results"}, page_size=1000
        )

    def list_threat_library(self) -> list[dict[str, Any]]:
        """Return Picus's curated threat library entries."""
        return self.list_objects(
            "observed-data", filters={"kind": "threat-library"}, page_size=1000
        )

    def get_simulation(self, simulation_id: str) -> dict[str, Any]:
        """Fetch a single simulation run."""
        return self.get_object("observed-data", simulation_id)

    def get_attack(self, attack_id: str) -> dict[str, Any]:
        """Fetch a single attack catalog entry."""
        return self.get_object("attack-pattern", attack_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Picus record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Picus to_stix expects a dict input")

        kind = native.get("_pc_kind") or "simulation"

        if kind == "attack":
            atk_id = native.get("id") or native.get("attackId", "unknown")
            mitre = native.get("mitreTechnique") or native.get("mitre_id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_PICUS, f"attack-pattern|{atk_id}")
            external_refs = []
            if mitre:
                external_refs.append(
                    {"source_name": "mitre-attack", "external_id": mitre}
                )
            return {
                "type": "attack-pattern",
                "id": f"attack-pattern--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(atk_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_picus": {"raw": native},
            }

        sim_id = str(
            native.get("id") or native.get("simulationId") or native.get("resultId", "")
        )
        targets = _values(
            native.get("agents") or native.get("targets") or native.get("endpoints")
        )
        techniques = _values(
            native.get("mitreTechniques") or native.get("techniques")
        )
        return bas_simulation_envelope(
            source_name="picus",
            simulation_id=sim_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("result") or native.get("status", ""),
            score=_as_float(native.get("effectivenessScore") or native.get("score")),
            first_observed=native.get("startDate") or native.get("createdAt", ""),
            last_observed=native.get("endDate") or native.get("updatedAt", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Picus connector is read-only."""
        return {
            "note": (
                "Picus connector is read-only. Use list_attacks, "
                "list_simulations, list_results, list_threat_library, "
                "get_simulation, or get_attack to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_picus_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Picus response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    for key in ("results", "items", "attacks", "simulations", "threats"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _values(container: Any) -> list[str]:
    """Normalize scalar / list into a list of strings."""
    if container is None:
        return []
    if isinstance(container, list):
        out: list[str] = []
        for item in container:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                val = item.get("name") or item.get("id") or item.get("hostname")
                if isinstance(val, str):
                    out.append(val)
        return out
    if isinstance(container, str):
        return [container]
    return []


def _as_float(value: Any) -> float | None:
    """Safely cast *value* to float."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
