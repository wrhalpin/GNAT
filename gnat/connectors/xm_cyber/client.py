# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.xm_cyber.client
===================================

XM Cyber Attack Path Management (APM) connector.

Authentication
--------------
API key exchanged for a session bearer via ``/api/v2/auth/login``::

    [xm_cyber]
    host    = https://tenant.xmcyber.com
    api_key = xm_...

Key endpoints
-------------
* ``POST /api/v2/auth/login``           — exchange api_key for session
* ``GET  /api/v2/entities``             — discovered entities (hosts,
  users, cloud resources)
* ``GET  /api/v2/entities/{id}``
* ``GET  /api/v2/attack-paths``         — attack paths between entities
* ``GET  /api/v2/critical-assets``      — defined crown-jewel assets
* ``GET  /api/v2/techniques``           — techniques used in attack paths
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_XMCYBER = uuid.UUID("81c1bef0-0001-4a1e-9c1e-81c1bef0c0fe")


class XMCyberClient(BaseClient, ConnectorMixin):
    """HTTP client for XM Cyber APM."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api/v2"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "attack-paths",
        "identity": "entities",
        "attack-pattern": "techniques",
    }

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize XMCyberClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange the API key for a session bearer token."""
        if not self.api_key:
            raise GNATClientError("XM Cyber connector requires api_key in config.")
        resp = self.post("/api/v2/auth/login", json={"apiKey": self.api_key})
        token = ""
        if isinstance(resp, dict):
            token = (
                resp.get("token")
                or resp.get("access_token")
                or (resp.get("data") or {}).get("token")
                or ""
            )
        if not token:
            raise GNATClientError("XM Cyber authentication failed — no token in response")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/api/v2/entities`` as a liveness probe."""
        try:
            self.get("/api/v2/entities", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single XM Cyber record by id."""
        if not object_id:
            raise GNATClientError("XM Cyber get_object requires a non-empty id")
        if stix_type == "identity":
            resp = self.get(f"/api/v2/entities/{object_id}")
            kind = "entity"
        elif stix_type == "observed-data":
            resp = self.get(f"/api/v2/attack-paths/{object_id}")
            kind = "attack_path"
        elif stix_type == "attack-pattern":
            resp = self.get(f"/api/v2/techniques/{object_id}")
            kind = "technique"
        else:
            raise GNATClientError(f"XM Cyber get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"XM Cyber returned unexpected payload for {object_id!r}")
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        return dict(data, _xm_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List XM Cyber records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        kind = (filters.get("kind") or "").lower()

        if stix_type == "identity":
            if kind == "critical-assets":
                resp = self.get("/api/v2/critical-assets", params=params)
                tag = "critical_asset"
            else:
                resp = self.get("/api/v2/entities", params=params)
                tag = "entity"
        elif stix_type == "observed-data":
            resp = self.get("/api/v2/attack-paths", params=params)
            tag = "attack_path"
        elif stix_type == "attack-pattern":
            resp = self.get("/api/v2/techniques", params=params)
            tag = "technique"
        else:
            raise GNATClientError(f"XM Cyber list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _xm_kind=tag) for r in _extract_xm_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """XM Cyber connector is read-only."""
        raise GNATClientError("XM Cyber connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """XM Cyber connector is read-only."""
        raise GNATClientError("XM Cyber connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_entities(self) -> list[dict[str, Any]]:
        """Return discovered entities (hosts, users, cloud resources)."""
        return self.list_objects("identity", page_size=1000)

    def list_critical_assets(self) -> list[dict[str, Any]]:
        """Return crown-jewel assets defined in XM Cyber."""
        return self.list_objects("identity", filters={"kind": "critical-assets"}, page_size=1000)

    def list_attack_paths(self) -> list[dict[str, Any]]:
        """Return attack paths discovered between entities."""
        return self.list_objects("observed-data", page_size=1000)

    def list_techniques(self) -> list[dict[str, Any]]:
        """Return techniques referenced by attack paths."""
        return self.list_objects("attack-pattern", page_size=1000)

    def get_entity(self, entity_id: str) -> dict[str, Any]:
        """Fetch a single XM Cyber entity."""
        return self.get_object("identity", entity_id)

    def get_attack_path(self, path_id: str) -> dict[str, Any]:
        """Fetch a single attack path."""
        return self.get_object("observed-data", path_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an XM Cyber record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("XM Cyber to_stix expects a dict input")

        kind = native.get("_xm_kind") or "attack_path"

        if kind in ("entity", "critical_asset"):
            ent_id = native.get("id") or native.get("name", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_XMCYBER, f"identity|{ent_id}")
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(ent_id),
                "identity_class": _xm_identity_class(native),
                "description": native.get("description") or "",
                "x_xm_cyber": {
                    "entity_type": native.get("type"),
                    "is_critical": kind == "critical_asset" or native.get("isCritical"),
                    "compromise_score": native.get("compromiseScore"),
                    "raw": native,
                },
            }

        if kind == "technique":
            tech_id = native.get("id") or native.get("name", "unknown")
            mitre = native.get("mitreId") or native.get("mitreTechnique", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_XMCYBER, f"attack-pattern|{tech_id}")
            external_refs = []
            if mitre:
                external_refs.append({"source_name": "mitre-attack", "external_id": mitre})
            return {
                "type": "attack-pattern",
                "id": f"attack-pattern--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(tech_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_xm_cyber": {"raw": native},
            }

        # attack-path → observed-data envelope
        path_id = str(native.get("id") or native.get("pathId") or native.get("uuid", ""))
        targets = _values(
            native.get("targets")
            or native.get("destinationEntities")
            or native.get("criticalAssets")
        )
        techniques = _values(native.get("techniques") or native.get("mitreTechniques"))
        return bas_simulation_envelope(
            source_name="xm_cyber",
            simulation_id=path_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("status") or "discovered",
            score=_as_float(native.get("riskScore") or native.get("complexity")),
            first_observed=native.get("discoveredAt") or native.get("createdAt", ""),
            last_observed=native.get("lastSeen") or native.get("updatedAt", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """XM Cyber connector is read-only."""
        return {
            "note": (
                "XM Cyber connector is read-only. Use list_entities, "
                "list_critical_assets, list_attack_paths, list_techniques, "
                "get_entity, or get_attack_path to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_xm_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an XM Cyber response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "entities", "attackPaths", "techniques"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _xm_identity_class(native: dict[str, Any]) -> str:
    """Map XM Cyber entity type to STIX identity_class."""
    etype = (native.get("type") or native.get("entityType") or "").lower()
    if "user" in etype or "account" in etype:
        return "individual"
    if "group" in etype or "role" in etype:
        return "group"
    if "cloud" in etype or "service" in etype:
        return "system"
    return "system"


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
