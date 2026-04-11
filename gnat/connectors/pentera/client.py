# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.pentera.client
==================================

Pentera automated security validation connector.

Authentication
--------------
Bearer JWT token (tenant-issued)::

    [pentera]
    host      = https://tenant.pentera.io
    api_token = pentera_jwt_...

Key endpoints
-------------
* ``GET /api/v1/tasks``             — penetration-test tasks
* ``GET /api/v1/tasks/{id}``
* ``GET /api/v1/findings``          — vulnerabilities + attack achievements
* ``GET /api/v1/assets``            — discovered assets
* ``GET /api/v1/techniques``        — attack techniques used
* ``GET /api/v1/achievements``      — successful exploit paths
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_PENTERA = uuid.UUID("9e072e7a-0001-4a1e-9c1e-9e072e7ac0fe")


class PenteraClient(BaseClient, ConnectorMixin):
    """HTTP client for Pentera."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "tasks",
        "attack-pattern": "techniques",
        "vulnerability": "findings",
    }

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize PenteraClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header."""
        if not self.api_token:
            raise GNATClientError(
                "Pentera connector requires api_token in config."
            )
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/api/v1/tasks`` with a small page as a liveness probe."""
        try:
            self.get("/api/v1/tasks", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Pentera record by id."""
        if not object_id:
            raise GNATClientError("Pentera get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v1/tasks/{object_id}")
            kind = "task"
        elif stix_type == "vulnerability":
            resp = self.get(f"/api/v1/findings/{object_id}")
            kind = "finding"
        elif stix_type == "attack-pattern":
            resp = self.get(f"/api/v1/techniques/{object_id}")
            kind = "technique"
        else:
            raise GNATClientError(
                f"Pentera get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Pentera returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _pnt_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Pentera records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        kind = (filters.get("kind") or "").lower()

        if stix_type == "observed-data":
            if kind == "achievements":
                resp = self.get("/api/v1/achievements", params=params)
                tag = "achievement"
            elif kind == "assets":
                resp = self.get("/api/v1/assets", params=params)
                tag = "asset"
            else:
                resp = self.get("/api/v1/tasks", params=params)
                tag = "task"
        elif stix_type == "vulnerability":
            resp = self.get("/api/v1/findings", params=params)
            tag = "finding"
        elif stix_type == "attack-pattern":
            resp = self.get("/api/v1/techniques", params=params)
            tag = "technique"
        else:
            raise GNATClientError(
                f"Pentera list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _pnt_kind=tag) for r in _extract_pentera_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Pentera connector is read-only."""
        raise GNATClientError(
            "Pentera connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Pentera connector is read-only."""
        raise GNATClientError(
            "Pentera connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_tasks(self) -> list[dict[str, Any]]:
        """Return Pentera pentest tasks."""
        return self.list_objects("observed-data", page_size=1000)

    def list_findings(self) -> list[dict[str, Any]]:
        """Return Pentera findings (vulnerabilities + achievements)."""
        return self.list_objects("vulnerability", page_size=1000)

    def list_assets(self) -> list[dict[str, Any]]:
        """Return discovered assets."""
        return self.list_objects(
            "observed-data", filters={"kind": "assets"}, page_size=1000
        )

    def list_achievements(self) -> list[dict[str, Any]]:
        """Return successful exploit achievements."""
        return self.list_objects(
            "observed-data", filters={"kind": "achievements"}, page_size=1000
        )

    def list_techniques(self) -> list[dict[str, Any]]:
        """Return Pentera attack techniques."""
        return self.list_objects("attack-pattern", page_size=1000)

    def get_task(self, task_id: str) -> dict[str, Any]:
        """Fetch a single Pentera task."""
        return self.get_object("observed-data", task_id)

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        """Fetch a single finding."""
        return self.get_object("vulnerability", finding_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Pentera record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Pentera to_stix expects a dict input")

        kind = native.get("_pnt_kind") or "task"

        if kind == "technique":
            tech_id = native.get("id") or native.get("name", "unknown")
            mitre = native.get("mitreId") or native.get("mitre_technique", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_PENTERA, f"attack-pattern|{tech_id}")
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
                "name": native.get("name") or str(tech_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_pentera": {"raw": native},
            }

        if kind == "finding":
            finding_id = native.get("id") or native.get("findingId", "unknown")
            cve = native.get("cve") or native.get("cveId", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_PENTERA, f"vulnerability|{finding_id}")
            external_refs: list[dict[str, Any]] = []
            if cve:
                external_refs.append({"source_name": "cve", "external_id": cve})
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": cve or native.get("name") or str(finding_id),
                "description": native.get("description") or native.get("summary", ""),
                "external_references": external_refs,
                "x_pentera": {
                    "severity": native.get("severity"),
                    "exploitable": native.get("exploitable"),
                    "assets_affected": native.get("assets") or [],
                    "raw": native,
                },
            }

        # task / asset / achievement → observed-data envelope
        sim_id = str(
            native.get("id") or native.get("taskId") or native.get("achievementId", "")
        )
        targets = _values(
            native.get("targets") or native.get("assets") or native.get("hostnames")
        )
        techniques = _values(
            native.get("techniques") or native.get("mitreTechniques")
        )
        return bas_simulation_envelope(
            source_name="pentera",
            simulation_id=sim_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("status") or native.get("result", ""),
            score=_as_float(native.get("riskScore") or native.get("severity")),
            first_observed=native.get("startTime") or native.get("createdAt", ""),
            last_observed=native.get("endTime") or native.get("completedAt", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Pentera connector is read-only."""
        return {
            "note": (
                "Pentera connector is read-only. Use list_tasks, "
                "list_findings, list_assets, list_achievements, "
                "list_techniques, get_task, or get_finding to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_pentera_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Pentera response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "items", "results", "tasks", "findings", "techniques", "assets", "achievements"):
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
