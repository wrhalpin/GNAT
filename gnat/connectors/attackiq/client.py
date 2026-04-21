# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.attackiq.client
===================================

AttackIQ Security Optimization Platform / Flex connector.

Authentication
--------------
Token header::

    [attackiq]
    host      = https://gts.attackiq.com
    api_token = aiq_...

Key endpoints
-------------
* ``GET /api/v1/assessments/``
* ``GET /api/v1/assessments/{id}/``
* ``GET /api/v1/scenarios/``
* ``GET /api/v1/results/``
* ``GET /api/v1/phases/``
* ``GET /api/v1/tests/``

STIX Type Mapping
-----------------
* ``observed-data`` → assessment runs + result rows (wrapped via
  :func:`bas_simulation_envelope`)
* ``attack-pattern`` → AttackIQ scenarios (MITRE ATT&CK aligned)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_ATTACKIQ = uuid.UUID("a77ac719-0001-4a1e-9c1e-a77ac7190fed")


class AttackIQClient(BaseClient, ConnectorMixin):
    """HTTP client for AttackIQ."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "assessments",
        "attack-pattern": "scenarios",
    }

    def __init__(
        self,
        host: str = "https://gts.attackiq.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize AttackIQClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Token header."""
        if not self.api_token:
            raise GNATClientError("AttackIQ connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"Token {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the assessments list with a small page as a liveness probe."""
        try:
            self.get("/api/v1/assessments/", params={"page_size": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single AttackIQ record by id."""
        if not object_id:
            raise GNATClientError("AttackIQ get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v1/assessments/{object_id}/")
            kind = "assessment"
        elif stix_type == "attack-pattern":
            resp = self.get(f"/api/v1/scenarios/{object_id}/")
            kind = "scenario"
        else:
            raise GNATClientError(f"AttackIQ get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"AttackIQ returned unexpected payload for {object_id!r}")
        return dict(resp, _aiq_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List AttackIQ records; filters keys: kind, assessment_id."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "page_size": int(page_size)}
        kind = (filters.get("kind") or "").lower()
        if filters.get("assessment_id"):
            params["assessment_id"] = filters["assessment_id"]

        if stix_type == "observed-data":
            if kind == "results":
                resp = self.get("/api/v1/results/", params=params)
                tag = "result"
            elif kind == "phases":
                resp = self.get("/api/v1/phases/", params=params)
                tag = "phase"
            elif kind == "tests":
                resp = self.get("/api/v1/tests/", params=params)
                tag = "test"
            else:
                resp = self.get("/api/v1/assessments/", params=params)
                tag = "assessment"
        elif stix_type == "attack-pattern":
            resp = self.get("/api/v1/scenarios/", params=params)
            tag = "scenario"
        else:
            raise GNATClientError(f"AttackIQ list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _aiq_kind=tag) for r in _extract_aiq_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """AttackIQ connector is read-only."""
        raise GNATClientError("AttackIQ connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """AttackIQ connector is read-only."""
        raise GNATClientError("AttackIQ connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_assessments(self) -> list[dict[str, Any]]:
        """Return AttackIQ assessments."""
        return self.list_objects("observed-data", page_size=500)

    def list_results(self, assessment_id: str = "") -> list[dict[str, Any]]:
        """Return result rows, optionally filtered to an assessment."""
        filters: dict[str, Any] = {"kind": "results"}
        if assessment_id:
            filters["assessment_id"] = assessment_id
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def list_scenarios(self) -> list[dict[str, Any]]:
        """Return scenario catalog (MITRE-aligned attack-patterns)."""
        return self.list_objects("attack-pattern", page_size=1000)

    def get_assessment(self, assessment_id: str) -> dict[str, Any]:
        """Fetch a single assessment by id."""
        return self.get_object("observed-data", assessment_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an AttackIQ record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("AttackIQ to_stix expects a dict input")

        kind = native.get("_aiq_kind") or "assessment"

        if kind == "scenario":
            scenario_id = native.get("id") or native.get("name", "unknown")
            mitre = native.get("mitre_id") or native.get("mitre_technique", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_ATTACKIQ, f"attack-pattern|{scenario_id}")
            external_refs = []
            if mitre:
                external_refs.append({"source_name": "mitre-attack", "external_id": mitre})
            return {
                "type": "attack-pattern",
                "id": f"attack-pattern--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(scenario_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_attackiq": {"raw": native},
            }

        # assessment / result / phase / test → observed-data
        sim_id = str(native.get("id") or native.get("uuid", ""))
        targets = _values(
            native.get("assets") or native.get("target_assets") or native.get("hostname")
        )
        techniques = _values(
            native.get("mitre_techniques") or native.get("mitre_ids") or native.get("scenarios")
        )
        return bas_simulation_envelope(
            source_name="attackiq",
            simulation_id=sim_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("status") or native.get("result") or "",
            score=_as_float(native.get("score") or native.get("outcome_score")),
            first_observed=native.get("started_at") or native.get("created", ""),
            last_observed=native.get("finished_at") or native.get("modified", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """AttackIQ connector is read-only."""
        return {
            "note": (
                "AttackIQ connector is read-only. Use list_assessments, "
                "list_results, list_scenarios, or get_assessment to query "
                "the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_aiq_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an AttackIQ paginated response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("results", "data", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _values(container: Any) -> list[str]:
    """Normalize scalar / list / None into a list of strings."""
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
