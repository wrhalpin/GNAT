# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cymulate.client
===================================

Cymulate Continuous-Security-Validation connector.

Authentication
--------------
``x-token`` API key header::

    [cymulate]
    host    = https://api.app.cymulate.com
    api_key = cym_...

Key endpoints
-------------
* ``GET /v1/assessments``                  — assessment runs
* ``GET /v1/assessments/{id}``
* ``GET /v1/assessments/{id}/findings``
* ``GET /v1/templates``                    — attack templates
* ``GET /v1/technical-findings``           — all technical findings
* ``GET /v1/simulations``                  — simulations per vector
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_CYMULATE = uuid.UUID("c704a7e0-0001-4a1e-9c1e-c704a7e0c0fe")


class CymulateClient(BaseClient, ConnectorMixin):
    """HTTP client for Cymulate."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "assessments",
        "attack-pattern": "templates",
    }

    def __init__(
        self,
        host: str = "https://api.app.cymulate.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize CymulateClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set ``x-token`` header from the configured API key."""
        if not self.api_key:
            raise GNATClientError(
                "Cymulate connector requires api_key in config."
            )
        self._auth_headers["x-token"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/templates`` as a liveness probe."""
        try:
            self.get("/v1/templates", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Cymulate record by id."""
        if not object_id:
            raise GNATClientError("Cymulate get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/assessments/{object_id}")
            kind = "assessment"
        elif stix_type == "attack-pattern":
            resp = self.get(f"/v1/templates/{object_id}")
            kind = "template"
        else:
            raise GNATClientError(
                f"Cymulate get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Cymulate returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _cym_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Cymulate records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        kind = (filters.get("kind") or "assessments").lower()

        if stix_type == "observed-data":
            if kind == "findings":
                assessment_id = filters.get("assessment_id")
                if not assessment_id:
                    resp = self.get("/v1/technical-findings", params=params)
                else:
                    resp = self.get(
                        f"/v1/assessments/{assessment_id}/findings", params=params
                    )
                tag = "finding"
            elif kind == "simulations":
                resp = self.get("/v1/simulations", params=params)
                tag = "simulation"
            else:
                resp = self.get("/v1/assessments", params=params)
                tag = "assessment"
        elif stix_type == "attack-pattern":
            resp = self.get("/v1/templates", params=params)
            tag = "template"
        else:
            raise GNATClientError(
                f"Cymulate list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _cym_kind=tag) for r in _extract_cym_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Cymulate connector is read-only."""
        raise GNATClientError(
            "Cymulate connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Cymulate connector is read-only."""
        raise GNATClientError(
            "Cymulate connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_assessments(self) -> list[dict[str, Any]]:
        """Return Cymulate assessments."""
        return self.list_objects("observed-data", page_size=500)

    def list_findings(
        self, assessment_id: str = ""
    ) -> list[dict[str, Any]]:
        """Return technical findings, optionally scoped to an assessment."""
        filters: dict[str, Any] = {"kind": "findings"}
        if assessment_id:
            filters["assessment_id"] = assessment_id
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def list_templates(self) -> list[dict[str, Any]]:
        """Return attack templates (MITRE-aligned)."""
        return self.list_objects("attack-pattern", page_size=1000)

    def list_simulations(self) -> list[dict[str, Any]]:
        """Return individual simulations."""
        return self.list_objects(
            "observed-data", filters={"kind": "simulations"}, page_size=1000
        )

    def get_assessment(self, assessment_id: str) -> dict[str, Any]:
        """Fetch a single assessment."""
        return self.get_object("observed-data", assessment_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Cymulate record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Cymulate to_stix expects a dict input")

        kind = native.get("_cym_kind") or "assessment"

        if kind == "template":
            tpl_id = native.get("id") or native.get("templateId", "unknown")
            mitre = native.get("mitreTechnique") or native.get("mitre_id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_CYMULATE, f"attack-pattern|{tpl_id}")
            external_refs = []
            if mitre:
                external_refs.append(
                    {"source_name": "mitre-attack", "external_id": mitre}
                )
            return {
                "type": "attack-pattern",
                "id": f"attack-pattern--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(tpl_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_cymulate": {"raw": native},
            }

        # assessment / finding / simulation → observed-data
        sim_id = str(
            native.get("id") or native.get("assessmentId") or native.get("runId", "")
        )
        targets = _values(
            native.get("targets") or native.get("endpoints") or native.get("agents")
        )
        techniques = _values(
            native.get("mitreTechniques") or native.get("techniques")
        )
        return bas_simulation_envelope(
            source_name="cymulate",
            simulation_id=sim_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("result") or native.get("status", ""),
            score=_as_float(native.get("riskScore") or native.get("score")),
            first_observed=native.get("startTime") or native.get("createdAt", ""),
            last_observed=native.get("endTime") or native.get("updatedAt", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Cymulate connector is read-only."""
        return {
            "note": (
                "Cymulate connector is read-only. Use list_assessments, "
                "list_findings, list_templates, list_simulations, or "
                "get_assessment to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_cym_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Cymulate response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "assessments", "findings", "templates", "simulations"):
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
