# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gurucul.client
==================================

Gurucul UEBA connector.

Authentication
--------------
Bearer token::

    [gurucul]
    host      = https://YOUR_TENANT.gurucul.com
    api_token = gurucul_...

Key endpoints
-------------
* ``GET /api/v1/incidents``             — UEBA incidents
* ``GET /api/v1/incidents/{id}``
* ``GET /api/v1/risk/users``            — user risk scores
* ``GET /api/v1/risk/entities``         — entity risk scores
* ``GET /api/v1/anomalies``             — detected anomalies
* ``GET /api/v1/models``                — active analytics models
* ``GET /api/v1/cases``                 — investigation cases
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_GURUCUL = uuid.UUID("90c0c019-0001-4a1e-9b1e-90c0c019c0fe")


class GuruculClient(BaseClient, ConnectorMixin):
    """HTTP client for Gurucul UEBA."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incidents",
        "user-account": "risk/users",
    }

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize GuruculClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    def authenticate(self) -> None:
        """Set Authorization: Bearer header."""
        if not self.api_token:
            raise GNATClientError("Gurucul connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query incidents with a tiny page as a liveness probe."""
        try:
            self.get("/api/v1/incidents", params={"size": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Gurucul record by id."""
        if not object_id:
            raise GNATClientError("Gurucul get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v1/incidents/{object_id}")
            kind = "incident"
        elif stix_type == "user-account":
            resp = self.get(f"/api/v1/risk/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(
                f"Gurucul get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Gurucul returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _gc_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Gurucul records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"size": int(page_size), "page": int(page)}
        for key in ("severity", "status", "since", "until", "model"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "incidents").lower()
            if kind == "anomalies":
                resp = self.get("/api/v1/anomalies", params=params)
                tag = "anomaly"
            elif kind == "cases":
                resp = self.get("/api/v1/cases", params=params)
                tag = "case"
            else:
                resp = self.get("/api/v1/incidents", params=params)
                tag = "incident"
        elif stix_type == "user-account":
            resp = self.get("/api/v1/risk/users", params=params)
            tag = "user"
        elif stix_type == "x-gurucul-entity":
            resp = self.get("/api/v1/risk/entities", params=params)
            tag = "entity"
        elif stix_type == "x-gurucul-model":
            resp = self.get("/api/v1/models", params=params)
            tag = "model"
        else:
            raise GNATClientError(
                f"Gurucul list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _gc_kind=tag) for r in _extract_gurucul_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Gurucul connector is read-only in Phase 2."""
        raise GNATClientError(
            "Gurucul connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Gurucul connector is read-only in Phase 2."""
        raise GNATClientError(
            "Gurucul connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_incidents(
        self, severity: str = "", since: str = ""
    ) -> list[dict[str, Any]]:
        """Return Gurucul UEBA incidents."""
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_anomalies(self, since: str = "") -> list[dict[str, Any]]:
        """Return detected behavioral anomalies."""
        filters: dict[str, Any] = {"kind": "anomalies"}
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def list_user_risk_scores(
        self, severity: str = ""
    ) -> list[dict[str, Any]]:
        """Return per-user risk scores."""
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        return self.list_objects("user-account", filters=filters, page_size=500)

    def list_entity_risk_scores(self) -> list[dict[str, Any]]:
        """Return non-user entity risk scores (hosts, apps, etc.)."""
        return self.list_objects("x-gurucul-entity", page_size=500)

    def list_models(self) -> list[dict[str, Any]]:
        """Return active UEBA analytics models."""
        return self.list_objects("x-gurucul-model", page_size=500)

    def list_cases(self) -> list[dict[str, Any]]:
        """Return investigation cases."""
        return self.list_objects(
            "observed-data", filters={"kind": "cases"}, page_size=500
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single incident by id."""
        return self.get_object("observed-data", incident_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Gurucul record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Gurucul to_stix expects a dict input")

        kind = native.get("_gc_kind") or "incident"

        if kind == "user":
            user_id = native.get("userId") or native.get("username", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_GURUCUL, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "account_login": native.get("username"),
                "display_name": native.get("displayName") or native.get("fullName"),
                "account_type": "domain",
                "x_gurucul": {
                    "user_id": user_id,
                    "risk_score": native.get("riskScore"),
                    "risk_level": native.get("riskLevel"),
                    "department": native.get("department"),
                    "raw": native,
                },
            }

        if kind == "entity":
            ent_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_GURUCUL, f"x-gurucul-entity|{ent_id}"
            )
            return {
                "type": "x-gurucul-entity",
                "id": f"x-gurucul-entity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(ent_id),
                "entity_type": native.get("type"),
                "risk_score": native.get("riskScore"),
                "x_gurucul": {"raw": native},
            }

        if kind == "model":
            model_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_GURUCUL, f"x-gurucul-model|{model_id}"
            )
            return {
                "type": "x-gurucul-model",
                "id": f"x-gurucul-model--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(model_id),
                "enabled": native.get("enabled"),
                "x_gurucul": {"raw": native},
            }

        # observed-data envelope (incident / anomaly / case)
        refs: list[str] = []
        user_id = native.get("userId") or native.get("username")
        if user_id:
            user_uuid = uuid.uuid5(_NAMESPACE_GURUCUL, f"user-account|{user_id}")
            refs.append(f"user-account--{user_uuid}")

        first = (
            native.get("timestamp")
            or native.get("createdAt")
            or native.get("eventTime")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="gurucul",
            x_extensions={
                "gurucul": {
                    "kind": kind,
                    "incident_id": native.get("id"),
                    "severity": native.get("severity"),
                    "risk_score": native.get("riskScore"),
                    "model": native.get("model") or native.get("modelName"),
                    "status": native.get("status"),
                    "title": native.get("title") or native.get("name"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Gurucul connector is read-only."""
        return {
            "note": (
                "Gurucul connector is read-only. Use list_incidents, "
                "list_anomalies, list_user_risk_scores, "
                "list_entity_risk_scores, list_models, list_cases, or "
                "get_incident to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_gurucul_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Gurucul response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "incidents", "users", "entities", "models"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
