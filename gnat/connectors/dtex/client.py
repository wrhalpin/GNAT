# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dtex.client
===============================

DTEX InTERCEPT connector — behavioral analytics for insider threat.

Authentication
--------------
Bearer token::

    [dtex]
    host      = https://api.dtexsystems.com
    api_token = dtex_...

Key endpoints
-------------
* ``GET /v1/alerts``             — behavioral alerts
* ``GET /v1/alerts/{id}``
* ``GET /v1/incidents``          — investigation workflow
* ``GET /v1/users``              — user behavioral profiles
* ``GET /v1/activities``         — raw activity stream
* ``GET /v1/policies``           — detection policies
* ``GET /v1/risk-factors``       — configured risk factors
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_DTEX = uuid.UUID("d7e1c700-0001-4a1e-9b1e-d7e1c700c0fe")


class DTEXClient(BaseClient, ConnectorMixin):
    """HTTP client for DTEX InTERCEPT."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "alerts",
        "user-account": "users",
    }

    def __init__(
        self,
        host: str = "https://api.dtexsystems.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize DTEXClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    def authenticate(self) -> None:
        """Set Authorization: Bearer header."""
        if not self.api_token:
            raise GNATClientError("DTEX connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query alerts with a small page as a liveness probe."""
        try:
            self.get("/v1/alerts", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single DTEX record by id."""
        if not object_id:
            raise GNATClientError("DTEX get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/alerts/{object_id}")
            kind = "alert"
        elif stix_type == "user-account":
            resp = self.get(f"/v1/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(f"DTEX get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"DTEX returned unexpected payload for {object_id!r}")
        return dict(resp, _dtex_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List DTEX records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        for key in ("severity", "status", "since", "until", "user"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "alerts").lower()
            if kind == "incidents":
                resp = self.get("/v1/incidents", params=params)
                tag = "incident"
            elif kind == "activities":
                resp = self.get("/v1/activities", params=params)
                tag = "activity"
            else:
                resp = self.get("/v1/alerts", params=params)
                tag = "alert"
        elif stix_type == "user-account":
            resp = self.get("/v1/users", params=params)
            tag = "user"
        elif stix_type == "x-dtex-policy":
            resp = self.get("/v1/policies", params=params)
            tag = "policy"
        elif stix_type == "x-dtex-risk-factor":
            resp = self.get("/v1/risk-factors", params=params)
            tag = "risk_factor"
        else:
            raise GNATClientError(f"DTEX list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _dtex_kind=tag) for r in _extract_dtex_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """DTEX connector is read-only in Phase 2."""
        raise GNATClientError("DTEX connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """DTEX connector is read-only in Phase 2."""
        raise GNATClientError("DTEX connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_alerts(self, severity: str = "", since: str = "") -> list[dict[str, Any]]:
        """Return behavioral alerts."""
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_incidents(self) -> list[dict[str, Any]]:
        """Return investigation workflow incidents."""
        return self.list_objects("observed-data", filters={"kind": "incidents"}, page_size=500)

    def list_activities(self, user: str = "", since: str = "") -> list[dict[str, Any]]:
        """Return raw user-activity stream."""
        filters: dict[str, Any] = {"kind": "activities"}
        if user:
            filters["user"] = user
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def list_users(self) -> list[dict[str, Any]]:
        """Return DTEX user behavioral profiles."""
        return self.list_objects("user-account", page_size=500)

    def list_policies(self) -> list[dict[str, Any]]:
        """Return detection policies."""
        return self.list_objects("x-dtex-policy", page_size=500)

    def list_risk_factors(self) -> list[dict[str, Any]]:
        """Return configured risk factors."""
        return self.list_objects("x-dtex-risk-factor", page_size=500)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch a single alert by id."""
        return self.get_object("observed-data", alert_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a DTEX record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("DTEX to_stix expects a dict input")

        kind = native.get("_dtex_kind") or "alert"

        if kind == "user":
            user_id = native.get("id") or native.get("username", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_DTEX, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "account_login": native.get("username"),
                "display_name": native.get("displayName") or native.get("fullName"),
                "account_type": "domain",
                "x_dtex": {
                    "user_id": user_id,
                    "department": native.get("department"),
                    "risk_score": native.get("riskScore"),
                    "risk_level": native.get("riskLevel"),
                    "raw": native,
                },
            }

        if kind == "policy":
            pol_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_DTEX, f"x-dtex-policy|{pol_id}")
            return {
                "type": "x-dtex-policy",
                "id": f"x-dtex-policy--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(pol_id),
                "severity": native.get("severity"),
                "enabled": native.get("enabled"),
                "x_dtex": {"raw": native},
            }

        if kind == "risk_factor":
            rf_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_DTEX, f"x-dtex-risk-factor|{rf_id}")
            return {
                "type": "x-dtex-risk-factor",
                "id": f"x-dtex-risk-factor--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(rf_id),
                "weight": native.get("weight"),
                "x_dtex": {"raw": native},
            }

        # observed-data envelope (alert / incident / activity)
        refs: list[str] = []
        user = native.get("user") or native.get("username") or native.get("userId")
        if isinstance(user, dict):
            user = user.get("id") or user.get("username")
        if user:
            user_uuid = uuid.uuid5(_NAMESPACE_DTEX, f"user-account|{user}")
            refs.append(f"user-account--{user_uuid}")

        first = (
            native.get("timestamp")
            or native.get("eventTime")
            or native.get("createdAt")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="dtex",
            x_extensions={
                "dtex": {
                    "kind": kind,
                    "event_id": native.get("id"),
                    "severity": native.get("severity"),
                    "risk_score": native.get("riskScore"),
                    "risk_factor": native.get("riskFactor"),
                    "category": native.get("category"),
                    "title": native.get("title") or native.get("description"),
                    "status": native.get("status"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """DTEX connector is read-only."""
        return {
            "note": (
                "DTEX connector is read-only. Use list_alerts, "
                "list_incidents, list_activities, list_users, "
                "list_policies, list_risk_factors, or get_alert to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_dtex_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a DTEX response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "alerts", "incidents", "users"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
