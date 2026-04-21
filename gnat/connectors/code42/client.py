# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.code42.client
=================================

Code42 Incydr connector — file-exfiltration-focused insider risk.

Authentication
--------------
OAuth2 client credentials against ``/v1/oauth`` (basic-auth of
api_client_id:api_client_secret), returns a short-lived Bearer token::

    [code42]
    host              = https://api.us.code42.com
    api_client_id     = key-...
    api_client_secret = ...

Key endpoints
-------------
* ``POST /v1/oauth``                — token exchange
* ``POST /v2/file-events``          — file-event search
* ``GET  /v1/alerts/search``        — Incydr alerts
* ``GET  /v1/cases``                — investigation cases
* ``GET  /v1/cases/{id}``
* ``GET  /v2/users``                — user directory
* ``GET  /v1/user-risk-profiles``   — per-user risk posture
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_CODE42 = uuid.UUID("c0de4200-0001-4a1e-9b1e-c0de4200c0fe")


class Code42Client(BaseClient, ConnectorMixin):
    """HTTP client for Code42 Incydr."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/v2"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "file-events",
        "user-account": "users",
    }

    def __init__(
        self,
        host: str = "https://api.us.code42.com",
        api_client_id: str = "",
        api_client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize Code42Client."""
        super().__init__(host=host, **kwargs)
        self.api_client_id = api_client_id
        self.api_client_secret = api_client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange client credentials for a Bearer token."""
        if not self.api_client_id or not self.api_client_secret:
            raise GNATClientError("Code42 connector requires api_client_id and api_client_secret.")
        # Use a plain POST with Basic auth on the /v1/oauth endpoint
        self._auth_headers["Authorization"] = self._basic_auth(
            self.api_client_id, self.api_client_secret
        )
        resp = self.post("/v1/oauth", data={"grant_type": "client_credentials"})
        token = ""
        if isinstance(resp, dict):
            token = resp.get("access_token") or resp.get("token", "")
        if not token:
            raise GNATClientError("Code42 authentication failed — no access_token in response")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the cases endpoint with a tiny page as a liveness probe."""
        try:
            self.get("/v1/cases", params={"pgSize": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Code42 record by id."""
        if not object_id:
            raise GNATClientError("Code42 get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/cases/{object_id}")
            kind = "case"
        elif stix_type == "user-account":
            resp = self.get(f"/v2/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(f"Code42 get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"Code42 returned unexpected payload for {object_id!r}")
        return dict(resp, _c42_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Code42 records."""
        filters = dict(filters or {})
        kind = (filters.get("kind") or "").lower()

        if stix_type == "observed-data":
            if kind == "file_events":
                body: dict[str, Any] = {
                    "pgSize": int(page_size),
                    "pgNum": int(page),
                }
                if filters.get("query"):
                    body["groupClause"] = filters["query"]
                resp = self.post("/v2/file-events", json=body)
                items = resp.get("fileEvents", []) if isinstance(resp, dict) else []
                tag = "file_event"
            elif kind == "alerts":
                resp = self.get("/v1/alerts/search", params={"pageSize": int(page_size)})
                items = resp.get("alerts", []) if isinstance(resp, dict) else []
                tag = "alert"
            else:
                resp = self.get("/v1/cases", params={"pgSize": int(page_size)})
                items = resp.get("cases", []) if isinstance(resp, dict) else []
                tag = "case"
        elif stix_type == "user-account":
            resp = self.get("/v2/users", params={"pgSize": int(page_size)})
            items = resp.get("users", []) if isinstance(resp, dict) else []
            tag = "user"
        elif stix_type == "x-code42-risk-profile":
            resp = self.get("/v1/user-risk-profiles", params={"pgSize": int(page_size)})
            items = resp.get("userRiskProfiles", []) if isinstance(resp, dict) else []
            tag = "risk_profile"
        else:
            raise GNATClientError(f"Code42 list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _c42_kind=tag) for r in items if isinstance(r, dict)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Code42 connector is read-only in Phase 2."""
        raise GNATClientError("Code42 connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Code42 connector is read-only in Phase 2."""
        raise GNATClientError("Code42 connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def search_file_events(self, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Search Code42 file-activity events via v2 search DSL."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "file_events", "query": query or {}},
            page_size=1000,
        )

    def list_alerts(self) -> list[dict[str, Any]]:
        """Return Incydr alerts."""
        return self.list_objects("observed-data", filters={"kind": "alerts"}, page_size=500)

    def list_cases(self) -> list[dict[str, Any]]:
        """Return Code42 investigation cases."""
        return self.list_objects("observed-data", page_size=500)

    def get_case(self, case_id: str) -> dict[str, Any]:
        """Fetch a single investigation case."""
        return self.get_object("observed-data", case_id)

    def list_users(self) -> list[dict[str, Any]]:
        """Return Code42 users."""
        return self.list_objects("user-account", page_size=500)

    def list_user_risk_profiles(self) -> list[dict[str, Any]]:
        """Return per-user risk-posture scores."""
        return self.list_objects("x-code42-risk-profile", page_size=500)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Code42 record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Code42 to_stix expects a dict input")

        kind = native.get("_c42_kind") or "case"

        if kind == "user":
            user_id = native.get("userId") or native.get("username", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_CODE42, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "account_login": native.get("username") or native.get("email"),
                "display_name": native.get("displayName") or native.get("name"),
                "account_type": "cloud",
                "x_code42": {
                    "user_id": user_id,
                    "email": native.get("email"),
                    "org_id": native.get("orgId"),
                    "active": native.get("active"),
                    "raw": native,
                },
            }

        if kind == "risk_profile":
            user_id = native.get("userId") or native.get("username", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_CODE42, f"x-code42-risk-profile|{user_id}")
            return {
                "type": "x-code42-risk-profile",
                "id": f"x-code42-risk-profile--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "user_id": user_id,
                "username": native.get("username"),
                "risk_score": native.get("riskScore"),
                "risk_factors": native.get("riskFactors") or [],
                "x_code42": {"raw": native},
            }

        # observed-data envelope (file_event / alert / case)
        refs: list[str] = []
        user_id: str | None = native.get("userId") or native.get("username")
        if not user_id:
            user_block = native.get("user")
            if isinstance(user_block, dict):
                user_id = user_block.get("id") or user_block.get("username")
        if not user_id:
            user_id = native.get("userUid")
        if isinstance(user_id, str) and user_id:
            user_uuid = uuid.uuid5(_NAMESPACE_CODE42, f"user-account|{user_id}")
            refs.append(f"user-account--{user_uuid}")

        filename: str | None = native.get("fileName")
        if not filename:
            file_block = native.get("file")
            if isinstance(file_block, dict):
                filename = file_block.get("name")
        if filename:
            file_uuid = uuid.uuid5(_NAMESPACE_CODE42, f"file|{filename}")
            refs.append(f"file--{file_uuid}")

        first = (
            native.get("eventTimestamp")
            or native.get("createdAt")
            or native.get("timestamp")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="code42",
            x_extensions={
                "code42": {
                    "kind": kind,
                    "event_id": native.get("eventId") or native.get("id"),
                    "destination_category": native.get("destinationCategory"),
                    "destination_name": native.get("destinationName"),
                    "exposure": native.get("exposure"),
                    "file_category": native.get("fileCategory"),
                    "file_size": native.get("fileSize"),
                    "risk_score": native.get("riskScore"),
                    "risk_severity": native.get("riskSeverity"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Code42 connector is read-only."""
        return {
            "note": (
                "Code42 connector is read-only. Use search_file_events, "
                "list_alerts, list_cases, get_case, list_users, or "
                "list_user_risk_profiles to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
