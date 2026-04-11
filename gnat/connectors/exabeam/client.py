# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.exabeam.client
==================================

Exabeam Security Operations Platform / UEBA connector.

Authentication
--------------
OAuth2 client credentials against ``/auth/v1/token``::

    [exabeam]
    host          = https://api.us-west.exabeam.cloud
    client_id     = exa_...
    client_secret = ...

Key endpoints
-------------
* ``POST /auth/v1/token``         — OAuth2 token exchange
* ``GET  /threat-detection/v1/incidents``
* ``GET  /threat-detection/v1/incidents/{id}``
* ``GET  /threat-detection/v1/sessions``          — risk-scored sessions
* ``GET  /threat-detection/v1/users``             — user risk profiles
* ``GET  /threat-detection/v1/notable-assets``
* ``GET  /threat-detection/v1/alerts``
* ``GET  /threat-detection/v1/cases``
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_EXABEAM = uuid.UUID("e1aba3a1-0001-4a1e-9b1e-e1aba3a1c0fe")


class ExabeamClient(BaseClient, ConnectorMixin):
    """HTTP client for the Exabeam Security Operations Platform."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/threat-detection/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incidents",
        "user-account": "users",
    }

    def __init__(
        self,
        host: str = "https://api.us-west.exabeam.cloud",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize ExabeamClient."""
        super().__init__(host=host, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> None:
        """Exchange client credentials for a Bearer token."""
        if not self.client_id or not self.client_secret:
            raise GNATClientError(
                "Exabeam connector requires client_id and client_secret."
            )
        resp = self.post(
            "/auth/v1/token",
            json={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
        )
        token = ""
        if isinstance(resp, dict):
            token = resp.get("access_token") or resp.get("token", "")
        if not token:
            raise GNATClientError(
                "Exabeam authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query incidents with a tiny page as a liveness probe."""
        try:
            self.get("/threat-detection/v1/incidents", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Exabeam record by id."""
        if not object_id:
            raise GNATClientError("Exabeam get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/threat-detection/v1/incidents/{object_id}")
            kind = "incident"
        elif stix_type == "user-account":
            resp = self.get(f"/threat-detection/v1/users/{object_id}")
            kind = "user"
        else:
            raise GNATClientError(
                f"Exabeam get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Exabeam returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _exa_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Exabeam records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size)}
        for key in ("priority", "status", "since", "until", "query"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "incidents").lower()
            if kind == "sessions":
                resp = self.get("/threat-detection/v1/sessions", params=params)
                tag = "session"
            elif kind == "alerts":
                resp = self.get("/threat-detection/v1/alerts", params=params)
                tag = "alert"
            elif kind == "cases":
                resp = self.get("/threat-detection/v1/cases", params=params)
                tag = "case"
            elif kind == "notable_assets":
                resp = self.get(
                    "/threat-detection/v1/notable-assets", params=params
                )
                tag = "notable_asset"
            else:
                resp = self.get("/threat-detection/v1/incidents", params=params)
                tag = "incident"
        elif stix_type == "user-account":
            resp = self.get("/threat-detection/v1/users", params=params)
            tag = "user"
        else:
            raise GNATClientError(
                f"Exabeam list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _exa_kind=tag) for r in _extract_exabeam_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Exabeam connector is read-only in Phase 2."""
        raise GNATClientError(
            "Exabeam connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Exabeam connector is read-only in Phase 2."""
        raise GNATClientError(
            "Exabeam connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_incidents(
        self, priority: str = "", since: str = ""
    ) -> list[dict[str, Any]]:
        """Return Exabeam incidents."""
        filters: dict[str, Any] = {}
        if priority:
            filters["priority"] = priority
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_sessions(self, since: str = "") -> list[dict[str, Any]]:
        """Return risk-scored user sessions (the Exabeam Smart Timeline unit)."""
        filters: dict[str, Any] = {"kind": "sessions"}
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_alerts(self) -> list[dict[str, Any]]:
        """Return raw alerts."""
        return self.list_objects(
            "observed-data", filters={"kind": "alerts"}, page_size=500
        )

    def list_cases(self) -> list[dict[str, Any]]:
        """Return investigation cases."""
        return self.list_objects(
            "observed-data", filters={"kind": "cases"}, page_size=500
        )

    def list_notable_assets(self) -> list[dict[str, Any]]:
        """Return notable (high-risk) assets."""
        return self.list_objects(
            "observed-data", filters={"kind": "notable_assets"}, page_size=500
        )

    def list_users(self) -> list[dict[str, Any]]:
        """Return user risk profiles."""
        return self.list_objects("user-account", page_size=500)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single incident by id."""
        return self.get_object("observed-data", incident_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Exabeam record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Exabeam to_stix expects a dict input")

        kind = native.get("_exa_kind") or "incident"

        if kind == "user":
            user_id = native.get("username") or native.get("userId", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_EXABEAM, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": "2.1",
                "account_login": native.get("username"),
                "display_name": native.get("displayName") or native.get("fullName"),
                "account_type": "domain",
                "x_exabeam": {
                    "user_id": user_id,
                    "risk_score": native.get("riskScore"),
                    "department": native.get("department"),
                    "raw": native,
                },
            }

        # observed-data envelope
        refs: list[str] = []
        user = native.get("username") or native.get("userId") or native.get("user")
        if isinstance(user, dict):
            user = user.get("username") or user.get("id")
        if user:
            user_uuid = uuid.uuid5(_NAMESPACE_EXABEAM, f"user-account|{user}")
            refs.append(f"user-account--{user_uuid}")

        asset = native.get("asset") or native.get("host") or native.get("hostname")
        if isinstance(asset, dict):
            asset = asset.get("name") or asset.get("hostname")
        if asset:
            asset_uuid = uuid.uuid5(_NAMESPACE_EXABEAM, f"identity|asset|{asset}")
            refs.append(f"identity--{asset_uuid}")

        first = (
            native.get("startTime")
            or native.get("createdAt")
            or native.get("timestamp")
            or utcnow()
        )
        last = native.get("endTime") or native.get("updatedAt") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="exabeam",
            x_extensions={
                "exabeam": {
                    "kind": kind,
                    "incident_id": native.get("id"),
                    "priority": native.get("priority"),
                    "risk_score": native.get("riskScore"),
                    "title": native.get("title"),
                    "status": native.get("status"),
                    "rule_names": native.get("rules") or native.get("ruleNames") or [],
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Exabeam connector is read-only."""
        return {
            "note": (
                "Exabeam connector is read-only. Use list_incidents, "
                "list_sessions, list_alerts, list_cases, list_notable_assets, "
                "list_users, or get_incident to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_exabeam_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an Exabeam response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "incidents", "sessions", "users", "alerts", "cases"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
