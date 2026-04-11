# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.silverfort.client
=====================================

Silverfort Identity Threat Detection & Response (ITDR) connector.

Authentication
--------------
OAuth2 client credentials — the connector POSTs to ``/api/v1/auth/token``
with the configured ``client_id`` and ``client_secret`` and caches the
returned Bearer token on ``self._auth_headers``::

    [silverfort]
    host          = https://your-tenant.silverfort.com
    client_id     = sf_client_id
    client_secret = sf_client_secret

Key endpoints
-------------
* ``GET /api/v1/users`` / ``/api/v1/users/{id}``
* ``GET /api/v1/events/authentications``
* ``GET /api/v1/policies``
* ``GET /api/v1/service-accounts``
* ``GET /api/v1/alerts``

STIX Type Mapping
-----------------
* ``user-account``  → ``/users`` (human + service accounts)
* ``observed-data`` → authn events, alerts (wrapping user-account refs)

Notes
-----
* ``TRUST_LEVEL`` is ``"trusted_internal"`` since the data represents
  the customer's own authentication telemetry.
* **Read-only.**  Policy changes and identity remediation are out of
  scope for Phase 1; ``upsert_object`` / ``delete_object`` raise.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_SILVERFORT = uuid.UUID("51147e57-0001-4a1b-9ec0-51147e57ab1e")


class SilverfortClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Silverfort ITDR.

    Parameters
    ----------
    host : str
        Base URL of the tenant.  No default — tenant URLs are unique.
    client_id : str
        OAuth2 client id.
    client_secret : str
        OAuth2 client secret.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "user-account": "users",
        "observed-data": "events/authentications",
    }

    def __init__(
        self,
        host: str = "",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SilverfortClient."""
        super().__init__(host=host, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange client credentials for a Bearer token."""
        if not self.client_id or not self.client_secret:
            raise GNATClientError(
                "Silverfort connector requires client_id and client_secret."
            )
        resp = self.post(
            "/api/v1/auth/token",
            json={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
        )
        token = ""
        if isinstance(resp, dict):
            token = resp.get("access_token") or resp.get("token") or ""
        if not token:
            raise GNATClientError(
                "Silverfort authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/api/v1/health`` as an authenticated liveness probe."""
        try:
            self.get("/api/v1/health")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single resource by id."""
        if not object_id:
            raise GNATClientError("Silverfort get_object requires a non-empty id")
        if stix_type == "user-account":
            resp = self.get(f"/api/v1/users/{object_id}")
        elif stix_type == "observed-data":
            resp = self.get(f"/api/v1/events/authentications/{object_id}")
        else:
            raise GNATClientError(
                f"Silverfort get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Silverfort returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _sf_kind=stix_type)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Silverfort resources of the given type."""
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page": int(page),
            "page_size": int(page_size),
        }
        for key in ("since", "until", "user", "risk_score_min", "status"):
            if filters.get(key) is not None:
                params[key] = filters[key]

        if stix_type == "user-account":
            resp = self.get("/api/v1/users", params=params)
            kind = "user-account"
        elif stix_type == "observed-data":
            resp = self.get("/api/v1/events/authentications", params=params)
            kind = "observed-data"
        elif stix_type == "x-silverfort-alert":
            resp = self.get("/api/v1/alerts", params=params)
            kind = "observed-data"
        else:
            raise GNATClientError(
                f"Silverfort list_objects does not support stix_type={stix_type!r}"
            )
        records = _extract_records(resp)
        return [dict(r, _sf_kind=kind) for r in records]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Silverfort connector is read-only."""
        raise GNATClientError(
            "Silverfort connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Silverfort connector is read-only."""
        raise GNATClientError(
            "Silverfort connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_users(self) -> list[dict[str, Any]]:
        """Return the full user roster."""
        return self.list_objects("user-account", page_size=10_000)

    def list_service_accounts(self) -> list[dict[str, Any]]:
        """Return Silverfort-identified service accounts."""
        resp = self.get("/api/v1/service-accounts")
        return [dict(r, _sf_kind="user-account") for r in _extract_records(resp)]

    def list_auth_events(
        self,
        since: str = "",
        user: str = "",
        risk_score_min: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return authentication events filtered by time/user/risk."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if user:
            filters["user"] = user
        if risk_score_min is not None:
            filters["risk_score_min"] = risk_score_min
        return self.list_objects(
            "observed-data", filters=filters, page_size=10_000
        )

    def list_alerts(self, status: str = "") -> list[dict[str, Any]]:
        """Return Silverfort alerts (optionally filtered by status)."""
        filters: dict[str, Any] = {}
        if status:
            filters["status"] = status
        return self.list_objects(
            "x-silverfort-alert", filters=filters, page_size=10_000
        )

    def get_user_risk(self, user_id: str) -> dict[str, Any]:
        """Fetch risk metadata for a single user."""
        return self.get_object("user-account", user_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Silverfort record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Silverfort to_stix expects a dict input")

        kind = native.get("_sf_kind") or "observed-data"
        now = utcnow()

        if kind == "user-account":
            user_id = (
                native.get("user_id")
                or native.get("id")
                or native.get("upn")
                or native.get("username", "")
            )
            stix_uuid = uuid.uuid5(_NAMESPACE_SILVERFORT, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "account_login": native.get("upn") or native.get("username"),
                "display_name": native.get("display_name") or native.get("name"),
                "account_type": native.get("account_type") or "domain",
                "x_silverfort": {
                    "user_id": user_id,
                    "risk_score": native.get("risk_score"),
                    "mfa_enrolled": native.get("mfa_enrolled"),
                    "privileged": native.get("privileged"),
                    "last_activity": native.get("last_activity"),
                    "tags": native.get("tags", []),
                    "raw": native,
                },
            }

        # observed-data — authentication event or alert
        refs: list[str] = []
        user_id = native.get("user_id") or native.get("upn") or native.get("user", "")
        if user_id:
            user_uuid = uuid.uuid5(
                _NAMESPACE_SILVERFORT, f"user-account|{user_id}"
            )
            refs.append(f"user-account--{user_uuid}")
        source_ip = native.get("source_ip") or native.get("client_ip")
        if source_ip:
            ip_uuid = uuid.uuid5(
                _NAMESPACE_SILVERFORT, f"ipv4-addr|{source_ip}"
            )
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("event_time")
            or native.get("timestamp")
            or native.get("created_at")
            or now
        )
        last = native.get("last_seen") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="silverfort",
            x_extensions={
                "silverfort": {
                    "risk_score": native.get("risk_score"),
                    "decision": native.get("decision"),
                    "mfa_method": native.get("mfa_method"),
                    "mfa_result": native.get("mfa_result"),
                    "protocol": native.get("protocol"),
                    "destination": native.get("destination"),
                    "alert_type": native.get("alert_type"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Silverfort connector is read-only."""
        return {
            "note": (
                "Silverfort connector is read-only. Use list_users, "
                "list_service_accounts, list_auth_events, list_alerts, "
                "or get_user_risk to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_records(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Silverfort response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "records"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
