# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.okta.client
===============================

Okta Identity Cloud connector.

Authentication
--------------
Okta uses a proprietary ``Authorization: SSWS <api_token>`` header::

    [okta]
    host      = https://YOUR_TENANT.okta.com
    api_token = okta_...

Key endpoints
-------------
* ``GET  /api/v1/users``              — list users
* ``GET  /api/v1/users/{id}``
* ``GET  /api/v1/groups``             — list groups
* ``GET  /api/v1/groups/{id}/users``  — group membership
* ``GET  /api/v1/apps``               — applications / OIDC clients
* ``GET  /api/v1/apps/{id}/users``    — app assignments
* ``GET  /api/v1/logs``               — system log (authn events)
* ``GET  /api/v1/policies``           — authentication / MFA policies
* ``GET  /api/v1/iam/roles``          — IAM roles

STIX Type Mapping
-----------------
* ``user-account`` → ``/users`` (humans + service accounts)
* ``identity``     → ``/groups`` (groups + org)
* ``observed-data`` → system log authn events (wrap user + source-ip refs)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_OKTA = uuid.UUID("07c7a700-0001-4a1e-9b1e-07c7a700c0fe")


class OktaClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Okta Identity Cloud.

    Parameters
    ----------
    host : str
        Tenant URL.  Defaults to an empty string; each Okta deployment
        has a unique sub-domain.
    api_token : str
        Okta API token (SSWS scheme).
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "user-account": "users",
        "identity": "groups",
        "observed-data": "logs",
    }

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize OktaClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set the proprietary ``Authorization: SSWS`` header."""
        if not self.api_token:
            raise GNATClientError("Okta connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"SSWS {self.api_token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/api/v1/users?limit=1`` as a cheap authenticated probe."""
        try:
            self.get("/api/v1/users", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Okta resource by id."""
        if not object_id:
            raise GNATClientError("Okta get_object requires a non-empty id")
        if stix_type == "user-account":
            resp = self.get(f"/api/v1/users/{object_id}")
            kind = "user"
        elif stix_type == "identity":
            resp = self.get(f"/api/v1/groups/{object_id}")
            kind = "group"
        elif stix_type == "observed-data":
            # System log events are not addressable by single id; fetch by uuid query
            resp = self.get("/api/v1/logs", params={"filter": f'uuid eq "{object_id}"'})
            kind = "event"
        elif stix_type == "x-okta-app":
            resp = self.get(f"/api/v1/apps/{object_id}")
            kind = "app"
        else:
            raise GNATClientError(f"Okta get_object does not support stix_type={stix_type!r}")
        if isinstance(resp, list) and resp:
            return dict(resp[0], _okta_kind=kind)
        if isinstance(resp, dict):
            return dict(resp, _okta_kind=kind)
        raise GNATClientError(f"Okta returned unexpected payload for {object_id!r}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Okta resources.

        ``filters`` keys:

        * ``q`` — free-text search (users / apps)
        * ``filter`` — Okta filter DSL
        * ``since`` — ISO 8601 cutoff (system log)
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size)}
        for key in ("q", "filter", "search", "since", "until"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "user-account":
            resp = self.get("/api/v1/users", params=params)
            kind = "user"
        elif stix_type == "identity":
            resp = self.get("/api/v1/groups", params=params)
            kind = "group"
        elif stix_type == "observed-data":
            resp = self.get("/api/v1/logs", params=params)
            kind = "event"
        elif stix_type == "x-okta-app":
            resp = self.get("/api/v1/apps", params=params)
            kind = "app"
        else:
            raise GNATClientError(f"Okta list_objects does not support stix_type={stix_type!r}")

        if isinstance(resp, list):
            return [dict(r, _okta_kind=kind) for r in resp if isinstance(r, dict)]
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Okta connector is read-only in Phase 2."""
        raise GNATClientError("Okta connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Okta connector is read-only in Phase 2."""
        raise GNATClientError("Okta connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_users(self, search: str = "", status: str = "") -> list[dict[str, Any]]:
        """Return all users, optionally filtered by search string / status."""
        filters: dict[str, Any] = {}
        if search:
            filters["search"] = search
        if status:
            filters["filter"] = f'status eq "{status}"'
        return self.list_objects("user-account", filters=filters, page_size=200)

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Fetch a single user by id or login."""
        return self.get_object("user-account", user_id)

    def list_groups(self, search: str = "") -> list[dict[str, Any]]:
        """Return all groups."""
        filters: dict[str, Any] = {}
        if search:
            filters["q"] = search
        return self.list_objects("identity", filters=filters, page_size=200)

    def list_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Return members of a specific group."""
        resp = self.get(f"/api/v1/groups/{group_id}/users", params={"limit": 200})
        if isinstance(resp, list):
            return [dict(r, _okta_kind="user") for r in resp if isinstance(r, dict)]
        return []

    def list_apps(self) -> list[dict[str, Any]]:
        """Return all Okta applications."""
        return self.list_objects("x-okta-app", page_size=200)

    def list_app_users(self, app_id: str) -> list[dict[str, Any]]:
        """Return users assigned to a specific application."""
        resp = self.get(f"/api/v1/apps/{app_id}/users", params={"limit": 200})
        if isinstance(resp, list):
            return [dict(r, _okta_kind="app_user") for r in resp if isinstance(r, dict)]
        return []

    def list_system_log_events(
        self, since: str = "", until: str = "", filter_expr: str = ""
    ) -> list[dict[str, Any]]:
        """Return Okta system log events."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if until:
            filters["until"] = until
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def list_policies(self, policy_type: str = "") -> list[dict[str, Any]]:
        """Return authentication / MFA policies."""
        params: dict[str, Any] = {}
        if policy_type:
            params["type"] = policy_type
        resp = self.get("/api/v1/policies", params=params)
        if isinstance(resp, list):
            return [r for r in resp if isinstance(r, dict)]
        return []

    def list_factors(self, user_id: str) -> list[dict[str, Any]]:
        """Return MFA factors enrolled by a user."""
        resp = self.get(f"/api/v1/users/{user_id}/factors")
        if isinstance(resp, list):
            return [r for r in resp if isinstance(r, dict)]
        return []

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Okta record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Okta to_stix expects a dict input")

        kind = native.get("_okta_kind") or "user"

        if kind in ("user", "app_user"):
            user_id = native.get("id") or ""
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            stix_uuid = uuid.uuid5(_NAMESPACE_OKTA, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "account_login": profile.get("login") or native.get("login", ""),
                "display_name": profile.get("displayName")
                or f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
                "account_type": "cloud",
                "x_okta": {
                    "user_id": user_id,
                    "status": native.get("status"),
                    "email": profile.get("email"),
                    "title": profile.get("title"),
                    "department": profile.get("department"),
                    "last_login": native.get("lastLogin"),
                    "mfa_factors_enrolled": native.get("credentials", {})
                    .get("provider", {})
                    .get("type")
                    if isinstance(native.get("credentials"), dict)
                    else None,
                    "raw": native,
                },
            }

        if kind == "group":
            group_id = native.get("id") or ""
            profile = native.get("profile") if isinstance(native.get("profile"), dict) else {}
            stix_uuid = uuid.uuid5(_NAMESPACE_OKTA, f"identity|group|{group_id}")
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": profile.get("name") or f"Okta group {group_id}",
                "identity_class": "group",
                "description": profile.get("description") or "",
                "x_okta_group": {
                    "group_id": group_id,
                    "type": native.get("type"),
                    "object_class": native.get("objectClass"),
                    "raw": native,
                },
            }

        if kind == "app":
            app_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_OKTA, f"x-okta-app|{app_id}")
            return {
                "type": "x-okta-app",
                "id": f"x-okta-app--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("label") or native.get("name", ""),
                "status": native.get("status"),
                "sign_on_mode": native.get("signOnMode"),
                "features": native.get("features") or [],
                "x_okta_app": {"raw": native},
            }

        # event → observed-data envelope
        event_id = native.get("uuid") or native.get("eventType", "")
        refs: list[str] = []

        actor = native.get("actor") if isinstance(native.get("actor"), dict) else {}
        actor_id = actor.get("id") or actor.get("alternateId")
        if actor_id:
            actor_uuid = uuid.uuid5(_NAMESPACE_OKTA, f"user-account|{actor_id}")
            refs.append(f"user-account--{actor_uuid}")

        client = native.get("client") if isinstance(native.get("client"), dict) else {}
        ip = client.get("ipAddress")
        if ip:
            ip_uuid = uuid.uuid5(_NAMESPACE_OKTA, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = native.get("published") or native.get("eventTime") or utcnow()

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="okta",
            x_extensions={
                "okta": {
                    "uuid": event_id,
                    "event_type": native.get("eventType"),
                    "outcome": native.get("outcome", {}).get("result")
                    if isinstance(native.get("outcome"), dict)
                    else None,
                    "severity": native.get("severity"),
                    "display_message": native.get("displayMessage"),
                    "actor_email": actor.get("alternateId"),
                    "user_agent": client.get("userAgent"),
                    "geographical_context": client.get("geographicalContext"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Okta connector is read-only."""
        return {
            "note": (
                "Okta connector is read-only. Use list_users, get_user, "
                "list_groups, list_group_members, list_apps, list_app_users, "
                "list_system_log_events, list_policies, or list_factors to "
                "query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
