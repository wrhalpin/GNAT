# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.ping_identity.client
========================================

Ping Identity (PingOne) connector.

Authentication
--------------
OAuth2 client credentials flow against
``https://auth.pingone.com/{env_id}/as/token``::

    [ping_identity]
    host           = https://api.pingone.com
    environment_id = 00000000-0000-0000-0000-000000000000
    client_id      = ...
    client_secret  = ...
    auth_region    = NA  ; NA / EU / AP / CA

Key endpoints
-------------
* ``GET /v1/environments/{env}/users``            — user directory
* ``GET /v1/environments/{env}/users/{id}``
* ``GET /v1/environments/{env}/populations``      — "groups" in PingOne
* ``GET /v1/environments/{env}/applications``     — registered apps
* ``GET /v1/environments/{env}/signOnPolicies``   — sign-on policies
* ``GET /v1/environments/{env}/activities``       — authentication activities
* ``GET /v1/environments/{env}/auditEvents``      — admin / change audit log

STIX Type Mapping
-----------------
* ``user-account`` → users
* ``identity``     → populations (groups) + environment (org)
* ``observed-data`` → activities + audit events
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_PING = uuid.UUID("917e1d00-0001-4a1e-9b1e-917e1d00c0fe")

_AUTH_REGIONS: dict[str, str] = {
    "NA": "https://auth.pingone.com",
    "EU": "https://auth.pingone.eu",
    "AP": "https://auth.pingone.asia",
    "CA": "https://auth.pingone.ca",
}


class PingIdentityClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Ping Identity / PingOne.

    Parameters
    ----------
    host : str
        PingOne API base URL.  Defaults to ``"https://api.pingone.com"``.
    environment_id : str
        PingOne environment id (GUID) — scopes every request.
    client_id : str
        OAuth2 client id.
    client_secret : str
        OAuth2 client secret.
    auth_region : str, optional
        One of ``"NA"``, ``"EU"``, ``"AP"``, ``"CA"`` selecting the
        regional auth endpoint.  Default ``"NA"``.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "user-account": "users",
        "identity": "populations",
        "observed-data": "activities",
    }

    def __init__(
        self,
        host: str = "https://api.pingone.com",
        environment_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        auth_region: str = "NA",
        **kwargs: Any,
    ) -> None:
        """Initialize PingIdentityClient."""
        super().__init__(host=host, **kwargs)
        self.environment_id = environment_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_region = auth_region

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange client credentials for a PingOne API access token."""
        if (
            not self.environment_id
            or not self.client_id
            or not self.client_secret
        ):
            raise GNATClientError(
                "Ping Identity connector requires environment_id, client_id, "
                "and client_secret."
            )
        region_base = _AUTH_REGIONS.get(
            self.auth_region.upper(), _AUTH_REGIONS["NA"]
        )
        token_url = f"{region_base}/{self.environment_id}/as/token"
        body = (
            f"grant_type=client_credentials"
            f"&client_id={self.client_id}"
            f"&client_secret={self.client_secret}"
        )
        pool = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=self.timeout, read=self.timeout),
            cert_reqs="CERT_REQUIRED" if self.verify_ssl else "CERT_NONE",
        )
        try:
            resp = pool.request(
                "POST",
                token_url,
                body=body.encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except urllib3.exceptions.HTTPError as exc:
            raise GNATClientError(
                f"Ping Identity token request failed: {exc}"
            ) from exc
        if resp.status >= 400:
            raise GNATClientError(
                f"Ping Identity token request returned HTTP {resp.status}: "
                f"{resp.data[:200]!r}"
            )
        try:
            data = json.loads(resp.data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GNATClientError(
                f"Ping Identity token response was not JSON: {exc}"
            ) from exc
        token = data.get("access_token") or ""
        if not token:
            raise GNATClientError(
                "Ping Identity authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── Internal path helper ──────────────────────────────────────────────

    def _env_path(self, suffix: str) -> str:
        """Return an environment-scoped PingOne API path."""
        return f"/v1/environments/{self.environment_id}/{suffix.lstrip('/')}"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/environments/{env}`` as a cheap authenticated probe."""
        try:
            self.get(f"/v1/environments/{self.environment_id}")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Ping Identity resource by id."""
        if not object_id:
            raise GNATClientError("Ping Identity get_object requires a non-empty id")
        if stix_type == "user-account":
            resp = self.get(self._env_path(f"users/{object_id}"))
            kind = "user"
        elif stix_type == "identity":
            resp = self.get(self._env_path(f"populations/{object_id}"))
            kind = "population"
        elif stix_type == "x-ping-application":
            resp = self.get(self._env_path(f"applications/{object_id}"))
            kind = "application"
        else:
            raise GNATClientError(
                f"Ping Identity get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Ping Identity returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _ping_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Ping Identity resources."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size)}
        for key in ("filter", "sort", "expand"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "user-account":
            resp = self.get(self._env_path("users"), params=params)
            kind = "user"
        elif stix_type == "identity":
            resp = self.get(self._env_path("populations"), params=params)
            kind = "population"
        elif stix_type == "x-ping-application":
            resp = self.get(self._env_path("applications"), params=params)
            kind = "application"
        elif stix_type == "observed-data":
            sub = (filters.get("kind") or "activities").lower()
            if sub == "audit_events":
                resp = self.get(self._env_path("auditEvents"), params=params)
                kind = "audit_event"
            else:
                resp = self.get(self._env_path("activities"), params=params)
                kind = "activity"
        else:
            raise GNATClientError(
                f"Ping Identity list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _ping_kind=kind) for r in _extract_ping_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Ping Identity connector is read-only."""
        raise GNATClientError(
            "Ping Identity connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Ping Identity connector is read-only."""
        raise GNATClientError(
            "Ping Identity connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_users(self, filter_expr: str = "") -> list[dict[str, Any]]:
        """Return all users, optionally filtered with Ping SCIM filter DSL."""
        filters: dict[str, Any] = {}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects("user-account", filters=filters, page_size=500)

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Fetch a single user by id."""
        return self.get_object("user-account", user_id)

    def list_populations(self) -> list[dict[str, Any]]:
        """Return all populations (PingOne's group-equivalent)."""
        return self.list_objects("identity", page_size=500)

    def list_applications(self) -> list[dict[str, Any]]:
        """Return registered applications."""
        return self.list_objects("x-ping-application", page_size=500)

    def list_sign_on_policies(self) -> list[dict[str, Any]]:
        """Return sign-on policy definitions."""
        resp = self.get(self._env_path("signOnPolicies"))
        return [
            dict(r, _ping_kind="sign_on_policy")
            for r in _extract_ping_list(resp)
        ]

    def list_activities(
        self, filter_expr: str = ""
    ) -> list[dict[str, Any]]:
        """Return authentication activity events."""
        filters: dict[str, Any] = {"kind": "activities"}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects(
            "observed-data", filters=filters, page_size=500
        )

    def list_audit_events(
        self, filter_expr: str = ""
    ) -> list[dict[str, Any]]:
        """Return administrative audit events."""
        filters: dict[str, Any] = {"kind": "audit_events"}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects(
            "observed-data", filters=filters, page_size=500
        )

    def list_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Return the populations/groups a specific user belongs to."""
        resp = self.get(self._env_path(f"users/{user_id}/groupMemberships"))
        return [
            dict(r, _ping_kind="population") for r in _extract_ping_list(resp)
        ]

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Ping Identity record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Ping Identity to_stix expects a dict input")

        kind = native.get("_ping_kind") or "user"

        if kind == "user":
            user_id = native.get("id") or ""
            name = native.get("name") if isinstance(native.get("name"), dict) else {}
            stix_uuid = uuid.uuid5(_NAMESPACE_PING, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": "2.1",
                "account_login": native.get("username"),
                "display_name": f"{name.get('given', '')} {name.get('family', '')}".strip()
                or native.get("username"),
                "account_type": "cloud",
                "x_ping_identity": {
                    "user_id": user_id,
                    "email": native.get("email"),
                    "enabled": native.get("enabled"),
                    "population_id": (native.get("population") or {}).get("id")
                    if isinstance(native.get("population"), dict)
                    else None,
                    "mfa_enabled": native.get("mfaEnabled"),
                    "raw": native,
                },
            }

        if kind == "population":
            pop_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_PING, f"identity|population|{pop_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": "2.1",
                "created": native.get("createdAt") or utcnow(),
                "modified": native.get("updatedAt") or utcnow(),
                "name": native.get("name") or f"PingOne population {pop_id}",
                "identity_class": "group",
                "description": native.get("description") or "",
                "x_ping_identity_population": {
                    "population_id": pop_id,
                    "user_count": native.get("userCount"),
                    "raw": native,
                },
            }

        if kind == "application":
            app_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_PING, f"x-ping-application|{app_id}"
            )
            return {
                "type": "x-ping-application",
                "id": f"x-ping-application--{stix_uuid}",
                "spec_version": "2.1",
                "created": native.get("createdAt") or utcnow(),
                "modified": native.get("updatedAt") or utcnow(),
                "name": native.get("name") or app_id,
                "enabled": native.get("enabled"),
                "protocol": native.get("protocol"),
                "type_hint": native.get("type"),
                "x_ping_identity_app": {"raw": native},
            }

        if kind == "sign_on_policy":
            pol_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_PING, f"x-ping-sign-on-policy|{pol_id}"
            )
            return {
                "type": "x-ping-sign-on-policy",
                "id": f"x-ping-sign-on-policy--{stix_uuid}",
                "spec_version": "2.1",
                "name": native.get("name") or pol_id,
                "default": native.get("default"),
                "x_ping_identity_policy": {"raw": native},
            }

        # activity / audit_event → observed-data envelope
        refs: list[str] = []

        actor_block = native.get("actors") if isinstance(native.get("actors"), list) else []
        user_id = None
        for actor in actor_block:
            if isinstance(actor, dict) and actor.get("type") == "USER":
                user_id = actor.get("id")
                break
        if not user_id:
            user_id = (native.get("actor") or {}).get("id") if isinstance(
                native.get("actor"), dict
            ) else None
        if user_id:
            user_uuid = uuid.uuid5(
                _NAMESPACE_PING, f"user-account|{user_id}"
            )
            refs.append(f"user-account--{user_uuid}")

        ip = (
            native.get("ipAddress")
            or (native.get("client") or {}).get("ip")
            if isinstance(native.get("client"), dict)
            else native.get("ipAddress")
        )
        if ip:
            ip_uuid = uuid.uuid5(_NAMESPACE_PING, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("createdAt")
            or native.get("recordedAt")
            or native.get("eventTime")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="ping_identity",
            x_extensions={
                "ping_identity": {
                    "kind": kind,
                    "event_id": native.get("id"),
                    "action": native.get("action") or native.get("activity"),
                    "result": native.get("result"),
                    "app_id": (native.get("application") or {}).get("id")
                    if isinstance(native.get("application"), dict)
                    else None,
                    "environment_id": self.environment_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Ping Identity connector is read-only."""
        return {
            "note": (
                "Ping Identity connector is read-only. Use list_users, "
                "get_user, list_populations, list_applications, "
                "list_sign_on_policies, list_activities, list_audit_events, "
                "or list_user_groups to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_ping_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a PingOne HAL-style response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    embedded = resp.get("_embedded")
    if isinstance(embedded, dict):
        for val in embedded.values():
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
    for key in ("data", "items", "results"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return [resp]
