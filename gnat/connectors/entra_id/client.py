# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.entra_id.client
===================================

Microsoft Entra ID (Azure AD) connector via Microsoft Graph v1.0.

Authentication
--------------
OAuth2 client credentials flow against
``https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`` with
scope ``https://graph.microsoft.com/.default``::

    [entra_id]
    host          = https://graph.microsoft.com
    tenant_id     = 00000000-0000-0000-0000-000000000000
    client_id     = 11111111-1111-1111-1111-111111111111
    client_secret = ...

Required Graph API permissions (application):
``User.Read.All``, ``Group.Read.All``, ``AuditLog.Read.All``,
``Directory.Read.All``, ``IdentityRiskyUser.Read.All``.

Key endpoints
-------------
* ``GET /v1.0/users``                         — user directory
* ``GET /v1.0/users/{id}``
* ``GET /v1.0/groups``                        — groups
* ``GET /v1.0/groups/{id}/members``
* ``GET /v1.0/servicePrincipals``             — applications
* ``GET /v1.0/auditLogs/signIns``             — sign-in audit log
* ``GET /v1.0/auditLogs/directoryAudits``     — directory-change audit
* ``GET /v1.0/identityProtection/riskyUsers`` — ITDR risk signals
* ``GET /v1.0/identity/conditionalAccess/policies``

STIX Type Mapping
-----------------
* ``user-account`` → ``/users``
* ``identity``     → ``/groups`` + org object
* ``observed-data`` → sign-in events, directory audits, risky-user events

Notes
-----
* **TRUST_LEVEL** is ``"trusted_internal"`` (the customer's own directory).
* **Read-only** for Phase 2.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_ENTRA = uuid.UUID("e711a100-0001-4a1e-9b1e-e711a100c0fe")


class EntraIDClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Microsoft Entra ID via Microsoft Graph.

    Parameters
    ----------
    host : str
        Microsoft Graph base URL.  Defaults to
        ``"https://graph.microsoft.com"``.
    tenant_id : str
        Azure tenant id (GUID).
    client_id : str
        Azure AD application (client) id.
    client_secret : str
        Azure AD application client secret.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1.0"
    API_PREFIX: str = "/v1.0"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "user-account": "users",
        "identity": "groups",
        "observed-data": "auditLogs/signIns",
    }

    def __init__(
        self,
        host: str = "https://graph.microsoft.com",
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize EntraIDClient."""
        super().__init__(host=host, **kwargs)
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Exchange client credentials for a Graph API access token.

        Posts to ``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``
        with ``grant_type=client_credentials`` and caches the returned
        Bearer token on ``self._auth_headers``.
        """
        if not self.tenant_id or not self.client_id or not self.client_secret:
            raise GNATClientError(
                "Entra ID connector requires tenant_id, client_id, and client_secret."
            )
        token_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )
        body = (
            f"grant_type=client_credentials"
            f"&client_id={self.client_id}"
            f"&client_secret={self.client_secret}"
            f"&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
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
                f"Entra ID token request failed: {exc}"
            ) from exc
        if resp.status >= 400:
            raise GNATClientError(
                f"Entra ID token request returned HTTP {resp.status}: "
                f"{resp.data[:200]!r}"
            )
        try:
            data = json.loads(resp.data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GNATClientError(
                f"Entra ID token response was not JSON: {exc}"
            ) from exc
        token = data.get("access_token") or ""
        if not token:
            raise GNATClientError(
                "Entra ID authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/v1.0/organization`` as a cheap authenticated probe."""
        try:
            self.get("/v1.0/organization", params={"$top": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Entra ID resource by id."""
        if not object_id:
            raise GNATClientError("Entra ID get_object requires a non-empty id")
        if stix_type == "user-account":
            resp = self.get(f"/v1.0/users/{object_id}")
            kind = "user"
        elif stix_type == "identity":
            resp = self.get(f"/v1.0/groups/{object_id}")
            kind = "group"
        elif stix_type == "x-entra-application":
            resp = self.get(f"/v1.0/servicePrincipals/{object_id}")
            kind = "service_principal"
        else:
            raise GNATClientError(
                f"Entra ID get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Entra ID returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _entra_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Entra ID resources via Graph OData query parameters.

        ``filters`` keys:

        * ``filter`` — OData ``$filter`` expression
        * ``select`` — OData ``$select`` projection
        * ``search`` — OData ``$search`` (requires ``ConsistencyLevel`` header)
        * ``kind`` — ``"sign_ins"`` / ``"directory_audits"`` /
          ``"risky_users"`` for ``observed-data``
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"$top": int(page_size)}
        if filters.get("filter"):
            params["$filter"] = filters["filter"]
        if filters.get("select"):
            params["$select"] = filters["select"]
        if filters.get("search"):
            params["$search"] = filters["search"]

        if stix_type == "user-account":
            resp = self.get("/v1.0/users", params=params)
            kind = "user"
        elif stix_type == "identity":
            resp = self.get("/v1.0/groups", params=params)
            kind = "group"
        elif stix_type == "x-entra-application":
            resp = self.get("/v1.0/servicePrincipals", params=params)
            kind = "service_principal"
        elif stix_type == "observed-data":
            sub = (filters.get("kind") or "sign_ins").lower()
            if sub == "directory_audits":
                resp = self.get("/v1.0/auditLogs/directoryAudits", params=params)
                kind = "directory_audit"
            elif sub == "risky_users":
                resp = self.get(
                    "/v1.0/identityProtection/riskyUsers", params=params
                )
                kind = "risky_user"
            else:
                resp = self.get("/v1.0/auditLogs/signIns", params=params)
                kind = "sign_in"
        else:
            raise GNATClientError(
                f"Entra ID list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _entra_kind=kind) for r in _extract_entra_value(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Entra ID connector is read-only in Phase 2."""
        raise GNATClientError(
            "Entra ID connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Entra ID connector is read-only in Phase 2."""
        raise GNATClientError(
            "Entra ID connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_users(
        self, filter_expr: str = "", select: str = ""
    ) -> list[dict[str, Any]]:
        """Return users, optionally filtered via OData ``$filter``."""
        filters: dict[str, Any] = {}
        if filter_expr:
            filters["filter"] = filter_expr
        if select:
            filters["select"] = select
        return self.list_objects("user-account", filters=filters, page_size=999)

    def get_user(self, user_id_or_upn: str) -> dict[str, Any]:
        """Fetch a user by object id or UPN."""
        return self.get_object("user-account", user_id_or_upn)

    def list_groups(self, filter_expr: str = "") -> list[dict[str, Any]]:
        """Return all groups."""
        filters: dict[str, Any] = {}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects("identity", filters=filters, page_size=999)

    def list_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Return members of a specific group."""
        resp = self.get(
            f"/v1.0/groups/{group_id}/members", params={"$top": 999}
        )
        return [
            dict(r, _entra_kind="user") for r in _extract_entra_value(resp)
        ]

    def list_service_principals(self) -> list[dict[str, Any]]:
        """Return registered applications (service principals)."""
        return self.list_objects("x-entra-application", page_size=999)

    def list_sign_ins(
        self,
        filter_expr: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        """Return sign-in audit events."""
        filters: dict[str, Any] = {"kind": "sign_ins"}
        if filter_expr:
            filters["filter"] = filter_expr
        elif since:
            filters["filter"] = f"createdDateTime ge {since}"
        return self.list_objects(
            "observed-data", filters=filters, page_size=999
        )

    def list_directory_audits(
        self, filter_expr: str = ""
    ) -> list[dict[str, Any]]:
        """Return directory-change audit events."""
        filters: dict[str, Any] = {"kind": "directory_audits"}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects(
            "observed-data", filters=filters, page_size=999
        )

    def list_risky_users(
        self, risk_level: str = ""
    ) -> list[dict[str, Any]]:
        """Return Identity Protection risky-user entries."""
        filters: dict[str, Any] = {"kind": "risky_users"}
        if risk_level:
            filters["filter"] = f"riskLevel eq '{risk_level}'"
        return self.list_objects(
            "observed-data", filters=filters, page_size=999
        )

    def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Return configured Conditional Access policies."""
        resp = self.get("/v1.0/identity/conditionalAccess/policies")
        return [
            dict(r, _entra_kind="conditional_access")
            for r in _extract_entra_value(resp)
        ]

    def list_organization(self) -> list[dict[str, Any]]:
        """Return the tenant organization record."""
        resp = self.get("/v1.0/organization")
        return _extract_entra_value(resp)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Entra ID record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Entra ID to_stix expects a dict input")

        kind = native.get("_entra_kind") or "user"

        if kind == "user":
            user_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_ENTRA, f"user-account|{user_id}")
            return {
                "type": "user-account",
                "id": f"user-account--{stix_uuid}",
                "spec_version": "2.1",
                "account_login": native.get("userPrincipalName"),
                "display_name": native.get("displayName"),
                "account_type": "azure",
                "x_entra_id": {
                    "user_id": user_id,
                    "mail": native.get("mail"),
                    "job_title": native.get("jobTitle"),
                    "department": native.get("department"),
                    "account_enabled": native.get("accountEnabled"),
                    "usage_location": native.get("usageLocation"),
                    "raw": native,
                },
            }

        if kind == "group":
            group_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_ENTRA, f"identity|group|{group_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": "2.1",
                "created": native.get("createdDateTime") or utcnow(),
                "modified": utcnow(),
                "name": native.get("displayName") or f"Entra group {group_id}",
                "identity_class": "group",
                "description": native.get("description") or "",
                "x_entra_id_group": {
                    "group_id": group_id,
                    "mail": native.get("mail"),
                    "security_enabled": native.get("securityEnabled"),
                    "mail_enabled": native.get("mailEnabled"),
                    "group_types": native.get("groupTypes") or [],
                    "raw": native,
                },
            }

        if kind == "service_principal":
            sp_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_ENTRA, f"x-entra-application|{sp_id}"
            )
            return {
                "type": "x-entra-application",
                "id": f"x-entra-application--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("displayName") or sp_id,
                "app_id": native.get("appId"),
                "account_enabled": native.get("accountEnabled"),
                "publisher_name": native.get("publisherName"),
                "x_entra_id_app": {"raw": native},
            }

        if kind == "conditional_access":
            pol_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_ENTRA, f"x-entra-ca-policy|{pol_id}"
            )
            return {
                "type": "x-entra-ca-policy",
                "id": f"x-entra-ca-policy--{stix_uuid}",
                "spec_version": "2.1",
                "name": native.get("displayName") or pol_id,
                "state": native.get("state"),
                "x_entra_id_policy": {"raw": native},
            }

        # observed-data envelope (sign_in / directory_audit / risky_user)
        refs: list[str] = []
        user_id: str | None = native.get("userId") or native.get(
            "userPrincipalName"
        )
        if not user_id and isinstance(native.get("initiatedBy"), dict):
            init_user = native["initiatedBy"].get("user") or {}
            if isinstance(init_user, dict):
                user_id = init_user.get("id") or init_user.get(
                    "userPrincipalName"
                )
        if user_id:
            user_uuid = uuid.uuid5(_NAMESPACE_ENTRA, f"user-account|{user_id}")
            refs.append(f"user-account--{user_uuid}")

        ip = native.get("ipAddress") or native.get("clientIP")
        if ip:
            ip_uuid = uuid.uuid5(_NAMESPACE_ENTRA, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("createdDateTime")
            or native.get("activityDateTime")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="entra_id",
            x_extensions={
                "entra_id": {
                    "kind": kind,
                    "event_id": native.get("id"),
                    "app_display_name": native.get("appDisplayName"),
                    "client_app_used": native.get("clientAppUsed"),
                    "conditional_access_status": native.get(
                        "conditionalAccessStatus"
                    ),
                    "risk_level_aggregated": native.get("riskLevelAggregated"),
                    "risk_state": native.get("riskState"),
                    "activity": native.get("activityDisplayName"),
                    "result": native.get("result")
                    or native.get("status", {}).get("errorCode")
                    if isinstance(native.get("status"), dict)
                    else native.get("result"),
                    "location_city": (native.get("location") or {}).get("city")
                    if isinstance(native.get("location"), dict)
                    else None,
                    "location_country": (native.get("location") or {}).get(
                        "countryOrRegion"
                    )
                    if isinstance(native.get("location"), dict)
                    else None,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Entra ID connector is read-only."""
        return {
            "note": (
                "Entra ID connector is read-only. Use list_users, "
                "list_groups, list_group_members, list_service_principals, "
                "list_sign_ins, list_directory_audits, list_risky_users, "
                "list_conditional_access_policies, or list_organization "
                "to query the Graph API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_entra_value(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Microsoft Graph OData response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    value = resp.get("value")
    if isinstance(value, list):
        return [r for r in value if isinstance(r, dict)]
    return [resp]
