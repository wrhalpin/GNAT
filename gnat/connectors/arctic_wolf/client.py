# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.arctic_wolf.client
======================================

Arctic Wolf Managed Detection & Response (MDR) connector.

Authentication
--------------
API key via ``Authorization: Bearer <api_key>`` header with an optional
``X-Arctic-Wolf-Customer`` header for multi-tenant MSSPs::

    [arctic_wolf]
    host         = https://api.arcticwolf.com
    api_key      = aw_...
    customer_id  = my-customer

Key endpoints
-------------
* ``GET /v1/tickets``            — Arctic Wolf tickets (the primary
  incident unit of work in the MDR delivery model)
* ``GET /v1/tickets/{id}``
* ``GET /v1/tickets/{id}/comments``
* ``GET /v1/investigations``     — investigation records
* ``GET /v1/investigations/{id}``
* ``GET /v1/customer``           — customer details + liveness probe

STIX Type Mapping
-----------------
* ``observed-data`` → tickets + investigations (envelope wraps the
  customer identity and any involved endpoint IPs)
* ``identity``      → customer account
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_ARCTICWOLF = uuid.UUID("a2c71cf0-0001-4a1e-9b1c-a2c71cf0c0fe")


class ArcticWolfClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Arctic Wolf MDR.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.arcticwolf.com"``.
    api_key : str
        Arctic Wolf API key.
    customer_id : str, optional
        Customer id sent in the ``X-Arctic-Wolf-Customer`` header for
        multi-tenant MSSP deployments.  Optional for single-tenant.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "tickets",
        "identity": "customer",
    }

    def __init__(
        self,
        host: str = "https://api.arcticwolf.com",
        api_key: str = "",
        customer_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize ArcticWolfClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        self.customer_id = customer_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization + optional Customer headers."""
        if not self.api_key:
            raise GNATClientError(
                "Arctic Wolf connector requires api_key in config."
            )
        self._auth_headers["Authorization"] = f"Bearer {self.api_key}"
        self._auth_headers["Accept"] = "application/json"
        if self.customer_id:
            self._auth_headers["X-Arctic-Wolf-Customer"] = self.customer_id

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/customer`` as a cheap authenticated probe."""
        try:
            self.get("/v1/customer")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Arctic Wolf record by id."""
        if not object_id:
            raise GNATClientError("Arctic Wolf get_object requires a non-empty id")
        if stix_type == "observed-data":
            # Default to tickets; investigations available via list_objects
            resp = self.get(f"/v1/tickets/{object_id}")
            kind = "ticket"
        elif stix_type == "identity":
            resp = self.get(f"/v1/customer/{object_id}")
            kind = "customer"
        else:
            raise GNATClientError(
                f"Arctic Wolf get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Arctic Wolf returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _aw_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Arctic Wolf records.

        ``filters`` keys:

        * ``kind`` — ``"tickets"`` (default) or ``"investigations"`` for
          ``observed-data``
        * ``status`` / ``severity`` / ``created_after`` — passed through
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "limit": int(page_size)}
        for key in ("status", "severity", "created_after", "updated_after"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "tickets").lower()
            if kind == "investigations":
                resp = self.get("/v1/investigations", params=params)
                tag = "investigation"
            else:
                resp = self.get("/v1/tickets", params=params)
                tag = "ticket"
        elif stix_type == "identity":
            resp = self.get("/v1/customer", params=params)
            tag = "customer"
        else:
            raise GNATClientError(
                f"Arctic Wolf list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _aw_kind=tag) for r in _extract_aw_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Arctic Wolf connector is read-only."""
        raise GNATClientError(
            "Arctic Wolf connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Arctic Wolf connector is read-only."""
        raise GNATClientError(
            "Arctic Wolf connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_tickets(
        self, status: str = "", severity: str = ""
    ) -> list[dict[str, Any]]:
        """Return Arctic Wolf tickets (MDR delivery workflow units)."""
        filters: dict[str, Any] = {"kind": "tickets"}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity
        return self.list_objects(
            "observed-data", filters=filters, page_size=1000
        )

    def list_investigations(self) -> list[dict[str, Any]]:
        """Return Arctic Wolf investigation records."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "investigations"},
            page_size=1000,
        )

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        """Fetch a single ticket by id."""
        return self.get_object("observed-data", ticket_id)

    def get_ticket_comments(self, ticket_id: str) -> list[dict[str, Any]]:
        """Fetch analyst comments for a ticket."""
        resp = self.get(f"/v1/tickets/{ticket_id}/comments")
        return _extract_aw_list(resp)

    def get_customer(self) -> dict[str, Any]:
        """Fetch the customer account record."""
        resp = self.get("/v1/customer")
        if isinstance(resp, dict):
            return dict(resp, _aw_kind="customer")
        return {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Arctic Wolf record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Arctic Wolf to_stix expects a dict input")

        kind = native.get("_aw_kind") or "ticket"

        if kind == "customer":
            cust_id = native.get("id") or self.customer_id or "unknown"
            stix_uuid = uuid.uuid5(
                _NAMESPACE_ARCTICWOLF, f"identity|customer|{cust_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name")
                or f"Arctic Wolf customer {cust_id}",
                "identity_class": "organization",
                "x_arctic_wolf": {"raw": native},
            }

        # ticket or investigation → observed-data envelope
        refs: list[str] = []
        cust_id = native.get("customer_id") or self.customer_id
        if cust_id:
            cust_uuid = uuid.uuid5(
                _NAMESPACE_ARCTICWOLF, f"identity|customer|{cust_id}"
            )
            refs.append(f"identity--{cust_uuid}")

        for ip in _values(native.get("affected_ips") or native.get("ips")):
            ip_uuid = uuid.uuid5(
                _NAMESPACE_ARCTICWOLF, f"ipv4-addr|{ip}"
            )
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("created_at")
            or native.get("detected_at")
            or utcnow()
        )
        last = native.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="arctic_wolf",
            x_extensions={
                "arctic_wolf": {
                    "kind": kind,
                    "ticket_id": native.get("id"),
                    "status": native.get("status"),
                    "severity": native.get("severity"),
                    "title": native.get("title"),
                    "summary": native.get("summary"),
                    "assigned_analyst": native.get("assigned_analyst"),
                    "customer_id": cust_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Arctic Wolf connector is read-only."""
        return {
            "note": (
                "Arctic Wolf connector is read-only. Use list_tickets, "
                "list_investigations, get_ticket, get_ticket_comments, "
                "or get_customer to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_aw_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an Arctic Wolf list response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("tickets", "investigations", "comments", "data", "results", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _values(container: Any) -> list[str]:
    """Normalize scalar / list / None into a list of strings."""
    if container is None:
        return []
    if isinstance(container, list):
        return [v for v in container if isinstance(v, str)]
    if isinstance(container, str):
        return [container]
    return []
