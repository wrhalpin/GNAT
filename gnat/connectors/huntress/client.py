# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.huntress.client
===================================

Huntress Managed EDR / ITDR connector.

Authentication
--------------
Huntress uses HTTP Basic with the API Key ID as username and the API
Secret as password::

    [huntress]
    host       = https://api.huntress.io
    api_key_id = hk_...
    api_secret = hs_...

Key endpoints
-------------
* ``GET /v1/account``            — account info + liveness probe
* ``GET /v1/organizations``      — managed organizations
* ``GET /v1/agents``             — deployed agents / endpoints
* ``GET /v1/agents/{id}``
* ``GET /v1/incident_reports``   — security incidents (alerts)
* ``GET /v1/incident_reports/{id}``
* ``GET /v1/reports``            — monthly summaries
* ``GET /v1/signals``            — raw EDR signals

STIX Type Mapping
-----------------
* ``observed-data`` → incident reports + EDR signals (envelopes wrap
  the affected agent as a synthetic ``identity`` + any involved
  ``ipv4-addr`` refs)
* ``identity``      → managed organizations
* ``x-huntress-agent`` → deployed agents (custom SCO; exposed via
  domain helper)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_HUNTRESS = uuid.UUID("81700707-0001-4a1e-9b1c-81700707c0fe")


class HuntressClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Huntress Managed EDR / ITDR API.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.huntress.io"``.
    api_key_id : str
        Huntress API Key ID (used as HTTP Basic username).
    api_secret : str
        Huntress API Secret (used as HTTP Basic password).
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incident_reports",
        "identity": "organizations",
    }

    def __init__(
        self,
        host: str = "https://api.huntress.io",
        api_key_id: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize HuntressClient."""
        super().__init__(host=host, **kwargs)
        self.api_key_id = api_key_id
        self.api_secret = api_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set HTTP Basic Authorization header from the configured creds."""
        if not self.api_key_id or not self.api_secret:
            raise GNATClientError(
                "Huntress connector requires api_key_id and api_secret."
            )
        self._auth_headers["Authorization"] = self._basic_auth(
            self.api_key_id, self.api_secret
        )
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/account`` as a cheap authenticated probe."""
        try:
            self.get("/v1/account")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Huntress record by id."""
        if not object_id:
            raise GNATClientError("Huntress get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/incident_reports/{object_id}")
            kind = "incident"
        elif stix_type == "identity":
            resp = self.get(f"/v1/organizations/{object_id}")
            kind = "organization"
        elif stix_type == "x-huntress-agent":
            resp = self.get(f"/v1/agents/{object_id}")
            kind = "agent"
        else:
            raise GNATClientError(
                f"Huntress get_object does not support stix_type={stix_type!r}"
            )
        data = _unwrap_huntress(resp)
        if not isinstance(data, dict):
            raise GNATClientError(
                f"Huntress returned unexpected payload for {object_id!r}"
            )
        return dict(data, _ht_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Huntress records.

        ``filters`` keys:

        * ``status``, ``severity``, ``updated_at_min``, ``updated_at_max``
          — passed through for incident reports
        * ``organization_id`` — restrict results to an organization
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "limit": int(page_size)}
        for key in (
            "status",
            "severity",
            "updated_at_min",
            "updated_at_max",
            "organization_id",
        ):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            resp = self.get("/v1/incident_reports", params=params)
            kind = "incident"
        elif stix_type == "identity":
            resp = self.get("/v1/organizations", params=params)
            kind = "organization"
        elif stix_type == "x-huntress-agent":
            resp = self.get("/v1/agents", params=params)
            kind = "agent"
        else:
            raise GNATClientError(
                f"Huntress list_objects does not support stix_type={stix_type!r}"
            )
        return [
            dict(r, _ht_kind=kind)
            for r in _extract_huntress_list(resp)
        ]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Huntress connector is read-only."""
        raise GNATClientError(
            "Huntress connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Huntress connector is read-only."""
        raise GNATClientError(
            "Huntress connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_organizations(self) -> list[dict[str, Any]]:
        """Return all managed organizations."""
        return self.list_objects("identity", page_size=1000)

    def list_agents(
        self, organization_id: str = ""
    ) -> list[dict[str, Any]]:
        """Return deployed Huntress agents, optionally filtered by org."""
        filters: dict[str, Any] = {}
        if organization_id:
            filters["organization_id"] = organization_id
        return self.list_objects(
            "x-huntress-agent", filters=filters, page_size=1000
        )

    def list_incidents(
        self,
        status: str = "",
        severity: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        """Return incident reports filtered by status/severity/time."""
        filters: dict[str, Any] = {}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity
        if since:
            filters["updated_at_min"] = since
        return self.list_objects(
            "observed-data", filters=filters, page_size=1000
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single incident report."""
        return self.get_object("observed-data", incident_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Huntress record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Huntress to_stix expects a dict input")

        kind = native.get("_ht_kind") or "incident"

        if kind == "organization":
            org_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_HUNTRESS, f"identity|org|{org_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or f"Huntress org {org_id}",
                "identity_class": "organization",
                "x_huntress": {"raw": native},
            }

        if kind == "agent":
            agent_id = native.get("id") or ""
            stix_uuid = uuid.uuid5(
                _NAMESPACE_HUNTRESS, f"agent|{agent_id}"
            )
            return {
                "type": "x-huntress-agent",
                "id": f"x-huntress-agent--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "hostname": native.get("hostname"),
                "platform": native.get("platform"),
                "version": native.get("version"),
                "organization_id": native.get("organization_id"),
                "x_huntress": {"raw": native},
            }

        # incident → observed-data envelope
        refs: list[str] = []
        org_id = native.get("organization_id")
        if org_id:
            org_uuid = uuid.uuid5(
                _NAMESPACE_HUNTRESS, f"identity|org|{org_id}"
            )
            refs.append(f"identity--{org_uuid}")

        agent_id = native.get("agent_id")
        if agent_id:
            agent_uuid = uuid.uuid5(
                _NAMESPACE_HUNTRESS, f"agent|{agent_id}"
            )
            refs.append(f"x-huntress-agent--{agent_uuid}")

        ip = native.get("remote_ip") or native.get("source_ip")
        if ip:
            ip_uuid = uuid.uuid5(
                _NAMESPACE_HUNTRESS, f"ipv4-addr|{ip}"
            )
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("detected_at")
            or native.get("created_at")
            or native.get("updated_at")
            or utcnow()
        )
        last = native.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="huntress",
            x_extensions={
                "huntress": {
                    "incident_id": native.get("id"),
                    "status": native.get("status"),
                    "severity": native.get("severity"),
                    "summary": native.get("summary")
                    or native.get("display_name"),
                    "incident_type": native.get("type"),
                    "organization_id": org_id,
                    "agent_id": agent_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Huntress connector is read-only."""
        return {
            "note": (
                "Huntress connector is read-only. Use list_organizations, "
                "list_agents, list_incidents, or get_incident to query "
                "the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _unwrap_huntress(resp: Any) -> Any:
    """Strip Huntress's single-key envelope (e.g. ``{"organization": ...}``)."""
    if isinstance(resp, dict) and len(resp) == 1:
        only = next(iter(resp.values()))
        if isinstance(only, dict):
            return only
    return resp


def _extract_huntress_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Huntress list response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in (
        "organizations",
        "agents",
        "incident_reports",
        "reports",
        "signals",
        "data",
        "results",
    ):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
