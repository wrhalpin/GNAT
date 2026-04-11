# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hackerone.client
====================================

HackerOne bug bounty / VDP platform connector.

Authentication
--------------
HTTP Basic, where the username is your HackerOne API username and the
password is the API token issued from your program settings::

    [hackerone]
    host         = https://api.hackerone.com
    api_username = h1_user
    api_token    = h1_token

Key endpoints
-------------
* ``GET /v1/reports``                       — bug bounty reports
* ``GET /v1/reports/{id}``
* ``GET /v1/programs``                      — programs you have access to
* ``GET /v1/programs/{handle}``
* ``GET /v1/me/programs``                   — programs the auth user runs
* ``GET /v1/{program}/structured_scopes``   — in-scope assets
* ``GET /v1/{program}/swag``                — swag fulfilment
* ``GET /v1/{program}/weaknesses``          — accepted weakness taxonomy

JSON:API style envelope: ``{"data": [...], "links": {...}}``. The
connector strips the envelope and tags items with ``_h1_kind``.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_H1 = uuid.UUID("4ac9e201-0001-4a1e-9b1e-4ac9e201c0fe")


class HackerOneClient(BaseClient, ConnectorMixin):
    """HTTP client for HackerOne."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "reports",
        "vulnerability": "weaknesses",
        "x-h1-program": "programs",
    }

    def __init__(
        self,
        host: str = "https://api.hackerone.com",
        api_username: str = "",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize HackerOneClient."""
        super().__init__(host=host, **kwargs)
        self.api_username = api_username
        self.api_token = api_token

    def authenticate(self) -> None:
        """Set HTTP Basic header from username + token."""
        if not self.api_username or not self.api_token:
            raise GNATClientError(
                "HackerOne connector requires api_username and api_token."
            )
        self._auth_headers["Authorization"] = self._basic_auth(
            self.api_username, self.api_token
        )
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query the authenticated user's programs as a liveness probe."""
        try:
            self.get("/v1/me/programs", params={"page[size]": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single HackerOne record by id."""
        if not object_id:
            raise GNATClientError("HackerOne get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/reports/{object_id}")
            kind = "report"
        elif stix_type == "x-h1-program":
            resp = self.get(f"/v1/programs/{object_id}")
            kind = "program"
        else:
            raise GNATClientError(
                f"HackerOne get_object does not support stix_type={stix_type!r}"
            )
        record = resp.get("data") if isinstance(resp, dict) else None
        if not isinstance(record, dict):
            raise GNATClientError(
                f"HackerOne returned unexpected payload for {object_id!r}"
            )
        return dict(record, _h1_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List HackerOne records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page[number]": int(page),
            "page[size]": int(page_size),
        }
        for key, qkey in (
            ("state", "filter[state][]"),
            ("severity", "filter[severity_rating][]"),
            ("program", "filter[program][]"),
        ):
            if filters.get(key):
                params[qkey] = filters[key]

        program = filters.get("program_handle")
        if stix_type == "observed-data":
            resp = self.get("/v1/reports", params=params)
            tag = "report"
        elif stix_type == "x-h1-program":
            kind = (filters.get("kind") or "all").lower()
            if kind == "mine":
                resp = self.get("/v1/me/programs", params=params)
            else:
                resp = self.get("/v1/programs", params=params)
            tag = "program"
        elif stix_type == "vulnerability":
            if not program:
                raise GNATClientError(
                    "HackerOne weakness listing requires 'program_handle'"
                )
            resp = self.get(f"/v1/{program}/weaknesses", params=params)
            tag = "weakness"
        elif stix_type == "x-h1-scope":
            if not program:
                raise GNATClientError(
                    "HackerOne scope listing requires 'program_handle'"
                )
            resp = self.get(
                f"/v1/{program}/structured_scopes", params=params
            )
            tag = "scope"
        else:
            raise GNATClientError(
                f"HackerOne list_objects does not support stix_type={stix_type!r}"
            )
        items = resp.get("data", []) if isinstance(resp, dict) else []
        return [dict(r, _h1_kind=tag) for r in items if isinstance(r, dict)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """HackerOne connector is read-only via CRUD."""
        raise GNATClientError(
            "HackerOne connector is read-only via CRUD. Use add_report_comment "
            "or change_report_state domain helpers for write operations."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """HackerOne connector is read-only."""
        raise GNATClientError(
            "HackerOne connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_reports(
        self,
        state: str = "",
        severity: str = "",
        program: str = "",
    ) -> list[dict[str, Any]]:
        """Return bug bounty reports filtered by state/severity/program."""
        filters: dict[str, Any] = {}
        if state:
            filters["state"] = state
        if severity:
            filters["severity"] = severity
        if program:
            filters["program"] = program
        return self.list_objects(
            "observed-data", filters=filters, page_size=100
        )

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Fetch a single report by id."""
        return self.get_object("observed-data", report_id)

    def list_programs(self, mine: bool = False) -> list[dict[str, Any]]:
        """Return programs you have access to (or run, if mine=True)."""
        return self.list_objects(
            "x-h1-program",
            filters={"kind": "mine" if mine else "all"},
            page_size=100,
        )

    def get_program(self, handle: str) -> dict[str, Any]:
        """Fetch a single program by handle."""
        return self.get_object("x-h1-program", handle)

    def list_weaknesses(self, program_handle: str) -> list[dict[str, Any]]:
        """Return the accepted weakness taxonomy for a program."""
        return self.list_objects(
            "vulnerability",
            filters={"program_handle": program_handle},
            page_size=200,
        )

    def list_structured_scopes(
        self, program_handle: str
    ) -> list[dict[str, Any]]:
        """Return the in-scope asset list for a program."""
        return self.list_objects(
            "x-h1-scope",
            filters={"program_handle": program_handle},
            page_size=200,
        )

    def add_report_comment(
        self, report_id: str, message: str, internal: bool = False
    ) -> dict[str, Any]:
        """Add a comment / activity entry to a report."""
        body: dict[str, Any] = {
            "data": {
                "type": "activity-comment",
                "attributes": {
                    "message": message,
                    "internal": bool(internal),
                },
            }
        }
        resp = self.post(f"/v1/reports/{report_id}/activities", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    def change_report_state(
        self, report_id: str, state: str, message: str = ""
    ) -> dict[str, Any]:
        """Change a report's state (triaged / resolved / informative / etc.)."""
        attrs: dict[str, Any] = {"state": state}
        if message:
            attrs["message"] = message
        body = {"data": {"type": "state-change", "attributes": attrs}}
        resp = self.post(f"/v1/reports/{report_id}/state_changes", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a HackerOne record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("HackerOne to_stix expects a dict input")

        kind = native.get("_h1_kind") or "report"
        attrs = native.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}

        if kind == "program":
            handle = native.get("id") or attrs.get("handle", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_H1, f"x-h1-program|{handle}")
            return {
                "type": "x-h1-program",
                "id": f"x-h1-program--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "handle": attrs.get("handle") or handle,
                "name": attrs.get("name"),
                "policy": attrs.get("policy"),
                "x_hackerone": {"raw": native},
            }

        if kind == "weakness":
            wid = native.get("id") or attrs.get("name", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_H1, f"vulnerability|{wid}")
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": attrs.get("name") or str(wid),
                "description": attrs.get("description"),
                "external_references": [
                    {
                        "source_name": "hackerone",
                        "external_id": str(wid),
                    }
                ],
                "x_hackerone": {"raw": native},
            }

        if kind == "scope":
            sid = native.get("id") or attrs.get("asset_identifier", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_H1, f"x-h1-scope|{sid}")
            return {
                "type": "x-h1-scope",
                "id": f"x-h1-scope--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "asset_type": attrs.get("asset_type"),
                "asset_identifier": attrs.get("asset_identifier"),
                "eligible_for_bounty": attrs.get("eligible_for_bounty"),
                "x_hackerone": {"raw": native},
            }

        # report → observed-data envelope
        report_id = native.get("id", "")
        first = (
            attrs.get("created_at")
            or attrs.get("submitted_at")
            or utcnow()
        )
        last = attrs.get("last_activity_at") or attrs.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=[],
            source_name="hackerone",
            x_extensions={
                "hackerone": {
                    "report_id": report_id,
                    "title": attrs.get("title"),
                    "state": attrs.get("state"),
                    "severity_rating": attrs.get("severity_rating"),
                    "vulnerability_information": attrs.get(
                        "vulnerability_information"
                    ),
                    "weakness": attrs.get("weakness"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """HackerOne connector is read-only via CRUD."""
        return {
            "note": (
                "HackerOne connector is read-only via CRUD. Use list_reports, "
                "get_report, list_programs, list_weaknesses, "
                "list_structured_scopes, add_report_comment, or "
                "change_report_state to interact with the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
