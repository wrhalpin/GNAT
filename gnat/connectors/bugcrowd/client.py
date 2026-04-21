# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.bugcrowd.client
===================================

Bugcrowd managed bug bounty / VDP connector.

Authentication
--------------
API token in the ``Authorization: Token <token>`` header (issued from
the Bugcrowd customer portal)::

    [bugcrowd]
    host      = https://api.bugcrowd.com
    api_token = bc_token

Bugcrowd v4 uses a JSON:API style envelope. Endpoints used by this
connector:

* ``GET  /submissions``                            — bug submissions
* ``GET  /submissions/{id}``
* ``GET  /programs``                               — engagement programs
* ``GET  /programs/{id}``
* ``GET  /programs/{id}/targets``                  — in-scope assets
* ``GET  /programs/{id}/rewards``                  — bounty pool rewards
* ``GET  /reports`` (managed services)             — pentest reports
* ``GET  /organizations``                          — your tenant orgs
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_BC = uuid.UUID("b09c20d1-0001-4a1e-9b1e-b09c20d1c0fe")


class BugcrowdClient(BaseClient, ConnectorMixin):
    """HTTP client for Bugcrowd."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v4"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "submissions",
        "x-bugcrowd-program": "programs",
        "x-bugcrowd-target": "targets",
    }

    def __init__(
        self,
        host: str = "https://api.bugcrowd.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize BugcrowdClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    def authenticate(self) -> None:
        """Set the proprietary ``Authorization: Token`` header."""
        if not self.api_token:
            raise GNATClientError("Bugcrowd connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"Token {self.api_token}"
        self._auth_headers["Accept"] = "application/vnd.bugcrowd+json"

    def health_check(self) -> bool:
        """Query a tiny page of organizations as a liveness probe."""
        try:
            self.get("/organizations", params={"page[limit]": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Bugcrowd record by id."""
        if not object_id:
            raise GNATClientError("Bugcrowd get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/submissions/{object_id}")
            kind = "submission"
        elif stix_type == "x-bugcrowd-program":
            resp = self.get(f"/programs/{object_id}")
            kind = "program"
        else:
            raise GNATClientError(f"Bugcrowd get_object does not support stix_type={stix_type!r}")
        record = resp.get("data") if isinstance(resp, dict) else None
        if not isinstance(record, dict):
            raise GNATClientError(f"Bugcrowd returned unexpected payload for {object_id!r}")
        return dict(record, _bc_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Bugcrowd records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page[limit]": int(page_size),
            "page[offset]": int((page - 1) * page_size),
        }
        for key, qkey in (
            ("state", "filter[state]"),
            ("severity", "filter[severity]"),
            ("program", "filter[program]"),
        ):
            if filters.get(key):
                params[qkey] = filters[key]
        program = filters.get("program_id")

        if stix_type == "observed-data":
            resp = self.get("/submissions", params=params)
            tag = "submission"
        elif stix_type == "x-bugcrowd-program":
            resp = self.get("/programs", params=params)
            tag = "program"
        elif stix_type == "x-bugcrowd-target":
            if not program:
                raise GNATClientError("Bugcrowd target listing requires 'program_id'")
            resp = self.get(f"/programs/{program}/targets", params=params)
            tag = "target"
        elif stix_type == "x-bugcrowd-reward":
            if not program:
                raise GNATClientError("Bugcrowd reward listing requires 'program_id'")
            resp = self.get(f"/programs/{program}/rewards", params=params)
            tag = "reward"
        elif stix_type == "x-bugcrowd-report":
            resp = self.get("/reports", params=params)
            tag = "pentest_report"
        elif stix_type == "x-bugcrowd-organization":
            resp = self.get("/organizations", params=params)
            tag = "organization"
        else:
            raise GNATClientError(f"Bugcrowd list_objects does not support stix_type={stix_type!r}")
        items = resp.get("data", []) if isinstance(resp, dict) else []
        return [dict(r, _bc_kind=tag) for r in items if isinstance(r, dict)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Bugcrowd connector is read-only via CRUD."""
        raise GNATClientError(
            "Bugcrowd connector is read-only via CRUD. Use add_submission_comment "
            "or change_submission_state domain helpers for write operations."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Bugcrowd connector is read-only."""
        raise GNATClientError("Bugcrowd connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_submissions(
        self,
        state: str = "",
        severity: str = "",
        program: str = "",
    ) -> list[dict[str, Any]]:
        """Return bug submissions filtered by state/severity/program."""
        filters: dict[str, Any] = {}
        if state:
            filters["state"] = state
        if severity:
            filters["severity"] = severity
        if program:
            filters["program"] = program
        return self.list_objects("observed-data", filters=filters, page_size=100)

    def get_submission(self, submission_id: str) -> dict[str, Any]:
        """Fetch a single submission by id."""
        return self.get_object("observed-data", submission_id)

    def list_programs(self) -> list[dict[str, Any]]:
        """Return engagement programs."""
        return self.list_objects("x-bugcrowd-program", page_size=100)

    def get_program(self, program_id: str) -> dict[str, Any]:
        """Fetch a single program by id."""
        return self.get_object("x-bugcrowd-program", program_id)

    def list_targets(self, program_id: str) -> list[dict[str, Any]]:
        """Return in-scope targets for a program."""
        return self.list_objects(
            "x-bugcrowd-target",
            filters={"program_id": program_id},
            page_size=200,
        )

    def list_rewards(self, program_id: str) -> list[dict[str, Any]]:
        """Return bounty rewards configured for a program."""
        return self.list_objects(
            "x-bugcrowd-reward",
            filters={"program_id": program_id},
            page_size=200,
        )

    def list_pentest_reports(self) -> list[dict[str, Any]]:
        """Return managed-pentest reports (Bugcrowd Pentest as a Service)."""
        return self.list_objects("x-bugcrowd-report", page_size=100)

    def list_organizations(self) -> list[dict[str, Any]]:
        """Return your tenant organizations."""
        return self.list_objects("x-bugcrowd-organization", page_size=100)

    def add_submission_comment(
        self, submission_id: str, message: str, internal: bool = False
    ) -> dict[str, Any]:
        """Add a comment to a submission."""
        body = {
            "data": {
                "type": "comment",
                "attributes": {
                    "body": message,
                    "internal": bool(internal),
                },
            }
        }
        resp = self.post(f"/submissions/{submission_id}/comments", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    def change_submission_state(
        self,
        submission_id: str,
        state: str,
        message: str = "",
    ) -> dict[str, Any]:
        """Change a submission's state (triaged / unresolved / resolved / ...)."""
        attrs: dict[str, Any] = {"state": state}
        if message:
            attrs["message"] = message
        body = {"data": {"type": "submission", "attributes": attrs}}
        resp = self.patch(f"/submissions/{submission_id}", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Bugcrowd record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Bugcrowd to_stix expects a dict input")

        kind = native.get("_bc_kind") or "submission"
        attrs = native.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}

        if kind == "program":
            program_id = native.get("id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_BC, f"x-bugcrowd-program|{program_id}")
            return {
                "type": "x-bugcrowd-program",
                "id": f"x-bugcrowd-program--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "program_id": program_id,
                "name": attrs.get("name"),
                "code": attrs.get("code"),
                "x_bugcrowd": {"raw": native},
            }

        if kind == "target":
            tid = native.get("id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_BC, f"x-bugcrowd-target|{tid}")
            return {
                "type": "x-bugcrowd-target",
                "id": f"x-bugcrowd-target--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": attrs.get("name"),
                "category": attrs.get("category"),
                "uri": attrs.get("uri") or attrs.get("url"),
                "x_bugcrowd": {"raw": native},
            }

        if kind == "reward":
            rid = native.get("id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_BC, f"x-bugcrowd-reward|{rid}")
            return {
                "type": "x-bugcrowd-reward",
                "id": f"x-bugcrowd-reward--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "amount": attrs.get("amount"),
                "currency": attrs.get("currency"),
                "severity": attrs.get("severity"),
                "x_bugcrowd": {"raw": native},
            }

        if kind == "organization":
            oid = native.get("id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_BC, f"x-bugcrowd-organization|{oid}")
            return {
                "type": "x-bugcrowd-organization",
                "id": f"x-bugcrowd-organization--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": attrs.get("name"),
                "x_bugcrowd": {"raw": native},
            }

        if kind == "pentest_report":
            rid = native.get("id", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_BC, f"x-bugcrowd-report|{rid}")
            return {
                "type": "x-bugcrowd-report",
                "id": f"x-bugcrowd-report--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "title": attrs.get("title"),
                "state": attrs.get("state"),
                "x_bugcrowd": {"raw": native},
            }

        # submission → observed-data envelope
        sid = native.get("id", "")
        first = attrs.get("created_at") or attrs.get("submitted_at") or utcnow()
        last = attrs.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=[],
            source_name="bugcrowd",
            x_extensions={
                "bugcrowd": {
                    "submission_id": sid,
                    "title": attrs.get("title"),
                    "state": attrs.get("state"),
                    "severity": attrs.get("severity"),
                    "vrt_id": attrs.get("vrt_id"),
                    "description": attrs.get("description")
                    or attrs.get("vulnerability_information"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Bugcrowd connector is read-only via CRUD."""
        return {
            "note": (
                "Bugcrowd connector is read-only via CRUD. Use list_submissions, "
                "get_submission, list_programs, list_targets, list_rewards, "
                "list_pentest_reports, add_submission_comment, or "
                "change_submission_state to interact."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
