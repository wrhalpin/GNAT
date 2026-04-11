# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gitguardian.client
======================================

GitGuardian connector — real-time secret detection and incident telemetry.

Authentication
--------------
Personal / Service Account API key via ``Authorization: Token <key>``::

    [gitguardian]
    host    = https://api.gitguardian.com
    api_key = gg_...

Key endpoints
-------------
* ``GET  /v1/incidents/secrets`` — list incidents with filters
* ``GET  /v1/incidents/secrets/{id}`` — fetch a single incident
* ``GET  /v1/sources`` — connected git sources
* ``GET  /v1/members`` — workspace members
* ``GET  /v1/health_check`` — authenticated liveness probe
* ``POST /v1/scan`` — ad-hoc content scan (exposed as ``scan_content``)
* ``POST /v1/multiscan`` — batched content scan

STIX Type Mapping
-----------------
GitGuardian incidents are mapped to STIX 2.1 ``observed-data`` envelopes
wrapping the leaked file and (when known) the committing identity.  All
vendor-specific context (repository, secret type, validity, severity,
assignee) lives under ``x_gitguardian``.

Notes
-----
* **Read-only by default.**  ``upsert_object`` and ``delete_object``
  raise :class:`GNATClientError`; content scans are exposed as domain
  helpers, not as part of the standard CRUD contract.
* All reference counts / pagination cursors follow GitGuardian's
  ``Link`` header convention; this connector exposes simple
  offset/limit semantics and lets the caller page manually.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

# Deterministic UUID-5 namespace for GitGuardian observable/envelope ids.
_NAMESPACE_GITGUARDIAN = uuid.UUID("b17e7fca-5e13-4f38-9af5-61f93e7b5c11")


class GitGuardianClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the GitGuardian v1 REST API.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.gitguardian.com"``.
    api_key : str
        GitGuardian API key (Personal or Service Account).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incidents/secrets",
        "identity": "members",
    }

    def __init__(
        self,
        host: str = "https://api.gitguardian.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize GitGuardianClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Token header from the configured API key."""
        if not self.api_key:
            raise GNATClientError(
                "GitGuardian connector requires api_key in config."
            )
        self._auth_headers["Authorization"] = f"Token {self.api_key}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/health_check`` as an authenticated liveness probe."""
        try:
            self.get("/v1/health_check")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single GitGuardian resource.

        Supported ``stix_type`` values:

        * ``"observed-data"`` — fetches ``/v1/incidents/secrets/{id}``
        * ``"identity"`` — fetches ``/v1/members/{id}``
        """
        if not object_id:
            raise GNATClientError("GitGuardian get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/incidents/secrets/{object_id}")
        elif stix_type == "identity":
            resp = self.get(f"/v1/members/{object_id}")
        else:
            raise GNATClientError(
                f"GitGuardian get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"GitGuardian returned unexpected payload for {object_id!r}"
            )
        return resp

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List GitGuardian resources.

        ``filters`` keys (``observed-data``):

        * ``status``: ``"TRIGGERED"`` / ``"ASSIGNED"`` / ``"RESOLVED"`` / ``"IGNORED"``
        * ``severity``: ``"critical"`` / ``"high"`` / ``"medium"`` / ``"low"`` / ``"info"``
        * ``validity``: ``"valid"`` / ``"invalid"`` / ``"unknown"``
        * ``from_date`` / ``to_date``: ISO 8601 timestamp strings
        * ``source_name``: repository full name substring
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"per_page": int(page_size)}
        # GitGuardian uses cursor pagination; translate the (page, page_size)
        # abstraction to ``cursor`` when the caller supplies one.
        if "cursor" in filters:
            params["cursor"] = filters.pop("cursor")

        if stix_type == "observed-data":
            for key in ("status", "severity", "validity", "from_date", "to_date", "source_name"):
                val = filters.get(key)
                if val:
                    params[key] = val
            resp = self.get("/v1/incidents/secrets", params=params)
        elif stix_type == "identity":
            resp = self.get("/v1/members", params=params)
        elif stix_type == "x-gitguardian-source":
            resp = self.get("/v1/sources", params=params)
        else:
            raise GNATClientError(
                f"GitGuardian list_objects does not support stix_type={stix_type!r}"
            )

        if isinstance(resp, list):
            return resp
        if isinstance(resp, dict):
            # Some GitGuardian endpoints wrap results in a ``data`` key
            data = resp.get("data") or resp.get("results") or []
            if isinstance(data, list):
                return data
        return []

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """GitGuardian connector is read-only (incident creation belongs to GG scanners)."""
        raise GNATClientError(
            "GitGuardian connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """GitGuardian connector is read-only."""
        raise GNATClientError(
            "GitGuardian connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_incidents(
        self,
        status: str = "",
        severity: str = "",
        validity: str = "",
        from_date: str = "",
        to_date: str = "",
        source_name: str = "",
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Convenience wrapper around ``list_objects("observed-data", …)``."""
        filters: dict[str, Any] = {}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity
        if validity:
            filters["validity"] = validity
        if from_date:
            filters["from_date"] = from_date
        if to_date:
            filters["to_date"] = to_date
        if source_name:
            filters["source_name"] = source_name
        return self.list_objects(
            "observed-data", filters=filters, page_size=page_size
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single secret incident by id."""
        return self.get_object("observed-data", str(incident_id))

    def list_sources(self, page_size: int = 100) -> list[dict[str, Any]]:
        """List connected git sources (repositories)."""
        return self.list_objects("x-gitguardian-source", page_size=page_size)

    def list_members(self, page_size: int = 100) -> list[dict[str, Any]]:
        """List workspace members / service accounts."""
        return self.list_objects("identity", page_size=page_size)

    def scan_content(self, document: str, filename: str = "") -> dict[str, Any]:
        """
        Ad-hoc scan of a single document via ``POST /v1/scan``.

        Returns the raw GitGuardian response describing any detected
        secrets.  This is a read-only analysis helper — no data is stored
        server-side unless the caller explicitly opts in.
        """
        body: dict[str, Any] = {"document": document}
        if filename:
            body["filename"] = filename
        resp = self.post("/v1/scan", json=body)
        return resp if isinstance(resp, dict) else {"raw": resp}

    def scan_content_batch(
        self, documents: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        """
        Batch content scan via ``POST /v1/multiscan``.

        *documents* is a list of dicts, each with ``document`` and
        optionally ``filename`` keys.
        """
        resp = self.post("/v1/multiscan", json=documents)
        if isinstance(resp, list):
            return resp
        return [resp] if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a GitGuardian incident dict to a STIX 2.1 ``observed-data``.

        The envelope wraps a synthetic ``file`` observable reference for
        the leaked secret plus (if present) an ``identity`` reference for
        the committing user.  Vendor fields live under
        ``x_gitguardian`` and ``x_gitguardian_occurrences``.
        """
        if not isinstance(native, dict):
            raise GNATClientError("GitGuardian to_stix expects a dict input")

        incident_id = str(native.get("id", ""))
        refs: list[str] = []

        # File observable — derived from the first occurrence's filepath
        occurrences = native.get("occurrences") or []
        first_occ = (
            occurrences[0] if isinstance(occurrences, list) and occurrences else {}
        )
        filepath = first_occ.get("filepath") if isinstance(first_occ, dict) else ""
        if filepath:
            file_uuid = uuid.uuid5(
                _NAMESPACE_GITGUARDIAN,
                f"file|{incident_id}|{filepath}",
            )
            refs.append(f"file--{file_uuid}")

        # Identity observable — derived from the committing author
        author = first_occ.get("author") if isinstance(first_occ, dict) else ""
        if author:
            ident_uuid = uuid.uuid5(_NAMESPACE_GITGUARDIAN, f"identity|{author}")
            refs.append(f"identity--{ident_uuid}")

        first = (
            native.get("date")
            or native.get("first_occurrence_date")
            or native.get("created_at")
            or utcnow()
        )
        last = (
            native.get("last_occurrence_date")
            or native.get("updated_at")
            or first
        )

        envelope = make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=max(1, len(occurrences) if isinstance(occurrences, list) else 1),
            object_refs=refs,
            source_name="gitguardian",
            x_extensions={
                "gitguardian": {
                    "incident_id": incident_id,
                    "secret_type": native.get("detector", {}).get("name")
                    if isinstance(native.get("detector"), dict)
                    else native.get("detector"),
                    "secret_family": native.get("detector", {}).get("family")
                    if isinstance(native.get("detector"), dict)
                    else None,
                    "status": native.get("status"),
                    "severity": native.get("severity"),
                    "validity": native.get("validity"),
                    "assignee_email": native.get("assignee_email"),
                    "assignee_id": native.get("assignee_id"),
                    "secrets_engine": native.get("secrets_engine"),
                    "repository": first_occ.get("source"),
                    "url": native.get("gitguardian_url") or native.get("url"),
                },
                "gitguardian_occurrences": occurrences,
            },
        )
        return envelope

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """GitGuardian is read-only; returns an informational stub."""
        return {
            "note": (
                "GitGuardian connector is read-only. Use list_incidents, "
                "get_incident, scan_content, or scan_content_batch to "
                "query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
