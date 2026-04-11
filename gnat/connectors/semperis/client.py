# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.semperis.client
===================================

Semperis Directory Services Protector (DSP) connector.

DSP monitors Active Directory and Entra ID for security drift, posture
violations (Indicators of Exposure), and runtime compromise signals
(Indicators of Compromise).  This connector exposes those signals as
STIX 2.1 ``indicator`` and ``observed-data`` objects.

Authentication
--------------
Bearer token::

    [semperis]
    host      = https://dsp.example.com
    api_token = dsp_...

Key endpoints
-------------
* ``GET /api/v1/IoEs`` — Indicators of Exposure (posture findings)
* ``GET /api/v1/IoCs`` — Indicators of Compromise
* ``GET /api/v1/Security/Evaluators`` — security evaluator rules
* ``GET /api/v1/Tenants/Forest/Domains`` — AD forest/domain inventory
* ``GET /api/v1/Security/Events`` — runtime security events

STIX Type Mapping
-----------------
* ``indicator``     → IoE + IoC records (patterns express the finding)
* ``observed-data`` → forest / domain posture snapshots, security events

Notes
-----
* ``TRUST_LEVEL`` is ``"trusted_internal"`` — AD posture data is the
  customer's own directory.
* **Read-only.**  ``upsert_object`` / ``delete_object`` raise.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_SEMPERIS = uuid.UUID("5e11e715-0dce-4a1b-9c3f-5e11e715abcd")


class SemperisClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Semperis DSP.

    Parameters
    ----------
    host : str
        Base URL of the DSP deployment.
    api_token : str
        DSP API bearer token.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "IoEs",
        "observed-data": "Security/Events",
    }

    def __init__(
        self,
        host: str = "",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SemperisClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header from the configured token."""
        if not self.api_token:
            raise GNATClientError(
                "Semperis connector requires api_token in config."
            )
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping ``/api/v1/Tenants/Forest/Domains`` as a liveness probe."""
        try:
            self.get("/api/v1/Tenants/Forest/Domains")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single IoE, IoC, or domain posture record by id."""
        if not object_id:
            raise GNATClientError("Semperis get_object requires a non-empty id")
        if stix_type == "indicator":
            resp = self.get(f"/api/v1/IoEs/{object_id}")
            kind = "ioe"
        elif stix_type == "observed-data":
            resp = self.get(f"/api/v1/Tenants/Forest/Domains/{object_id}")
            kind = "domain-posture"
        else:
            raise GNATClientError(
                f"Semperis get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Semperis returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _sem_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List DSP records.

        ``filters`` keys:

        * ``kind`` — ``"ioe"`` (default) or ``"ioc"`` for the indicator type
        * ``severity`` — ``"critical"`` / ``"high"`` / ``"medium"`` / ``"low"``
        * ``status`` — ``"open"`` / ``"resolved"`` / ``"ignored"``
        * ``evaluator`` — evaluator rule name
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "pageSize": int(page_size)}
        for key in ("severity", "status", "evaluator", "since", "until"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "indicator":
            kind_filter = (filters.get("kind") or "ioe").lower()
            if kind_filter == "ioc":
                resp = self.get("/api/v1/IoCs", params=params)
                kind = "ioc"
            else:
                resp = self.get("/api/v1/IoEs", params=params)
                kind = "ioe"
        elif stix_type == "observed-data":
            resp = self.get("/api/v1/Security/Events", params=params)
            kind = "event"
        elif stix_type == "x-semperis-evaluator":
            resp = self.get("/api/v1/Security/Evaluators", params=params)
            kind = "evaluator"
        else:
            raise GNATClientError(
                f"Semperis list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _sem_kind=kind) for r in _extract_records(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Semperis connector is read-only."""
        raise GNATClientError(
            "Semperis connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Semperis connector is read-only."""
        raise GNATClientError(
            "Semperis connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_ioes(self, severity: str = "", status: str = "") -> list[dict[str, Any]]:
        """Return Indicators of Exposure (posture violations)."""
        filters: dict[str, Any] = {"kind": "ioe"}
        if severity:
            filters["severity"] = severity
        if status:
            filters["status"] = status
        return self.list_objects("indicator", filters=filters, page_size=10_000)

    def list_iocs(self, severity: str = "") -> list[dict[str, Any]]:
        """Return Indicators of Compromise."""
        filters: dict[str, Any] = {"kind": "ioc"}
        if severity:
            filters["severity"] = severity
        return self.list_objects("indicator", filters=filters, page_size=10_000)

    def list_evaluators(self) -> list[dict[str, Any]]:
        """Return the configured Semperis security evaluator rules."""
        return self.list_objects("x-semperis-evaluator", page_size=10_000)

    def list_forest_domains(self) -> list[dict[str, Any]]:
        """Return the AD forest domain inventory."""
        resp = self.get("/api/v1/Tenants/Forest/Domains")
        return [dict(r, _sem_kind="domain-posture") for r in _extract_records(resp)]

    def list_security_events(
        self, since: str = "", until: str = ""
    ) -> list[dict[str, Any]]:
        """Return runtime AD security events."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if until:
            filters["until"] = until
        return self.list_objects(
            "observed-data", filters=filters, page_size=10_000
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Semperis record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Semperis to_stix expects a dict input")

        kind = native.get("_sem_kind") or "event"
        now = utcnow()

        if kind in ("ioe", "ioc"):
            ioe_id = (
                native.get("id")
                or native.get("name")
                or native.get("evaluator")
                or "unknown"
            )
            stix_uuid = uuid.uuid5(
                _NAMESPACE_SEMPERIS, f"indicator|{kind}|{ioe_id}"
            )
            pattern = (
                f"[x-semperis-{kind}:evaluator = '{native.get('evaluator', ioe_id)}']"
            )
            labels = ["malicious-activity"] if kind == "ioc" else ["anomalous-activity"]
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": native.get("first_seen") or now,
                "modified": native.get("last_seen") or now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": native.get("first_seen") or now,
                "name": native.get("name") or f"Semperis {kind.upper()} {ioe_id}",
                "description": native.get("description") or f"Semperis {kind.upper()} finding",
                "labels": labels,
                "x_semperis": {
                    "kind": kind,
                    "severity": native.get("severity"),
                    "status": native.get("status"),
                    "evaluator": native.get("evaluator"),
                    "affected_objects": native.get("affected_objects"),
                    "mitre_attack_tactics": native.get("mitre_attack_tactics", []),
                    "raw": native,
                },
            }

        # observed-data — security event or forest/domain posture snapshot
        refs: list[str] = []
        actor = (
            native.get("actor")
            or native.get("user")
            or native.get("initiator", "")
        )
        if actor:
            user_uuid = uuid.uuid5(_NAMESPACE_SEMPERIS, f"user-account|{actor}")
            refs.append(f"user-account--{user_uuid}")

        first = (
            native.get("event_time")
            or native.get("timestamp")
            or native.get("first_seen")
            or now
        )
        last = native.get("last_seen") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="semperis",
            x_extensions={
                "semperis": {
                    "kind": kind,
                    "event_type": native.get("event_type"),
                    "severity": native.get("severity"),
                    "target": native.get("target"),
                    "domain": native.get("domain"),
                    "forest": native.get("forest"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Semperis connector is read-only."""
        return {
            "note": (
                "Semperis connector is read-only. Use list_ioes, list_iocs, "
                "list_evaluators, list_forest_domains, or list_security_events "
                "to query DSP."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_records(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a DSP response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("value", "data", "results", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
