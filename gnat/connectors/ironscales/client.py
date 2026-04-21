# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.ironscales.client
=====================================

IRONSCALES AI-driven email security connector.

Authentication
--------------
IRONSCALES issues a scoped API key per company id; requests include
the company-specific ``Authorization: Bearer <api_key>`` header plus
a ``X-Company-Id`` header for tenant routing::

    [ironscales]
    host       = https://appapi.ironscales.com
    api_key    = is_...
    company_id = 12345

Key endpoints
-------------
* ``GET  /appapi/company/{id}/incidents/``           — phishing incidents
* ``GET  /appapi/company/{id}/incidents/{iid}/``
* ``GET  /appapi/company/{id}/incidents/{iid}/affected-mailboxes/``
* ``GET  /appapi/company/{id}/classifications/``     — classification rules
* ``GET  /appapi/company/{id}/mitigation-actions/``
* ``GET  /appapi/company/{id}/report/reported-emails/``
* ``GET  /appapi/company/{id}/mailboxes/``           — protected mailboxes
* ``GET  /appapi/company/{id}/federation/signatures/`` — community intel

STIX Type Mapping
-----------------
* ``observed-data`` → incidents + reported emails (each wraps an
  ``email-message`` + sender ``identity`` ref pair)
* ``indicator``     → community federation signatures
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_IRONSCALES = uuid.UUID("1705ca1e-0001-4a1e-9b1e-1705ca1ec0fe")


class IRONSCALESClient(BaseClient, ConnectorMixin):
    """
    HTTP client for IRONSCALES.

    Parameters
    ----------
    host : str
        API base URL.  Defaults to ``"https://appapi.ironscales.com"``.
    api_key : str
        IRONSCALES API key (scoped to the company id).
    company_id : str
        IRONSCALES company id (tenant identifier).
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/appapi"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "incidents",
        "indicator": "federation/signatures",
    }

    def __init__(
        self,
        host: str = "https://appapi.ironscales.com",
        api_key: str = "",
        company_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize IRONSCALESClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        self.company_id = company_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Bearer token + X-Company-Id headers."""
        if not self.api_key:
            raise GNATClientError("IRONSCALES connector requires api_key in config.")
        if not self.company_id:
            raise GNATClientError("IRONSCALES connector requires company_id in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_key}"
        self._auth_headers["X-Company-Id"] = str(self.company_id)
        self._auth_headers["Accept"] = "application/json"

    # ── Internal path helper ──────────────────────────────────────────────

    def _company_path(self, suffix: str) -> str:
        """Return a company-scoped IRONSCALES API path."""
        return f"/appapi/company/{self.company_id}/{suffix.lstrip('/')}"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the incidents endpoint with a small page as a liveness probe."""
        try:
            self.get(self._company_path("incidents/"), params={"page_size": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single IRONSCALES record by id."""
        if not object_id:
            raise GNATClientError("IRONSCALES get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(self._company_path(f"incidents/{object_id}/"))
            kind = "incident"
        elif stix_type == "indicator":
            resp = self.get(self._company_path(f"federation/signatures/{object_id}/"))
            kind = "signature"
        else:
            raise GNATClientError(f"IRONSCALES get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"IRONSCALES returned unexpected payload for {object_id!r}")
        return dict(resp, _is_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List IRONSCALES records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"page_size": int(page_size), "page": int(page)}
        for key in ("classification", "severity", "since", "until", "state"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            sub = (filters.get("kind") or "incidents").lower()
            if sub == "reported_emails":
                resp = self.get(self._company_path("report/reported-emails/"), params=params)
                tag = "reported_email"
            elif sub == "mailboxes":
                resp = self.get(self._company_path("mailboxes/"), params=params)
                tag = "mailbox"
            elif sub == "mitigation_actions":
                resp = self.get(self._company_path("mitigation-actions/"), params=params)
                tag = "mitigation_action"
            else:
                resp = self.get(self._company_path("incidents/"), params=params)
                tag = "incident"
        elif stix_type == "indicator":
            resp = self.get(self._company_path("federation/signatures/"), params=params)
            tag = "signature"
        elif stix_type == "x-ironscales-classification":
            resp = self.get(self._company_path("classifications/"), params=params)
            tag = "classification"
        else:
            raise GNATClientError(
                f"IRONSCALES list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _is_kind=tag) for r in _extract_ironscales_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """IRONSCALES connector is read-only in Phase 2."""
        raise GNATClientError("IRONSCALES connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """IRONSCALES connector is read-only in Phase 2."""
        raise GNATClientError("IRONSCALES connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_incidents(
        self,
        classification: str = "",
        severity: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        """Return phishing incidents."""
        filters: dict[str, Any] = {"kind": "incidents"}
        if classification:
            filters["classification"] = classification
        if severity:
            filters["severity"] = severity
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Fetch a single incident by id."""
        return self.get_object("observed-data", incident_id)

    def list_affected_mailboxes(self, incident_id: str) -> list[dict[str, Any]]:
        """Return the mailboxes affected by an incident."""
        resp = self.get(self._company_path(f"incidents/{incident_id}/affected-mailboxes/"))
        return [dict(r, _is_kind="affected_mailbox") for r in _extract_ironscales_list(resp)]

    def list_reported_emails(self, since: str = "") -> list[dict[str, Any]]:
        """Return user-reported phishing emails."""
        filters: dict[str, Any] = {"kind": "reported_emails"}
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_mailboxes(self) -> list[dict[str, Any]]:
        """Return protected mailboxes."""
        return self.list_objects("observed-data", filters={"kind": "mailboxes"}, page_size=500)

    def list_mitigation_actions(self) -> list[dict[str, Any]]:
        """Return available / historical mitigation actions."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "mitigation_actions"},
            page_size=500,
        )

    def list_classifications(self) -> list[dict[str, Any]]:
        """Return classification rules."""
        return self.list_objects("x-ironscales-classification", page_size=500)

    def list_federation_signatures(self, since: str = "") -> list[dict[str, Any]]:
        """Return IRONSCALES community (federation) signatures."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        return self.list_objects("indicator", filters=filters, page_size=500)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an IRONSCALES record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("IRONSCALES to_stix expects a dict input")

        kind = native.get("_is_kind") or "incident"

        if kind == "signature":
            sig_id = native.get("id") or native.get("signature_id", "")
            sig_type = (native.get("type") or "").lower()
            value = native.get("value") or native.get("pattern", "")
            if sig_type == "hash":
                pattern = f"[file:hashes.'SHA-256' = '{value}']"
            elif sig_type == "url":
                pattern = f"[url:value = '{value}']"
            elif sig_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
            elif sig_type in ("ip", "ipv4"):
                pattern = f"[ipv4-addr:value = '{value}']"
            else:
                pattern = f"[x-ironscales:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_IRONSCALES, f"indicator|{value or sig_id}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": native.get("created_at") or utcnow(),
                "modified": native.get("updated_at") or utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": native.get("created_at") or utcnow(),
                "name": f"IRONSCALES federation: {value or sig_id}",
                "description": native.get("description")
                or "IRONSCALES community federation signature",
                "labels": ["malicious-activity"],
                "x_ironscales_federation": {
                    "signature_id": sig_id,
                    "sig_type": sig_type,
                    "community_votes": native.get("votes"),
                    "raw": native,
                },
            }

        if kind == "classification":
            cls_id = native.get("id") or native.get("name", "unknown")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_IRONSCALES,
                f"x-ironscales-classification|{cls_id}",
            )
            return {
                "type": "x-ironscales-classification",
                "id": f"x-ironscales-classification--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(cls_id),
                "description": native.get("description") or "",
                "severity": native.get("severity"),
                "x_ironscales": {"raw": native},
            }

        # observed-data envelope (incident / reported_email / mitigation / mailbox)
        refs: list[str] = []
        message_id = native.get("message_id") or native.get("incident_id") or native.get("id") or ""
        if message_id:
            msg_uuid = uuid.uuid5(_NAMESPACE_IRONSCALES, f"email-message|{message_id}")
            refs.append(f"email-message--{msg_uuid}")

        sender = native.get("sender") or native.get("from") or native.get("from_address")
        if isinstance(sender, dict):
            sender = sender.get("email") or sender.get("address")
        if sender:
            sender_uuid = uuid.uuid5(_NAMESPACE_IRONSCALES, f"identity|{sender}")
            refs.append(f"identity--{sender_uuid}")

        first = (
            native.get("first_reported_at")
            or native.get("created_at")
            or native.get("reported_at")
            or utcnow()
        )
        last = native.get("last_reported_at") or native.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=int(native.get("affected_mailboxes_count") or native.get("count") or 1),
            object_refs=refs,
            source_name="ironscales",
            x_extensions={
                "ironscales": {
                    "kind": kind,
                    "incident_id": native.get("id") or native.get("incident_id"),
                    "classification": native.get("classification"),
                    "severity": native.get("severity"),
                    "state": native.get("state") or native.get("status"),
                    "subject": native.get("subject"),
                    "sender": sender,
                    "company_id": self.company_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """IRONSCALES connector is read-only."""
        return {
            "note": (
                "IRONSCALES connector is read-only. Use list_incidents, "
                "get_incident, list_affected_mailboxes, list_reported_emails, "
                "list_mailboxes, list_mitigation_actions, "
                "list_classifications, or list_federation_signatures "
                "to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_ironscales_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an IRONSCALES paginated response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("results", "data", "items", "incidents", "mailboxes", "signatures"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
