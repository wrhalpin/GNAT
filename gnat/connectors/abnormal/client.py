# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abnormal.client
===================================

Abnormal Security connector — AI-driven email threat detection focused
on business-email-compromise (BEC), credential phishing, and vendor
impersonation.

Authentication
--------------
Bearer token::

    [abnormal]
    host      = https://api.abnormalplatform.com
    api_token = abnormal_...

Key endpoints
-------------
* ``GET /v1/threats`` — list threats
* ``GET /v1/threats/{threatId}``
* ``GET /v1/threats/{threatId}/messages/{messageId}``
* ``GET /v1/cases`` — BEC investigation cases
* ``GET /v1/cases/{caseId}``
* ``GET /v1/vendor-cases`` — vendor impersonation cases
* ``GET /v1/abusemailbox/campaigns`` — user-reported campaigns

STIX Type Mapping
-----------------
* ``observed-data`` → threats, cases, vendor-cases, campaigns
  (envelope wraps ``email-message`` + sender ``identity``)

Notes
-----
* ``TRUST_LEVEL`` is ``"trusted_internal"``.
* **Read-only.**
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_ABNORMAL = uuid.UUID("ab401ab0-0001-4a1e-9a1c-ab401ab0c0de")


class AbnormalClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Abnormal Security.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.abnormalplatform.com"``.
    api_token : str
        Abnormal API Bearer token.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "threats",
    }

    def __init__(
        self,
        host: str = "https://api.abnormalplatform.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize AbnormalClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header from the configured token."""
        if not self.api_token:
            raise GNATClientError(
                "Abnormal connector requires api_token in config."
            )
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/threats`` with a tiny page as a liveness probe."""
        try:
            self.get("/v1/threats", params={"pageNumber": 1, "pageSize": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Abnormal threat or case by id."""
        if not object_id:
            raise GNATClientError("Abnormal get_object requires a non-empty id")
        if stix_type != "observed-data":
            raise GNATClientError(
                f"Abnormal get_object does not support stix_type={stix_type!r}"
            )
        resp = self.get(f"/v1/threats/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Abnormal returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _ab_kind="threat")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Abnormal records.

        ``filters`` keys:

        * ``kind`` — ``"threats"`` (default), ``"cases"``, ``"vendor_cases"``,
          ``"abusemailbox_campaigns"``
        * ``filter`` — Abnormal filter DSL passed to the endpoint
        """
        if stix_type != "observed-data":
            raise GNATClientError(
                f"Abnormal list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        kind = (filters.get("kind") or "threats").lower()
        params: dict[str, Any] = {"pageNumber": int(page), "pageSize": int(page_size)}
        if filters.get("filter"):
            params["filter"] = filters["filter"]

        if kind == "threats":
            resp = self.get("/v1/threats", params=params)
            tag = "threat"
        elif kind == "cases":
            resp = self.get("/v1/cases", params=params)
            tag = "case"
        elif kind == "vendor_cases":
            resp = self.get("/v1/vendor-cases", params=params)
            tag = "vendor_case"
        elif kind == "abusemailbox_campaigns":
            resp = self.get("/v1/abusemailbox/campaigns", params=params)
            tag = "abusemailbox_campaign"
        else:
            raise GNATClientError(f"Unknown Abnormal kind {kind!r}")

        records = _extract_records(resp, kind)
        return [dict(r, _ab_kind=tag) for r in records]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Abnormal connector is read-only."""
        raise GNATClientError(
            "Abnormal connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Abnormal connector is read-only."""
        raise GNATClientError(
            "Abnormal connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_threats(self, filter_expr: str = "") -> list[dict[str, Any]]:
        """Return recent Abnormal threats."""
        filters: dict[str, Any] = {"kind": "threats"}
        if filter_expr:
            filters["filter"] = filter_expr
        return self.list_objects("observed-data", filters=filters, page_size=1000)

    def get_threat(self, threat_id: str) -> dict[str, Any]:
        """Fetch a single threat by id."""
        return self.get_object("observed-data", threat_id)

    def get_threat_message(
        self, threat_id: str, message_id: str
    ) -> dict[str, Any]:
        """Fetch a specific message within a threat."""
        resp = self.get(f"/v1/threats/{threat_id}/messages/{message_id}")
        if isinstance(resp, dict):
            return dict(resp, _ab_kind="message", _ab_threat_id=threat_id)
        return {}

    def list_cases(self) -> list[dict[str, Any]]:
        """Return BEC investigation cases."""
        return self.list_objects(
            "observed-data", filters={"kind": "cases"}, page_size=1000
        )

    def list_vendor_cases(self) -> list[dict[str, Any]]:
        """Return vendor-impersonation cases."""
        return self.list_objects(
            "observed-data", filters={"kind": "vendor_cases"}, page_size=1000
        )

    def list_abusemailbox_campaigns(self) -> list[dict[str, Any]]:
        """Return user-reported phishing campaigns from the abuse mailbox."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "abusemailbox_campaigns"},
            page_size=1000,
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Abnormal record to STIX 2.1 ``observed-data``."""
        if not isinstance(native, dict):
            raise GNATClientError("Abnormal to_stix expects a dict input")

        kind = native.get("_ab_kind") or "threat"
        threat_id = str(native.get("threatId") or native.get("id", ""))
        refs: list[str] = []

        # Synthetic email-message ref
        if threat_id:
            msg_uuid = uuid.uuid5(_NAMESPACE_ABNORMAL, f"email-message|{threat_id}")
            refs.append(f"email-message--{msg_uuid}")

        # Sender / attacker identity
        sender = (
            native.get("fromAddress")
            or native.get("sender_email")
            or native.get("attackerEmail", "")
        )
        if sender:
            ident_uuid = uuid.uuid5(_NAMESPACE_ABNORMAL, f"identity|{sender}")
            refs.append(f"identity--{ident_uuid}")

        first = (
            native.get("receivedTime")
            or native.get("firstObserved")
            or native.get("created_at")
            or utcnow()
        )
        last = (
            native.get("lastObserved")
            or native.get("updated_at")
            or first
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="abnormal",
            x_extensions={
                "abnormal": {
                    "kind": kind,
                    "threat_id": threat_id,
                    "attack_type": native.get("attackType"),
                    "attack_vector": native.get("attackVector"),
                    "attack_strategy": native.get("attackStrategy"),
                    "judgement": native.get("judgement"),
                    "impersonated_party": native.get("impersonatedParty"),
                    "vendor_name": native.get("vendorName"),
                    "subject": native.get("subject"),
                    "from_address": sender,
                    "recipient_address": native.get("toAddresses")
                    or native.get("recipientAddress"),
                    "case_id": native.get("caseId"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Abnormal connector is read-only."""
        return {
            "note": (
                "Abnormal connector is read-only. Use list_threats, "
                "get_threat, list_cases, list_vendor_cases, or "
                "list_abusemailbox_campaigns to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_records(resp: Any, kind: str) -> list[dict[str, Any]]:
    """Pull records out of an Abnormal response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in (kind, "threats", "cases", "vendorCases", "campaigns", "results", "data"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
