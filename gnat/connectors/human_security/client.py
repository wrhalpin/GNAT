# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.human_security.client
=========================================

HUMAN Security (formerly White Ops) connector — bot defense, account
takeover, and ad fraud telemetry.

Authentication
--------------
OAuth2 client credentials at ``/oauth/token``::

    [human_security]
    host          = https://api.humansecurity.com
    client_id     = hs_client_id
    client_secret = hs_client_secret

Key endpoints
-------------
* ``POST /oauth/token``                       — token exchange
* ``GET  /v1/bot-detections``                 — bot defense events
* ``GET  /v1/bot-detections/{id}``
* ``GET  /v1/account-takeover/events``        — ATO events
* ``GET  /v1/credential-stuffing/events``     — credential-stuffing events
* ``GET  /v1/threats``                        — recent threat intelligence
* ``GET  /v1/integrations``                   — connected app integrations
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    make_observed_data_envelope,
    utcnow,
)

_NAMESPACE_HUMAN = uuid.UUID("4b07a17e-0001-4a1e-9b1e-4b07a17ec0fe")


class HumanSecurityClient(BaseClient, ConnectorMixin):
    """HTTP client for HUMAN Security."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "bot-detections",
        "indicator": "threats",
    }

    def __init__(
        self,
        host: str = "https://api.humansecurity.com",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize HumanSecurityClient."""
        super().__init__(host=host, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> None:
        """Exchange client credentials for a Bearer token."""
        if not self.client_id or not self.client_secret:
            raise GNATClientError("HUMAN Security connector requires client_id and client_secret.")
        resp = self.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        token = ""
        if isinstance(resp, dict):
            token = resp.get("access_token") or resp.get("token", "")
        if not token:
            raise GNATClientError(
                "HUMAN Security authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query bot-detections with a tiny page as a liveness probe."""
        try:
            self.get("/v1/bot-detections", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single record by id."""
        if not object_id:
            raise GNATClientError("HUMAN Security get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/v1/bot-detections/{object_id}")
            kind = "bot_detection"
        elif stix_type == "indicator":
            resp = self.get(f"/v1/threats/{object_id}")
            kind = "threat"
        else:
            raise GNATClientError(
                f"HUMAN Security get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(f"HUMAN Security returned unexpected payload for {object_id!r}")
        return dict(resp, _hs_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List HUMAN Security records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        for key in ("since", "until", "category", "severity"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "bot_detections").lower()
            if kind == "ato_events":
                resp = self.get("/v1/account-takeover/events", params=params)
                tag = "ato_event"
            elif kind == "credential_stuffing":
                resp = self.get("/v1/credential-stuffing/events", params=params)
                tag = "credential_stuffing"
            else:
                resp = self.get("/v1/bot-detections", params=params)
                tag = "bot_detection"
        elif stix_type == "indicator":
            resp = self.get("/v1/threats", params=params)
            tag = "threat"
        elif stix_type == "x-human-integration":
            resp = self.get("/v1/integrations", params=params)
            tag = "integration"
        else:
            raise GNATClientError(
                f"HUMAN Security list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _hs_kind=tag) for r in _extract_human_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """HUMAN Security connector is read-only."""
        raise GNATClientError(
            "HUMAN Security connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """HUMAN Security connector is read-only."""
        raise GNATClientError(
            "HUMAN Security connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_bot_detections(self, since: str = "") -> list[dict[str, Any]]:
        """Return bot defense events."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_account_takeover_events(self) -> list[dict[str, Any]]:
        """Return account-takeover events."""
        return self.list_objects("observed-data", filters={"kind": "ato_events"}, page_size=500)

    def list_credential_stuffing(self) -> list[dict[str, Any]]:
        """Return credential-stuffing events."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "credential_stuffing"},
            page_size=500,
        )

    def list_threats(self) -> list[dict[str, Any]]:
        """Return curated threat intelligence."""
        return self.list_objects("indicator", page_size=500)

    def list_integrations(self) -> list[dict[str, Any]]:
        """Return connected app integrations."""
        return self.list_objects("x-human-integration", page_size=500)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a HUMAN Security record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("HUMAN Security to_stix expects a dict input")

        kind = native.get("_hs_kind") or "bot_detection"

        if kind == "threat":
            ioc_type = (native.get("type") or "ip").lower()
            value = native.get("value") or native.get("indicator", "")
            if ioc_type in ("ip", "ipv4"):
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif ioc_type == "domain":
                pattern = make_indicator_pattern("domain-name", value)
            elif ioc_type == "url":
                pattern = make_indicator_pattern("url", value)
            else:
                pattern = f"[x-human-security:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_HUMAN, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"HUMAN Security: {value}",
                "description": native.get("description") or "HUMAN Security threat",
                "labels": ["malicious-activity"],
                "x_human_security": {
                    "category": native.get("category"),
                    "confidence": native.get("confidence"),
                    "raw": native,
                },
            }

        if kind == "integration":
            int_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_HUMAN, f"x-human-integration|{int_id}")
            return {
                "type": "x-human-integration",
                "id": f"x-human-integration--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(int_id),
                "platform": native.get("platform"),
                "x_human_security": {"raw": native},
            }

        # observed-data envelope (bot_detection / ato_event / credential_stuffing)
        refs: list[str] = []
        ip = native.get("ipAddress") or native.get("ip") or native.get("source_ip")
        if ip:
            ip_uuid = uuid.uuid5(_NAMESPACE_HUMAN, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{ip_uuid}")
        user = native.get("userId") or native.get("username")
        if user:
            user_uuid = uuid.uuid5(_NAMESPACE_HUMAN, f"user-account|{user}")
            refs.append(f"user-account--{user_uuid}")

        first = (
            native.get("timestamp")
            or native.get("createdAt")
            or native.get("eventTime")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="human_security",
            x_extensions={
                "human_security": {
                    "kind": kind,
                    "event_id": native.get("id") or native.get("eventId"),
                    "verdict": native.get("verdict") or native.get("classification"),
                    "user_agent": native.get("userAgent"),
                    "asn": native.get("asn"),
                    "country": native.get("country"),
                    "is_bot": native.get("isBot") or native.get("bot"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """HUMAN Security connector is read-only."""
        return {
            "note": (
                "HUMAN Security connector is read-only. Use "
                "list_bot_detections, list_account_takeover_events, "
                "list_credential_stuffing, list_threats, or "
                "list_integrations to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_human_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a HUMAN Security response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "events", "detections", "threats"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
