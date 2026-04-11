# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.mimecast.client
===================================

Mimecast email security connector (Mimecast API 2.0).

Authentication
--------------
Mimecast API 2.0 uses OAuth2 client credentials — exchange the
client_id / client_secret for a short-lived Bearer token against
``/oauth/token``::

    [mimecast]
    host          = https://api.services.mimecast.com
    client_id     = mc_client_id
    client_secret = mc_client_secret

Key endpoints
-------------
* ``POST /oauth/token``                            — OAuth2 token exchange
* ``GET  /api/ttp/threat-intel/get-feed``          — threat intel feed
* ``POST /api/ttp/url/get-logs``                   — URL Protect logs
* ``POST /api/ttp/attachment/get-logs``            — Attachment Protect logs
* ``POST /api/ttp/impersonation/get-logs``         — Impersonation Protect
* ``POST /api/message-finder/search``              — message search
* ``GET  /api/directory/find-users``               — user directory
* ``GET  /api/directory/find-groups``              — distribution groups
* ``POST /api/audit/get-audit-events``             — admin audit events

STIX Type Mapping
-----------------
* ``observed-data`` → message events, URL / attachment / impersonation
  logs (each wraps an ``email-message`` + ``identity`` ref pair)
* ``identity``      → mail users + distribution groups
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_MIMECAST = uuid.UUID("111eca57-0001-4a1e-9b1e-111eca57c0fe")


class MimecastClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Mimecast API 2.0.

    Parameters
    ----------
    host : str
        API base URL.  Defaults to ``"https://api.services.mimecast.com"``.
    client_id : str
        OAuth2 client id.
    client_secret : str
        OAuth2 client secret.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "ttp",
        "identity": "directory",
    }

    def __init__(
        self,
        host: str = "https://api.services.mimecast.com",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize MimecastClient."""
        super().__init__(host=host, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange client credentials for a Mimecast Bearer token."""
        if not self.client_id or not self.client_secret:
            raise GNATClientError(
                "Mimecast connector requires client_id and client_secret."
            )
        token_url = f"{self.host}/oauth/token"
        body = (
            f"client_id={self.client_id}"
            f"&client_secret={self.client_secret}"
            f"&grant_type=client_credentials"
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
                f"Mimecast token request failed: {exc}"
            ) from exc
        if resp.status >= 400:
            raise GNATClientError(
                f"Mimecast token request returned HTTP {resp.status}: "
                f"{resp.data[:200]!r}"
            )
        try:
            data = json.loads(resp.data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GNATClientError(
                f"Mimecast token response was not JSON: {exc}"
            ) from exc
        token = data.get("access_token") or ""
        if not token:
            raise GNATClientError(
                "Mimecast authentication failed — no access_token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the audit-events endpoint as a cheap authenticated probe."""
        try:
            self.post(
                "/api/audit/get-audit-events", json={"data": [{"pageSize": 1}]}
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Mimecast record.

        Mimecast is mostly search-oriented — ``get_object`` routes
        message ids to the message-finder endpoint.
        """
        if not object_id:
            raise GNATClientError("Mimecast get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.post(
                "/api/message-finder/search",
                json={"data": [{"messageId": object_id}]},
            )
            if isinstance(resp, dict):
                items = _extract_mimecast_items(resp)
                if items:
                    return dict(items[0], _mc_kind="message")
            raise GNATClientError(
                f"Mimecast: no message found for {object_id!r}"
            )
        raise GNATClientError(
            f"Mimecast get_object does not support stix_type={stix_type!r}"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Mimecast records via the search endpoints.

        ``filters`` keys:

        * ``kind`` — ``"messages"`` (default), ``"url_logs"``,
          ``"attachment_logs"``, ``"impersonation_logs"``,
          ``"threat_intel"``, ``"audit_events"``
        * ``from`` / ``to`` — ISO 8601 bounds
        * ``query`` — Mimecast search body (merged into the request)
        """
        filters = dict(filters or {})
        kind = (filters.get("kind") or "messages").lower()

        meta: dict[str, Any] = {"pageSize": int(page_size)}
        data_item: dict[str, Any] = {}
        if filters.get("from"):
            data_item["from"] = filters["from"]
        if filters.get("to"):
            data_item["to"] = filters["to"]
        extra = filters.get("query") or {}
        if isinstance(extra, dict):
            data_item.update(extra)

        body: dict[str, Any] = {"meta": {"pagination": meta}, "data": [data_item]}

        if stix_type == "identity":
            if kind == "groups":
                resp = self.get(
                    "/api/directory/find-groups",
                    params={"pageSize": int(page_size)},
                )
                tag = "group"
            else:
                resp = self.post(
                    "/api/directory/find-users", json=body
                )
                tag = "user"
        elif stix_type == "observed-data":
            if kind == "url_logs":
                resp = self.post("/api/ttp/url/get-logs", json=body)
                tag = "url_log"
            elif kind == "attachment_logs":
                resp = self.post(
                    "/api/ttp/attachment/get-logs", json=body
                )
                tag = "attachment_log"
            elif kind == "impersonation_logs":
                resp = self.post(
                    "/api/ttp/impersonation/get-logs", json=body
                )
                tag = "impersonation_log"
            elif kind == "threat_intel":
                resp = self.get(
                    "/api/ttp/threat-intel/get-feed",
                    params={"pageSize": int(page_size)},
                )
                tag = "threat_intel"
            elif kind == "audit_events":
                resp = self.post(
                    "/api/audit/get-audit-events", json=body
                )
                tag = "audit_event"
            else:
                resp = self.post(
                    "/api/message-finder/search", json=body
                )
                tag = "message"
        else:
            raise GNATClientError(
                f"Mimecast list_objects does not support stix_type={stix_type!r}"
            )
        return [
            dict(r, _mc_kind=tag) for r in _extract_mimecast_items(resp)
        ]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Mimecast connector is read-only in Phase 2."""
        raise GNATClientError(
            "Mimecast connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Mimecast connector is read-only in Phase 2."""
        raise GNATClientError(
            "Mimecast connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def search_messages(
        self, from_date: str = "", to_date: str = "", query: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Search the message-finder archive."""
        filters: dict[str, Any] = {"kind": "messages"}
        if from_date:
            filters["from"] = from_date
        if to_date:
            filters["to"] = to_date
        if query:
            filters["query"] = query
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_url_protect_logs(
        self, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """Return URL Protect click/scan logs."""
        filters: dict[str, Any] = {"kind": "url_logs"}
        if from_date:
            filters["from"] = from_date
        if to_date:
            filters["to"] = to_date
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_attachment_protect_logs(
        self, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """Return Attachment Protect sandboxing logs."""
        filters: dict[str, Any] = {"kind": "attachment_logs"}
        if from_date:
            filters["from"] = from_date
        if to_date:
            filters["to"] = to_date
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def list_impersonation_logs(
        self, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """Return Impersonation Protect (BEC / CEO fraud) logs."""
        filters: dict[str, Any] = {"kind": "impersonation_logs"}
        if from_date:
            filters["from"] = from_date
        if to_date:
            filters["to"] = to_date
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_threat_intel_feed(self) -> list[dict[str, Any]]:
        """Return the Mimecast threat-intel feed (hashes, URLs, domains)."""
        return self.list_objects(
            "observed-data", filters={"kind": "threat_intel"}, page_size=500
        )

    def list_users(self) -> list[dict[str, Any]]:
        """Return mail users from the directory."""
        return self.list_objects("identity", filters={"kind": "users"}, page_size=500)

    def list_groups(self) -> list[dict[str, Any]]:
        """Return distribution groups from the directory."""
        return self.list_objects("identity", filters={"kind": "groups"}, page_size=500)

    def list_audit_events(
        self, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """Return admin audit events."""
        filters: dict[str, Any] = {"kind": "audit_events"}
        if from_date:
            filters["from"] = from_date
        if to_date:
            filters["to"] = to_date
        return self.list_objects("observed-data", filters=filters, page_size=500)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Mimecast record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Mimecast to_stix expects a dict input")

        kind = native.get("_mc_kind") or "message"

        if kind == "user":
            user_id = native.get("emailAddress") or native.get("id", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_MIMECAST, f"identity|user|{user_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or user_id,
                "identity_class": "individual",
                "contact_information": user_id,
                "x_mimecast_user": {"raw": native},
            }

        if kind == "group":
            group_id = native.get("id") or native.get("folderId", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_MIMECAST, f"identity|group|{group_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("description") or native.get("source", "mimecast group"),
                "identity_class": "group",
                "x_mimecast_group": {"raw": native},
            }

        # observed-data for message + TTP log + audit event
        refs: list[str] = []
        msg_id = (
            native.get("messageId")
            or native.get("id")
            or native.get("msgId", "")
        )
        if msg_id:
            msg_uuid = uuid.uuid5(
                _NAMESPACE_MIMECAST, f"email-message|{msg_id}"
            )
            refs.append(f"email-message--{msg_uuid}")

        sender = (
            native.get("from")
            or native.get("senderAddress")
            or native.get("actor")
        )
        if isinstance(sender, dict):
            sender = sender.get("emailAddress") or sender.get("address")
        if sender:
            sender_uuid = uuid.uuid5(_NAMESPACE_MIMECAST, f"identity|{sender}")
            refs.append(f"identity--{sender_uuid}")

        first = (
            native.get("received")
            or native.get("date")
            or native.get("eventTime")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="mimecast",
            x_extensions={
                "mimecast": {
                    "kind": kind,
                    "subject": native.get("subject"),
                    "from": sender,
                    "to": native.get("to")
                    or native.get("recipientAddress"),
                    "action": native.get("action") or native.get("eventType"),
                    "route": native.get("route"),
                    "result": native.get("result") or native.get("scanResult"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Mimecast connector is read-only."""
        return {
            "note": (
                "Mimecast connector is read-only. Use search_messages, "
                "list_url_protect_logs, list_attachment_protect_logs, "
                "list_impersonation_logs, get_threat_intel_feed, "
                "list_users, list_groups, or list_audit_events to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_mimecast_items(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Mimecast API 2.0 response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data")
    if isinstance(data, list):
        out: list[dict[str, Any]] = []
        for block in data:
            if isinstance(block, dict):
                for key in ("messages", "logs", "items", "users", "groups", "events", "threats"):
                    val = block.get(key)
                    if isinstance(val, list):
                        out.extend(r for r in val if isinstance(r, dict))
                        break
                else:
                    out.append(block)
        return out
    return []
