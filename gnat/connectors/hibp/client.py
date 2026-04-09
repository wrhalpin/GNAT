# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hibp.client
============================

Have I Been Pwned (HIBP) connector.

HIBP provides breach and paste intelligence — checking whether email
addresses or phone numbers appear in known data breaches, and exposing
a comprehensive breach database.

Authentication
--------------
API key sent as ``hibp-api-key`` header::

    [hibp]
    host    = https://haveibeenpwned.com
    api_key = <your-hibp-api-key>

Obtain a key at https://haveibeenpwned.com/API/Key.

STIX Type Mapping
-----------------
+----------------+--------------------------------------------+
| STIX Type      | HIBP Resource                              |
+================+============================================+
| vulnerability  | Breaches (data breach records)             |
+----------------+--------------------------------------------+
| identity       | Pastes / Account exposure records          |
+----------------+--------------------------------------------+

Key Endpoints
-------------
* /api/v3/breachedaccount/{account}  — Breaches for an email account
* /api/v3/breaches                   — All breaches in the system
* /api/v3/breach/{name}              — Single breach details
* /api/v3/pasteaccount/{account}     — Pastes containing an account
* /api/v3/dataclasses                — Enumerate all data class types

Rate Limiting
-------------
HIBP imposes a 10 req/s rate limit for most endpoints.
Use ``page_size`` ≤ 100 for list_objects to stay within limits.

References
----------
https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class HIBPClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Have I Been Pwned API v3.

    Read-only — HIBP does not accept writes.

    Parameters
    ----------
    host : str
        Base URL (default ``https://haveibeenpwned.com``).
    api_key : str
        HIBP API key from haveibeenpwned.com/API/Key.
    """

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "vulnerability": "breaches",
        "identity": "pasteaccount",
    }

    def __init__(
        self,
        host: str = "https://haveibeenpwned.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize HIBPClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the HIBP API key header."""
        self._auth_headers["hibp-api-key"] = self._api_key
        self._auth_headers["User-Agent"] = "GNAT-Security-Client/1.0"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the breaches endpoint with a single well-known breach."""
        self.get("/api/v3/breach/Adobe")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single HIBP object.

        For ``vulnerability``, *object_id* is the breach name (e.g. ``"Adobe"``).
        For ``identity``, *object_id* is an email address.
        """
        if stix_type == "vulnerability":
            return self.get(f"/api/v3/breach/{object_id}")
        if stix_type == "identity":
            resp = self.get(f"/api/v3/breachedaccount/{object_id}")
            if isinstance(resp, list):
                return {"account": object_id, "breaches": resp}
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(f"Unsupported STIX type for HIBP: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List HIBP objects by STIX type.

        For ``vulnerability``, returns all or filtered breaches.
        The *page* and *page_size* parameters are applied client-side as
        HIBP does not support server-side pagination for breach listing.
        """
        f = filters or {}
        if stix_type == "vulnerability":
            domain = f.get("domain", "")
            params: dict[str, Any] = {}
            if domain:
                params["domain"] = domain
            resp = self.get("/api/v3/breaches", params=params)
            items = resp if isinstance(resp, list) else []
            start = (page - 1) * page_size
            return items[start : start + page_size]
        if stix_type == "identity":
            account = f.get("account", "")
            if not account:
                raise GNATClientError(
                    "HIBP list_objects for 'identity' requires filters={'account': '<email>'}"
                )
            resp = self.get(f"/api/v3/breachedaccount/{account}")
            return resp if isinstance(resp, list) else []
        raise GNATClientError(f"Unsupported STIX type for HIBP: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("HIBP API is read-only — upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("HIBP API is read-only — delete not supported.")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def check_account(self, account: str, truncate: bool = True) -> list[dict[str, Any]]:
        """Check if an email address appears in any known breach."""
        params: dict[str, Any] = {"truncateResponse": str(truncate).lower()}
        resp = self.get(f"/api/v3/breachedaccount/{account}", params=params)
        return resp if isinstance(resp, list) else []

    def get_all_breaches(self, domain: str | None = None) -> list[dict[str, Any]]:
        """Retrieve all breaches, optionally filtered by domain."""
        params: dict[str, Any] = {}
        if domain:
            params["domain"] = domain
        resp = self.get("/api/v3/breaches", params=params)
        return resp if isinstance(resp, list) else []

    def get_pastes(self, account: str) -> list[dict[str, Any]]:
        """Return all pastes that include a given email address."""
        resp = self.get(f"/api/v3/pasteaccount/{account}")
        return resp if isinstance(resp, list) else []

    def get_data_classes(self) -> list[str]:
        """Return all data class types tracked by HIBP."""
        resp = self.get("/api/v3/dataclasses")
        return resp if isinstance(resp, list) else []

    def get_breach(self, name: str) -> dict[str, Any]:
        """Return a single breach by name."""
        resp = self.get(f"/api/v3/breach/{name}")
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a HIBP breach record to STIX."""
        if "Name" in native:
            return self._breach_to_stix(native)
        # Paste record
        return self._paste_to_stix(native)

    def _breach_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for breach to stix."""
        name = native.get("Name", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"hibp-breach-{name}"))
        data_classes = native.get("DataClasses", [])
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": native.get("Title", name),
            "description": native.get("Description", "")[:1000],
            "created": native.get("AddedDate", _now_ts()),
            "modified": native.get("ModifiedDate", _now_ts()),
            "x_source_platform": "hibp",
            "x_hibp": {
                "breach_name": name,
                "domain": native.get("Domain", ""),
                "breach_date": native.get("BreachDate", ""),
                "pwn_count": native.get("PwnCount", 0),
                "data_classes": data_classes,
                "is_verified": native.get("IsVerified", False),
                "is_sensitive": native.get("IsSensitive", False),
                "is_fabricated": native.get("IsFabricated", False),
                "is_spam_list": native.get("IsSpamList", False),
            },
        }

    def _paste_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for paste to stix."""
        paste_id = native.get("Id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"hibp-paste-{paste_id}"))
        return {
            "type": "identity",
            "id": f"identity--{uid}",
            "name": f"Paste: {native.get('Title', paste_id)}",
            "identity_class": "individual",
            "created": native.get("Date", _now_ts()),
            "modified": native.get("Date", _now_ts()),
            "x_source_platform": "hibp",
            "x_hibp": {
                "paste_id": paste_id,
                "source": native.get("Source", ""),
                "title": native.get("Title", ""),
                "email_count": native.get("EmailCount", 0),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract HIBP query parameters from a STIX dict."""
        return {
            "stix_id": stix_dict.get("id", ""),
            "name": stix_dict.get("name", ""),
            "query": stix_dict.get("name", ""),
        }
