# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.group_ib.client
===============================

Group-IB (Threat Intelligence + Digital Risk + Fraud Protection) connector — full client.

Authentication
--------------
Username + API Token (Basic Auth or token as password)::

    [group_ib]
    host     = https://tap.group-ib.com/api/v2/     # or your regional instance
    username = <your-group-ib-username>
    token    = <your-group-ib-api-token>

Generate the token in the Group-IB portal (Profile → Security and Access → Personal token).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Group-IB Resource                |
+================+==================================+
| indicator      | IOCs from collections (malware, breaches, etc.) |
+----------------+----------------------------------+
| report         | Attacks, vulnerabilities, fraud events |
+----------------+----------------------------------+

Key Endpoints (API v2)
----------------------
* /collections/{collection_name}     — Pull data from collections (compromised accounts, malware, vulnerabilities, etc.)
* Incremental pulls via seqUpdate or date filters
* Supports TAXII/STIX export in some configurations

Notes
-----
* Excellent for cybercrime attribution, compromised data, and fraud intel.
* Use collections for targeted pulls (e.g., "compromised_accounts", "malware", "vulnerabilities").
* Complements your Cyble/CloudSEK/ZeroFox DRP coverage with fraud and attribution depth.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a2b3c4d5-e6f7-8a9b-0c1d-2e3f4a5b6c7d")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GroupIBClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Group-IB Threat Intelligence API v2.

    Parameters
    ----------
    host : str
        Base API URL (e.g. "https://tap.group-ib.com/api/v2/").
    username : str
        Group-IB portal username.
    token : str
        Group-IB API token (used as password).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "indicator": "collections",
        "report": "collections",
    }

    def __init__(
        self,
        host: str = "https://tap.group-ib.com/api/v2/",
        username: str = "",
        token: str = "",
        **kwargs: Any,
    ):
        """Initialize GroupIBClient."""
        super().__init__(host=host, **kwargs)
        self._username = username
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Basic Auth (username + token as password)."""
        self._auth_headers["Authorization"] = self._basic_auth(self._username, self._token)
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via a collection or status endpoint."""
        self.get("/collections", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        # Example: fetch specific item from a collection
        """Retrieve object."""
        return self.get(f"/collections/{object_id}")  # adjust path as needed per collection

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size}
        params.update(filters)

        # Default: pull from collections (specify collection_name in filters)
        collection = filters.pop("collection", "malware")  # default example
        resp = self.get(f"/collections/{collection}", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Group-IB connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_collection(
        self,
        collection_name: str,  # e.g. "compromised_accounts", "malware", "vulnerabilities", "attacks"
        limit: int = 50,
        since: str | None = None,  # ISO date for incremental
    ) -> list[dict[str, Any]]:
        """Fetch data from a specific Group-IB collection."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        resp = self.get(f"/collections/{collection_name}", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def fetch_compromised_accounts(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Convenience helper for compromised accounts collection."""
        return self.fetch_collection("compromised_accounts", limit, since)

    def fetch_malware(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Convenience helper for malware collection."""
        return self.fetch_collection("malware", limit, since)

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch based on collection type or structure."""
        # Simple heuristic — expand with more collection-specific logic if needed
        if "email" in native or "login" in native or "password" in native:
            return self._compromised_to_stix(native)
        if "hash" in native or "ioc" in native:
            return self._ioc_to_stix(native)
        return self._event_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {
            "note": "Group-IB is read-only for threat intelligence and risk data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _compromised_to_stix(self, item: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for compromised to stix."""
        now = _now_ts()
        iid = item.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'groupib:{iid}')}"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": item.get("email") or item.get("login", "Compromised Credential"),
            "description": "Compromised account from Group-IB collection",
            "pattern": f"[email-addr:value = '{item.get('email')}']" if item.get("email") else None,
            "pattern_type": "stix",
            "indicator_types": ["compromised"],
            "x_groupib": {
                "item_id": iid,
                "collection": "compromised_accounts",
                "source": item.get("source"),
            },
        }

    def _ioc_to_stix(self, ioc: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for ioc to stix."""
        now = _now_ts()
        iid = ioc.get("id", "")
        ind_id = f"indicator--{_uuid.uuid5(_STIX_NS, f'groupib:{iid}')}"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": ioc.get("value", "Group-IB IOC"),
            "description": ioc.get("description", ""),
            "pattern": f"[file:hashes.'SHA-256' = '{ioc.get('hash')}']"
            if ioc.get("hash")
            else None,
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "x_groupib": {
                "item_id": iid,
                "collection": ioc.get("collection", "malware"),
            },
        }

    def _event_to_stix(self, event: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for event to stix."""
        now = _now_ts()
        eid = event.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'groupib:{eid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": event.get("date") or now,
            "modified": now,
            "name": event.get("title", "Group-IB Event"),
            "description": event.get("description", ""),
            "report_types": ["threat-report"],
            "x_groupib": {
                "event_id": eid,
                "collection": event.get("collection"),
                "severity": event.get("severity"),
            },
        }
