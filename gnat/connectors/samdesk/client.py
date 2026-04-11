# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.samdesk.client
==================================

Samdesk global crisis-detection connector.

Authentication
--------------
API key header::

    [samdesk]
    host    = https://api.samdesk.io
    api_key = sd_...

Key endpoints
-------------
* ``GET /v1/events``                  — crisis events feed
* ``GET /v1/events/{id}``
* ``GET /v1/categories``              — event categories
* ``GET /v1/topics``                  — saved topics / monitors
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_SAMDESK = uuid.UUID("5a40e510-0001-4a1e-9b1e-5a40e510c0fe")


class SamdeskClient(BaseClient, ConnectorMixin):
    """HTTP client for Samdesk."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"observed-data": "events"}

    def __init__(
        self,
        host: str = "https://api.samdesk.io",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SamdeskClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    def authenticate(self) -> None:
        """Set X-Api-Key header from the configured key."""
        if not self.api_key:
            raise GNATClientError("Samdesk connector requires api_key in config.")
        self._auth_headers["X-Api-Key"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query categories as a cheap authenticated probe."""
        try:
            self.get("/v1/categories", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Samdesk record by id."""
        if not object_id:
            raise GNATClientError("Samdesk get_object requires a non-empty id")
        if stix_type != "observed-data":
            raise GNATClientError(
                f"Samdesk get_object does not support stix_type={stix_type!r}"
            )
        resp = self.get(f"/v1/events/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Samdesk returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _sd_kind="event")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Samdesk records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        for key in ("category", "country", "since", "until", "topic"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "events").lower()
            if kind == "categories":
                resp = self.get("/v1/categories", params=params)
                tag = "category"
            elif kind == "topics":
                resp = self.get("/v1/topics", params=params)
                tag = "topic"
            else:
                resp = self.get("/v1/events", params=params)
                tag = "event"
        else:
            raise GNATClientError(
                f"Samdesk list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _sd_kind=tag) for r in _extract_samdesk_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Samdesk connector is read-only."""
        raise GNATClientError(
            "Samdesk connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Samdesk connector is read-only."""
        raise GNATClientError(
            "Samdesk connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_events(
        self,
        category: str = "",
        country: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        """Return crisis events."""
        filters: dict[str, Any] = {}
        if category:
            filters["category"] = category
        if country:
            filters["country"] = country
        if since:
            filters["since"] = since
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_event(self, event_id: str) -> dict[str, Any]:
        """Fetch a single event by id."""
        return self.get_object("observed-data", event_id)

    def list_categories(self) -> list[dict[str, Any]]:
        """Return event category taxonomy."""
        return self.list_objects(
            "observed-data", filters={"kind": "categories"}, page_size=500
        )

    def list_topics(self) -> list[dict[str, Any]]:
        """Return saved topics / monitors."""
        return self.list_objects(
            "observed-data", filters={"kind": "topics"}, page_size=500
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Samdesk record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Samdesk to_stix expects a dict input")

        kind = native.get("_sd_kind") or "event"

        if kind in ("category", "topic"):
            cat_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_SAMDESK, f"x-samdesk-{kind}|{cat_id}"
            )
            return {
                "type": f"x-samdesk-{kind}",
                "id": f"x-samdesk-{kind}--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(cat_id),
                "x_samdesk": {"raw": native},
            }

        # event → observed-data envelope
        event_id = native.get("id") or ""
        refs: list[str] = []
        location = native.get("location")
        if isinstance(location, dict):
            place = location.get("name") or location.get("country")
            if place:
                loc_uuid = uuid.uuid5(
                    _NAMESPACE_SAMDESK, f"identity|location|{place}"
                )
                refs.append(f"identity--{loc_uuid}")

        first = (
            native.get("started_at")
            or native.get("created_at")
            or native.get("timestamp")
            or utcnow()
        )

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=native.get("updated_at") or first,
            number_observed=1,
            object_refs=refs,
            source_name="samdesk",
            x_extensions={
                "samdesk": {
                    "event_id": event_id,
                    "title": native.get("title"),
                    "description": native.get("description"),
                    "category": native.get("category"),
                    "country": (location or {}).get("country") if isinstance(location, dict) else None,
                    "city": (location or {}).get("city") if isinstance(location, dict) else None,
                    "severity": native.get("severity"),
                    "url": native.get("url"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Samdesk connector is read-only."""
        return {
            "note": (
                "Samdesk connector is read-only. Use list_events, "
                "get_event, list_categories, or list_topics to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_samdesk_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Samdesk response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "events", "categories", "topics"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
