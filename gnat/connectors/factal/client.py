# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.factal.client
=================================

Factal real-time risk intelligence connector.

Authentication
--------------
Bearer token::

    [factal]
    host      = https://api.factal.com
    api_token = factal_...

Key endpoints
-------------
* ``GET /v2/events``           — verified breaking-news events
* ``GET /v2/events/{id}``
* ``GET /v2/topics``           — topic taxonomy
* ``GET /v2/places``           — geographic places
* ``GET /v2/users/me``         — authenticated user (liveness probe)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_FACTAL = uuid.UUID("fac7a100-0001-4a1e-9b1e-fac7a100c0fe")


class FactalClient(BaseClient, ConnectorMixin):
    """HTTP client for Factal."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/v2"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"observed-data": "events"}

    def __init__(
        self,
        host: str = "https://api.factal.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize FactalClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    def authenticate(self) -> None:
        """Set Authorization: Bearer header."""
        if not self.api_token:
            raise GNATClientError("Factal connector requires api_token in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query ``/v2/users/me`` as an authenticated probe."""
        try:
            self.get("/v2/users/me")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Factal record by id."""
        if not object_id:
            raise GNATClientError("Factal get_object requires a non-empty id")
        if stix_type != "observed-data":
            raise GNATClientError(
                f"Factal get_object does not support stix_type={stix_type!r}"
            )
        resp = self.get(f"/v2/events/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Factal returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _ft_kind="event")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Factal records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": int(page_size), "page": int(page)}
        for key in ("topic", "country", "since", "min_severity"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            kind = (filters.get("kind") or "events").lower()
            if kind == "topics":
                resp = self.get("/v2/topics", params=params)
                tag = "topic"
            elif kind == "places":
                resp = self.get("/v2/places", params=params)
                tag = "place"
            else:
                resp = self.get("/v2/events", params=params)
                tag = "event"
        else:
            raise GNATClientError(
                f"Factal list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _ft_kind=tag) for r in _extract_factal_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Factal connector is read-only."""
        raise GNATClientError(
            "Factal connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Factal connector is read-only."""
        raise GNATClientError(
            "Factal connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_events(
        self,
        topic: str = "",
        country: str = "",
        since: str = "",
        min_severity: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return verified breaking-news events."""
        filters: dict[str, Any] = {}
        if topic:
            filters["topic"] = topic
        if country:
            filters["country"] = country
        if since:
            filters["since"] = since
        if min_severity is not None:
            filters["min_severity"] = int(min_severity)
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_event(self, event_id: str) -> dict[str, Any]:
        """Fetch a single event by id."""
        return self.get_object("observed-data", event_id)

    def list_topics(self) -> list[dict[str, Any]]:
        """Return Factal topic taxonomy."""
        return self.list_objects(
            "observed-data", filters={"kind": "topics"}, page_size=500
        )

    def list_places(self) -> list[dict[str, Any]]:
        """Return geographic place definitions."""
        return self.list_objects(
            "observed-data", filters={"kind": "places"}, page_size=500
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Factal record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Factal to_stix expects a dict input")

        kind = native.get("_ft_kind") or "event"

        if kind == "topic":
            topic_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_FACTAL, f"x-factal-topic|{topic_id}"
            )
            return {
                "type": "x-factal-topic",
                "id": f"x-factal-topic--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(topic_id),
                "x_factal": {"raw": native},
            }

        if kind == "place":
            place_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_FACTAL, f"identity|location|{place_id}"
            )
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(place_id),
                "identity_class": "group",
                "x_factal_place": {
                    "country": native.get("country"),
                    "lat": native.get("lat"),
                    "lon": native.get("lon"),
                    "raw": native,
                },
            }

        # event → observed-data envelope
        event_id = native.get("id") or ""
        refs: list[str] = []
        place = native.get("place") or native.get("location")
        if isinstance(place, dict):
            place_id = place.get("id") or place.get("name")
            if place_id:
                place_uuid = uuid.uuid5(
                    _NAMESPACE_FACTAL, f"identity|location|{place_id}"
                )
                refs.append(f"identity--{place_uuid}")

        first = (
            native.get("started_at")
            or native.get("created_at")
            or native.get("timestamp")
            or utcnow()
        )
        last = native.get("updated_at") or native.get("ended_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="factal",
            x_extensions={
                "factal": {
                    "event_id": event_id,
                    "title": native.get("title"),
                    "summary": native.get("summary") or native.get("description"),
                    "severity": native.get("severity"),
                    "category": native.get("category"),
                    "topics": native.get("topics") or [],
                    "verified": native.get("verified"),
                    "url": native.get("url"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Factal connector is read-only."""
        return {
            "note": (
                "Factal connector is read-only. Use list_events, get_event, "
                "list_topics, or list_places to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_factal_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Factal response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "results", "items", "events", "topics", "places"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
