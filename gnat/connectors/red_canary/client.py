# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.red_canary.client
=====================================

Red Canary MDR connector.

Authentication
--------------
API key via ``X-Api-Key`` header::

    [red_canary]
    host    = https://my.redcanary.co
    api_key = rc_...

Key endpoints
-------------
* ``GET /openapi/v3/detections``         — Red Canary confirmed detections
* ``GET /openapi/v3/detections/{id}``
* ``GET /openapi/v3/events``             — low-level EDR events backing
  a detection
* ``GET /openapi/v3/endpoints``          — managed endpoints
* ``GET /openapi/v3/endpoints/{id}``
* ``GET /openapi/v3/organization``       — customer org info
* ``PATCH /openapi/v3/detections/{id}``  — update status (not exposed
  via CRUD in Phase 2)

STIX Type Mapping
-----------------
* ``observed-data`` → detections (envelope wraps the affected endpoint
  as ``identity`` + any triggering ``process`` / ``ipv4-addr`` refs)
* ``identity``      → organization + endpoint metadata
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_REDCANARY = uuid.UUID("4edca4a2-0001-4a1e-9c1b-4edca4a2c0fe")


class RedCanaryClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Red Canary MDR.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://my.redcanary.co"``.
    api_key : str
        Red Canary API key.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/openapi/v3"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "detections",
        "identity": "organization",
    }

    def __init__(
        self,
        host: str = "https://my.redcanary.co",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize RedCanaryClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set X-Api-Key header from the configured key."""
        if not self.api_key:
            raise GNATClientError(
                "Red Canary connector requires api_key in config."
            )
        self._auth_headers["X-Api-Key"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/openapi/v3/organization`` as an authenticated probe."""
        try:
            self.get("/openapi/v3/organization")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Red Canary resource by id."""
        if not object_id:
            raise GNATClientError("Red Canary get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/openapi/v3/detections/{object_id}")
            kind = "detection"
        elif stix_type == "identity":
            resp = self.get(f"/openapi/v3/endpoints/{object_id}")
            kind = "endpoint"
        else:
            raise GNATClientError(
                f"Red Canary get_object does not support stix_type={stix_type!r}"
            )
        data = _unwrap_rc(resp)
        if not isinstance(data, dict):
            raise GNATClientError(
                f"Red Canary returned unexpected payload for {object_id!r}"
            )
        return dict(data, _rc_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Red Canary resources.

        ``filters`` keys: ``severity``, ``classification``, ``since``,
        ``kind`` (``"detections"`` default or ``"endpoints"`` for
        ``identity``).
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page[number]": int(page),
            "page[size]": int(page_size),
        }
        for key in ("severity", "classification", "since"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            resp = self.get("/openapi/v3/detections", params=params)
            kind = "detection"
        elif stix_type == "identity":
            resp = self.get("/openapi/v3/endpoints", params=params)
            kind = "endpoint"
        elif stix_type == "x-red-canary-event":
            resp = self.get("/openapi/v3/events", params=params)
            kind = "event"
        else:
            raise GNATClientError(
                f"Red Canary list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _rc_kind=kind) for r in _extract_rc_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Red Canary connector is read-only in Phase 2."""
        raise GNATClientError(
            "Red Canary connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Red Canary connector is read-only."""
        raise GNATClientError(
            "Red Canary connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_detections(
        self,
        severity: str = "",
        classification: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        """Return confirmed Red Canary detections."""
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if classification:
            filters["classification"] = classification
        if since:
            filters["since"] = since
        return self.list_objects(
            "observed-data", filters=filters, page_size=1000
        )

    def get_detection(self, detection_id: str) -> dict[str, Any]:
        """Fetch a single detection."""
        return self.get_object("observed-data", detection_id)

    def list_endpoints(self) -> list[dict[str, Any]]:
        """Return managed endpoints."""
        return self.list_objects("identity", page_size=1000)

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any]:
        """Fetch metadata for a specific endpoint."""
        return self.get_object("identity", endpoint_id)

    def list_events(self, since: str = "") -> list[dict[str, Any]]:
        """Return low-level EDR events backing detections."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        return self.list_objects(
            "x-red-canary-event", filters=filters, page_size=1000
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Red Canary record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Red Canary to_stix expects a dict input")

        kind = native.get("_rc_kind") or "detection"

        if kind == "endpoint":
            endpoint_id = native.get("id") or native.get("hostname", "unknown")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_REDCANARY, f"identity|endpoint|{endpoint_id}"
            )
            attrs = native.get("attributes") if isinstance(native.get("attributes"), dict) else native
            return {
                "type": "identity",
                "id": f"identity--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": attrs.get("hostname") or f"endpoint {endpoint_id}",
                "identity_class": "system",
                "x_red_canary_endpoint": {
                    "platform": attrs.get("platform"),
                    "operating_system": attrs.get("operating_system"),
                    "username": attrs.get("username"),
                    "ip_address": attrs.get("ip_address"),
                    "raw": native,
                },
            }

        # detection / event → observed-data envelope
        attrs = (
            native.get("attributes")
            if isinstance(native.get("attributes"), dict)
            else native
        )
        refs: list[str] = []
        endpoint_id = attrs.get("endpoint_id") or attrs.get("endpoint", {}).get("id") \
            if isinstance(attrs.get("endpoint"), dict) else attrs.get("endpoint_id")
        if endpoint_id:
            endpoint_uuid = uuid.uuid5(
                _NAMESPACE_REDCANARY, f"identity|endpoint|{endpoint_id}"
            )
            refs.append(f"identity--{endpoint_uuid}")

        ip = attrs.get("ip_address") or attrs.get("source_ip")
        if ip:
            ip_uuid = uuid.uuid5(
                _NAMESPACE_REDCANARY, f"ipv4-addr|{ip}"
            )
            refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            attrs.get("detected_at")
            or attrs.get("first_seen_at")
            or attrs.get("created_at")
            or utcnow()
        )
        last = attrs.get("last_seen_at") or attrs.get("updated_at") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="red_canary",
            x_extensions={
                "red_canary": {
                    "kind": kind,
                    "detection_id": native.get("id"),
                    "severity": attrs.get("severity"),
                    "classification": attrs.get("classification"),
                    "headline": attrs.get("headline"),
                    "summary": attrs.get("summary"),
                    "confirmed": attrs.get("confirmed"),
                    "endpoint_id": endpoint_id,
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Red Canary connector is read-only."""
        return {
            "note": (
                "Red Canary connector is read-only. Use list_detections, "
                "get_detection, list_endpoints, get_endpoint, or list_events "
                "to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _unwrap_rc(resp: Any) -> Any:
    """Strip Red Canary's JSON:API ``{"data": ...}`` envelope."""
    if isinstance(resp, dict) and "data" in resp:
        return resp["data"]
    return resp


def _extract_rc_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Red Canary list response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    for key in ("detections", "endpoints", "events", "results", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
