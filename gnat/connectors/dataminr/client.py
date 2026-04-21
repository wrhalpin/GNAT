# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dataminr.client
===================================

Dataminr Pulse real-time event/threat/risk intelligence connector.

Authentication
--------------
OAuth2 client credentials at ``/auth/2/token``::

    [dataminr]
    host          = https://gateway.dataminr.com
    client_id     = dm_client
    client_secret = dm_secret

Key endpoints
-------------
* ``POST /auth/2/token``                 — token exchange
* ``GET  /api/3/alerts``                 — recent Pulse alerts
* ``GET  /api/3/alerts/{id}``
* ``GET  /api/3/lists``                  — watch lists
* ``GET  /api/3/lists/{id}/alerts``
* ``GET  /api/3/relatedAlerts``          — related-alert traversal

STIX Type Mapping
-----------------
``observed-data`` → real-time alerts (each wraps a synthetic location
``identity`` ref + the source as a custom ``x_dataminr_source``).
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_DATAMINR = uuid.UUID("da7a0001-0001-4a1e-9b1e-da7a0001c0fe")


class DataminrClient(BaseClient, ConnectorMixin):
    """HTTP client for Dataminr Pulse."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/api/3"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "alerts",
    }

    def __init__(
        self,
        host: str = "https://gateway.dataminr.com",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize DataminrClient."""
        super().__init__(host=host, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> None:
        """Exchange client credentials for a Dataminr Bearer token."""
        if not self.client_id or not self.client_secret:
            raise GNATClientError("Dataminr connector requires client_id and client_secret.")
        resp = self.post(
            "/auth/2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        token = ""
        if isinstance(resp, dict):
            token = resp.get("dmaToken") or resp.get("access_token") or resp.get("token", "")
        if not token:
            raise GNATClientError("Dataminr authentication failed — no token in response")
        self._auth_headers["Authorization"] = f"Dmauth {token}"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Query alerts with a tiny page as a liveness probe."""
        try:
            self.get("/api/3/alerts", params={"num": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Dataminr alert by id."""
        if not object_id:
            raise GNATClientError("Dataminr get_object requires a non-empty id")
        if stix_type != "observed-data":
            raise GNATClientError(f"Dataminr get_object does not support stix_type={stix_type!r}")
        resp = self.get(f"/api/3/alerts/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"Dataminr returned unexpected payload for {object_id!r}")
        return dict(resp, _dm_kind="alert")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Dataminr records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"num": int(page_size)}
        for key in ("from", "to", "lists", "alertType"):
            if filters.get(key):
                params[key] = filters[key]
        if stix_type == "observed-data":
            kind = (filters.get("kind") or "alerts").lower()
            if kind == "lists":
                resp = self.get("/api/3/lists", params=params)
                tag = "list"
            elif kind == "list_alerts":
                list_id = filters.get("list_id")
                if not list_id:
                    raise GNATClientError("Dataminr list_alerts requires 'list_id' filter")
                resp = self.get(f"/api/3/lists/{list_id}/alerts", params=params)
                tag = "alert"
            elif kind == "related":
                alert_id = filters.get("alert_id")
                if not alert_id:
                    raise GNATClientError("Dataminr related requires 'alert_id' filter")
                resp = self.get(
                    "/api/3/relatedAlerts",
                    params={**params, "alertId": alert_id},
                )
                tag = "alert"
            else:
                resp = self.get("/api/3/alerts", params=params)
                tag = "alert"
        else:
            raise GNATClientError(f"Dataminr list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _dm_kind=tag) for r in _extract_dataminr_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Dataminr connector is read-only."""
        raise GNATClientError("Dataminr connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Dataminr connector is read-only."""
        raise GNATClientError("Dataminr connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_alerts(self, since: str = "", alert_type: str = "") -> list[dict[str, Any]]:
        """Return recent Pulse alerts."""
        filters: dict[str, Any] = {}
        if since:
            filters["from"] = since
        if alert_type:
            filters["alertType"] = alert_type
        return self.list_objects("observed-data", filters=filters, page_size=500)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch a single Pulse alert by id."""
        return self.get_object("observed-data", alert_id)

    def list_watchlists(self) -> list[dict[str, Any]]:
        """Return configured watch lists."""
        return self.list_objects("observed-data", filters={"kind": "lists"}, page_size=500)

    def list_list_alerts(self, list_id: str) -> list[dict[str, Any]]:
        """Return alerts matching a specific watch list."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "list_alerts", "list_id": list_id},
            page_size=500,
        )

    def list_related_alerts(self, alert_id: str) -> list[dict[str, Any]]:
        """Return alerts related to a specific source alert."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "related", "alert_id": alert_id},
            page_size=500,
        )

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Dataminr record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Dataminr to_stix expects a dict input")

        kind = native.get("_dm_kind") or "alert"

        if kind == "list":
            list_id = native.get("id") or native.get("name", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_DATAMINR, f"x-dataminr-list|{list_id}")
            return {
                "type": "x-dataminr-list",
                "id": f"x-dataminr-list--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "name": native.get("name") or str(list_id),
                "x_dataminr": {"raw": native},
            }

        # alert → observed-data envelope
        alert_id = native.get("alertId") or native.get("id") or ""
        refs: list[str] = []
        location = native.get("eventLocation") or {}
        if isinstance(location, dict):
            place = location.get("name") or location.get("countryCode")
            if place:
                loc_uuid = uuid.uuid5(_NAMESPACE_DATAMINR, f"identity|location|{place}")
                refs.append(f"identity--{loc_uuid}")

        first = (
            native.get("eventTime") or native.get("publishTime") or native.get("time") or utcnow()
        )

        alert_type_raw = native.get("alertType")
        if isinstance(alert_type_raw, dict):
            alert_type_val = alert_type_raw.get("name") or alert_type_raw.get("id")
        else:
            alert_type_val = alert_type_raw

        source_raw = native.get("source")
        if isinstance(source_raw, dict):
            source_val = source_raw.get("displayName") or source_raw.get("name")
        else:
            source_val = source_raw

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=first,
            number_observed=1,
            object_refs=refs,
            source_name="dataminr",
            x_extensions={
                "dataminr": {
                    "alert_id": alert_id,
                    "alert_type": alert_type_val,
                    "caption": native.get("caption"),
                    "headline": native.get("headline"),
                    "url": native.get("expandAlertURL") or native.get("url"),
                    "source": source_val,
                    "categories": native.get("categories") or [],
                    "watchlists": native.get("watchlistsMatchedByType")
                    or native.get("watchlistsMatched"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Dataminr connector is read-only."""
        return {
            "note": (
                "Dataminr connector is read-only. Use list_alerts, "
                "get_alert, list_watchlists, list_list_alerts, or "
                "list_related_alerts to query the Pulse API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_dataminr_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Dataminr response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "alerts", "results", "items", "watchlists", "lists"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
