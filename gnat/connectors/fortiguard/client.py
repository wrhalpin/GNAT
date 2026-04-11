# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortiguard.client
=====================================

Fortinet FortiGuard Labs connector.

FortiGuard exposes several public data sources:

* IOC feeds (optional API key for higher rate limits)
* Outbreak Alerts (publicly readable RSS + JSON)
* IP and URL reputation (web lookups)
* Threat encyclopedia entries

Authentication
--------------
Optional API key via ``Authorization: Bearer <api_key>`` for the
commercial IOC Service; the public outbreak and encyclopedia endpoints
are anonymous::

    [fortiguard]
    host    = https://fortiguard.com
    api_key =

Key endpoints
-------------
* ``GET /api/v1/iocs``               — IOC feed (requires api_key)
* ``GET /api/v1/outbreak-alerts``    — Outbreak Alerts
* ``GET /encyclopedia/virus``        — virus encyclopedia
* ``GET /api/v1/ip/{ip}``            — IP reputation
* ``GET /api/v1/url?url={url}``      — URL category / reputation
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_FORTIGUARD = uuid.UUID("f0411164-0001-4a1e-9b1e-f0411164cafe")


class FortiGuardClient(BaseClient, ConnectorMixin):
    """HTTP client for FortiGuard Labs."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report": "outbreak-alerts",
        "malware": "encyclopedia/virus",
    }

    def __init__(
        self,
        host: str = "https://fortiguard.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize FortiGuardClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set optional Authorization Bearer header."""
        self._auth_headers["Accept"] = "application/json"
        if self.api_key:
            self._auth_headers["Authorization"] = f"Bearer {self.api_key}"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call the public outbreak-alerts endpoint as a liveness probe."""
        try:
            self.get("/api/v1/outbreak-alerts", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single FortiGuard record by id."""
        if not object_id:
            raise GNATClientError("FortiGuard get_object requires a non-empty id")
        if stix_type == "indicator":
            # Dispatch IP vs URL via _looks_like_ipv4
            if _looks_like_ipv4(object_id):
                resp = self.get(f"/api/v1/ip/{object_id}")
                kind = "ip"
            else:
                resp = self.get("/api/v1/url", params={"url": object_id})
                kind = "url"
        elif stix_type == "report":
            resp = self.get(f"/api/v1/outbreak-alerts/{object_id}")
            kind = "outbreak"
        elif stix_type == "malware":
            resp = self.get(f"/encyclopedia/virus/{object_id}")
            kind = "virus"
        else:
            raise GNATClientError(
                f"FortiGuard get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"FortiGuard returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _fg_kind=kind, _fg_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List FortiGuard records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "limit": int(page_size)}
        for key in ("severity", "since", "category"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "indicator":
            if not self.api_key:
                raise GNATClientError(
                    "FortiGuard list_objects(indicator) requires a commercial api_key"
                )
            resp = self.get("/api/v1/iocs", params=params)
            tag = "ioc"
        elif stix_type == "report":
            resp = self.get("/api/v1/outbreak-alerts", params=params)
            tag = "outbreak"
        elif stix_type == "malware":
            resp = self.get("/encyclopedia/virus", params=params)
            tag = "virus"
        else:
            raise GNATClientError(
                f"FortiGuard list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _fg_kind=tag) for r in _extract_fg_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """FortiGuard connector is read-only."""
        raise GNATClientError(
            "FortiGuard connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """FortiGuard connector is read-only."""
        raise GNATClientError(
            "FortiGuard connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_outbreak_alerts(self) -> list[dict[str, Any]]:
        """Return FortiGuard outbreak alerts."""
        return self.list_objects("report", page_size=500)

    def list_iocs(
        self, since: str = "", severity: str = ""
    ) -> list[dict[str, Any]]:
        """Return FortiGuard IOC feed entries (requires commercial api_key)."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if severity:
            filters["severity"] = severity
        return self.list_objects("indicator", filters=filters, page_size=1000)

    def ip_reputation(self, ip: str) -> dict[str, Any]:
        """Return FortiGuard IP reputation."""
        return self.get_object("indicator", ip)

    def url_reputation(self, url: str) -> dict[str, Any]:
        """Return FortiGuard URL category / reputation."""
        return self.get_object("indicator", url)

    def get_outbreak_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch a single outbreak alert."""
        return self.get_object("report", alert_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a FortiGuard record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("FortiGuard to_stix expects a dict input")

        kind = native.get("_fg_kind") or "outbreak"

        if kind in ("ip", "url", "ioc"):
            value = (
                native.get("_fg_query")
                or native.get("value")
                or native.get("ioc")
                or ""
            )
            if kind == "ip":
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif kind == "url":
                pattern = make_indicator_pattern("url", value)
            else:
                ioc_type = (native.get("type") or "").lower()
                if ioc_type in ("ip", "ipv4"):
                    pattern = make_indicator_pattern("ipv4-addr", value)
                elif ioc_type == "domain":
                    pattern = make_indicator_pattern("domain-name", value)
                elif ioc_type in ("sha256", "sha1", "md5"):
                    pattern = make_indicator_pattern(f"file:{ioc_type}", value)
                else:
                    pattern = make_indicator_pattern("url", value)
            stix_uuid = uuid.uuid5(_NAMESPACE_FORTIGUARD, f"indicator|{value}")
            score = native.get("rating") or native.get("risk_score")
            labels = (
                ["malicious-activity"]
                if (isinstance(score, (int, float)) and score >= 5)
                or (isinstance(score, str) and "malicious" in score.lower())
                else ["benign"]
            )
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"FortiGuard: {value}",
                "description": native.get("description") or "FortiGuard IOC",
                "labels": labels,
                "x_fortiguard": {
                    "rating": native.get("rating"),
                    "category": native.get("category"),
                    "raw": native,
                },
            }

        if kind == "virus":
            name = native.get("name") or native.get("id", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_FORTIGUARD, f"malware|{name}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(name),
                "is_family": bool(native.get("is_family", True)),
                "description": native.get("description") or "",
                "malware_types": ["unknown"],
                "x_fortiguard": {"raw": native},
            }

        # outbreak → report
        alert_id = native.get("id") or native.get("title", "unknown")
        stix_uuid = uuid.uuid5(_NAMESPACE_FORTIGUARD, f"report|{alert_id}")
        return {
            "type": "report",
            "id": f"report--{stix_uuid}",
            "spec_version": "2.1",
            "created": native.get("published") or utcnow(),
            "modified": native.get("updated") or utcnow(),
            "name": native.get("title") or str(alert_id),
            "description": native.get("summary") or native.get("description", ""),
            "published": native.get("published") or utcnow(),
            "report_types": ["threat-report"],
            "object_refs": [],
            "x_fortiguard": {
                "severity": native.get("severity"),
                "category": native.get("category"),
                "affected_products": native.get("affected_products"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """FortiGuard connector is read-only."""
        return {
            "note": (
                "FortiGuard connector is read-only. Use list_outbreak_alerts, "
                "list_iocs, ip_reputation, url_reputation, or "
                "get_outbreak_alert to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _looks_like_ipv4(value: str) -> bool:
    """Return True if *value* looks like an IPv4 dotted-quad."""
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _extract_fg_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a FortiGuard response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "items", "results", "iocs", "alerts", "virus"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
