# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.bitdefender_iz.client
=========================================

Bitdefender IntelliZone connector.

Authentication
--------------
API key header (``X-API-Key``)::

    [bitdefender_iz]
    host    = https://intellizone.bitdefender.com
    api_key = bd_...

Key endpoints
-------------
* ``GET /api/v1/iocs``
* ``GET /api/v1/iocs/{id}``
* ``GET /api/v1/reports``
* ``GET /api/v1/reports/{id}``
* ``GET /api/v1/apt/groups``       — APT groups
* ``GET /api/v1/malware/families`` — malware family catalog
* ``GET /api/v1/samples/{sha256}``
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_BITDEFENDER = uuid.UUID("b17de7ea-0001-4a1e-9b1e-b17de7eac0fe")


class BitdefenderIntelliZoneClient(BaseClient, ConnectorMixin):
    """HTTP client for Bitdefender IntelliZone."""

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report": "reports",
        "malware": "malware/families",
        "threat-actor": "apt/groups",
    }

    def __init__(
        self,
        host: str = "https://intellizone.bitdefender.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize BitdefenderIntelliZoneClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set X-API-Key header."""
        if not self.api_key:
            raise GNATClientError(
                "Bitdefender IntelliZone connector requires api_key in config."
            )
        self._auth_headers["X-API-Key"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the reports list as a liveness probe."""
        try:
            self.get("/api/v1/reports", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Bitdefender record by id."""
        if not object_id:
            raise GNATClientError(
                "Bitdefender IntelliZone get_object requires a non-empty id"
            )
        if stix_type == "report":
            resp = self.get(f"/api/v1/reports/{object_id}")
            kind = "report"
        elif stix_type == "malware":
            resp = self.get(f"/api/v1/malware/families/{object_id}")
            kind = "family"
        elif stix_type == "threat-actor":
            resp = self.get(f"/api/v1/apt/groups/{object_id}")
            kind = "actor"
        elif stix_type == "indicator":
            resp = self.get(f"/api/v1/iocs/{object_id}")
            kind = "ioc"
        else:
            raise GNATClientError(
                f"Bitdefender IntelliZone get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Bitdefender IntelliZone returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _bd_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Bitdefender records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "limit": int(page_size)}
        for key in ("since", "actor", "family", "ioc_type"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "indicator":
            resp = self.get("/api/v1/iocs", params=params)
            tag = "ioc"
        elif stix_type == "report":
            resp = self.get("/api/v1/reports", params=params)
            tag = "report"
        elif stix_type == "malware":
            resp = self.get("/api/v1/malware/families", params=params)
            tag = "family"
        elif stix_type == "threat-actor":
            resp = self.get("/api/v1/apt/groups", params=params)
            tag = "actor"
        else:
            raise GNATClientError(
                f"Bitdefender IntelliZone list_objects does not support stix_type={stix_type!r}"
            )
        return [dict(r, _bd_kind=tag) for r in _extract_bd_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Bitdefender IntelliZone connector is read-only."""
        raise GNATClientError(
            "Bitdefender IntelliZone connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Bitdefender IntelliZone connector is read-only."""
        raise GNATClientError(
            "Bitdefender IntelliZone connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_iocs(
        self, since: str = "", ioc_type: str = ""
    ) -> list[dict[str, Any]]:
        """Return IntelliZone IOC feed entries."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if ioc_type:
            filters["ioc_type"] = ioc_type
        return self.list_objects("indicator", filters=filters, page_size=1000)

    def list_reports(
        self, actor: str = ""
    ) -> list[dict[str, Any]]:
        """Return IntelliZone threat reports."""
        filters: dict[str, Any] = {}
        if actor:
            filters["actor"] = actor
        return self.list_objects("report", filters=filters, page_size=500)

    def list_malware_families(self) -> list[dict[str, Any]]:
        """Return Bitdefender's malware family catalog."""
        return self.list_objects("malware", page_size=1000)

    def list_apt_groups(self) -> list[dict[str, Any]]:
        """Return Bitdefender's APT group taxonomy."""
        return self.list_objects("threat-actor", page_size=500)

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Fetch a single threat report."""
        return self.get_object("report", report_id)

    def get_sample(self, sha256: str) -> dict[str, Any]:
        """Fetch analysis metadata for a SHA-256."""
        resp = self.get(f"/api/v1/samples/{sha256}")
        if isinstance(resp, dict):
            return dict(resp, _bd_kind="sample")
        return {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Bitdefender record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Bitdefender IntelliZone to_stix expects a dict input")

        kind = native.get("_bd_kind") or "ioc"

        if kind == "report":
            report_id = native.get("id") or native.get("title", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_BITDEFENDER, f"report|{report_id}")
            return {
                "type": "report",
                "id": f"report--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": native.get("published") or utcnow(),
                "modified": native.get("updated") or utcnow(),
                "name": native.get("title") or str(report_id),
                "description": native.get("summary") or "",
                "published": native.get("published") or utcnow(),
                "report_types": ["threat-report"],
                "object_refs": [],
                "x_bitdefender": {"raw": native},
            }

        if kind == "family":
            family_id = native.get("id") or native.get("name", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_BITDEFENDER, f"malware|{family_id}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(family_id),
                "is_family": True,
                "description": native.get("description") or "",
                "malware_types": native.get("types") or ["unknown"],
                "x_bitdefender": {"raw": native},
            }

        if kind == "actor":
            actor_id = native.get("id") or native.get("name", "unknown")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_BITDEFENDER, f"threat-actor|{actor_id}"
            )
            return {
                "type": "threat-actor",
                "id": f"threat-actor--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(actor_id),
                "description": native.get("description") or "",
                "threat_actor_types": ["unknown"],
                "aliases": native.get("aliases") or [],
                "x_bitdefender": {"raw": native},
            }

        if kind == "sample":
            sha256 = native.get("sha256") or ""
            family = native.get("family") or native.get("detection", "unknown")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_BITDEFENDER, f"malware|{family}|{sha256}"
            )
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": native.get("description") or "Bitdefender sample",
                "malware_types": ["unknown"],
                "x_bitdefender": {"sha256": sha256, "raw": native},
            }

        # indicator
        value = native.get("value") or native.get("ioc") or ""
        ioc_type = (native.get("type") or native.get("ioc_type") or "").lower()
        if ioc_type in ("ip", "ipv4"):
            pattern = make_indicator_pattern("ipv4-addr", value)
        elif ioc_type == "domain":
            pattern = make_indicator_pattern("domain-name", value)
        elif ioc_type == "url":
            pattern = make_indicator_pattern("url", value)
        elif ioc_type in ("sha256", "sha1", "md5"):
            pattern = make_indicator_pattern(f"file:{ioc_type}", value)
        else:
            pattern = f"[x-bitdefender:value = '{value}']"
        stix_uuid = uuid.uuid5(_NAMESPACE_BITDEFENDER, f"indicator|{value}")
        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"Bitdefender: {value}",
            "description": native.get("description") or "Bitdefender IntelliZone IOC",
            "labels": ["malicious-activity"],
            "x_bitdefender": {
                "confidence": native.get("confidence"),
                "severity": native.get("severity"),
                "actor": native.get("actor"),
                "family": native.get("family"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Bitdefender IntelliZone connector is read-only."""
        return {
            "note": (
                "Bitdefender IntelliZone connector is read-only. Use list_iocs, "
                "list_reports, list_malware_families, list_apt_groups, "
                "get_report, or get_sample to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_bd_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Bitdefender response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "items", "results", "iocs", "reports", "families", "groups"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
