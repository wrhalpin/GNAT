# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.eset_ti.client
==================================

ESET Threat Intelligence connector.

Authentication
--------------
Bearer token::

    [eset_ti]
    host      = https://eti.eset.com
    api_token = eset_...

Key endpoints
-------------
* ``GET /api/v1/iocs``           — IOC feed
* ``GET /api/v1/reports``        — APT / campaign reports
* ``GET /api/v1/samples/{sha256}``
* ``GET /api/v1/yara``           — YARA rule feed
* ``GET /api/v1/botnet``         — botnet tracking
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_ESET = uuid.UUID("e5e7e7e0-0001-4a1e-9b1e-e5e7e7e0c0fe")


class ESETThreatIntelClient(BaseClient, ConnectorMixin):
    """HTTP client for ESET Threat Intelligence."""

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "report": "reports",
        "malware": "samples",
    }

    def __init__(
        self,
        host: str = "https://eti.eset.com",
        api_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize ESETThreatIntelClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header."""
        if not self.api_token:
            raise GNATClientError("ESET Threat Intelligence connector requires api_token.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query the reports list with a small page as a liveness probe."""
        try:
            self.get("/api/v1/reports", params={"limit": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single ESET resource by id."""
        if not object_id:
            raise GNATClientError("ESET TI get_object requires a non-empty id")
        if stix_type == "report":
            resp = self.get(f"/api/v1/reports/{object_id}")
            kind = "report"
        elif stix_type == "malware":
            resp = self.get(f"/api/v1/samples/{object_id}")
            kind = "sample"
        elif stix_type == "indicator":
            resp = self.get(f"/api/v1/iocs/{object_id}")
            kind = "ioc"
        else:
            raise GNATClientError(f"ESET TI get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"ESET TI returned unexpected payload for {object_id!r}")
        return dict(resp, _eset_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List ESET records."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"page": int(page), "limit": int(page_size)}
        for key in ("since", "actor", "family", "ioc_type"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "indicator":
            kind = (filters.get("kind") or "iocs").lower()
            if kind == "yara":
                resp = self.get("/api/v1/yara", params=params)
                tag = "yara"
            elif kind == "botnet":
                resp = self.get("/api/v1/botnet", params=params)
                tag = "botnet"
            else:
                resp = self.get("/api/v1/iocs", params=params)
                tag = "ioc"
        elif stix_type == "report":
            resp = self.get("/api/v1/reports", params=params)
            tag = "report"
        elif stix_type == "malware":
            resp = self.get("/api/v1/samples", params=params)
            tag = "sample"
        else:
            raise GNATClientError(f"ESET TI list_objects does not support stix_type={stix_type!r}")
        return [dict(r, _eset_kind=tag) for r in _extract_eset_list(resp)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """ESET TI connector is read-only."""
        raise GNATClientError(
            "ESET Threat Intelligence connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ESET TI connector is read-only."""
        raise GNATClientError(
            "ESET Threat Intelligence connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_iocs(self, since: str = "", ioc_type: str = "") -> list[dict[str, Any]]:
        """Return ESET IOC feed entries."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        if ioc_type:
            filters["ioc_type"] = ioc_type
        return self.list_objects("indicator", filters=filters, page_size=1000)

    def list_reports(self, actor: str = "", family: str = "") -> list[dict[str, Any]]:
        """Return ESET APT / campaign reports."""
        filters: dict[str, Any] = {}
        if actor:
            filters["actor"] = actor
        if family:
            filters["family"] = family
        return self.list_objects("report", filters=filters, page_size=500)

    def list_samples(self) -> list[dict[str, Any]]:
        """Return ESET malware sample catalog."""
        return self.list_objects("malware", page_size=500)

    def list_yara(self) -> list[dict[str, Any]]:
        """Return ESET YARA rule feed."""
        return self.list_objects("indicator", filters={"kind": "yara"}, page_size=1000)

    def list_botnet(self) -> list[dict[str, Any]]:
        """Return ESET botnet tracking entries."""
        return self.list_objects("indicator", filters={"kind": "botnet"}, page_size=1000)

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Fetch a single ESET report."""
        return self.get_object("report", report_id)

    def get_sample(self, sha256: str) -> dict[str, Any]:
        """Fetch ESET analysis metadata for a SHA-256."""
        return self.get_object("malware", sha256)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an ESET record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("ESET TI to_stix expects a dict input")

        kind = native.get("_eset_kind") or "ioc"

        if kind == "report":
            report_id = native.get("id") or native.get("title", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_ESET, f"report|{report_id}")
            return {
                "type": "report",
                "id": f"report--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": native.get("published") or utcnow(),
                "modified": native.get("updated") or utcnow(),
                "name": native.get("title") or str(report_id),
                "description": native.get("summary") or native.get("description", ""),
                "published": native.get("published") or utcnow(),
                "report_types": ["threat-report"],
                "object_refs": [],
                "x_eset": {
                    "actor": native.get("actor") or native.get("threat_actor"),
                    "malware_family": native.get("family"),
                    "region": native.get("region"),
                    "raw": native,
                },
            }

        if kind == "sample":
            sha256 = native.get("sha256") or native.get("id", "")
            family = native.get("family") or native.get("detection", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_ESET, f"malware|{family}|{sha256}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": native.get("description") or "ESET sample",
                "malware_types": ["unknown"],
                "x_eset": {"sha256": sha256, "raw": native},
            }

        # indicator (ioc / yara / botnet)
        value = native.get("ioc") or native.get("value") or ""
        ioc_type = (native.get("ioc_type") or native.get("type") or "").lower()
        if ioc_type in ("ip", "ipv4"):
            pattern = make_indicator_pattern("ipv4-addr", value)
        elif ioc_type == "domain":
            pattern = make_indicator_pattern("domain-name", value)
        elif ioc_type == "url":
            pattern = make_indicator_pattern("url", value)
        elif ioc_type in ("sha256", "sha1", "md5"):
            pattern = make_indicator_pattern(f"file:{ioc_type}", value)
        elif kind == "yara":
            pattern = f"[x-eset-yara:rule = '{native.get('rule_name') or value}']"
        else:
            pattern = f"[x-eset:value = '{value}']"

        stix_uuid = uuid.uuid5(_NAMESPACE_ESET, f"indicator|{kind}|{value or native.get('id', '')}")
        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"ESET: {value or native.get('rule_name', native.get('id', ''))}",
            "description": native.get("description") or "ESET threat indicator",
            "labels": ["malicious-activity"],
            "x_eset": {
                "kind": kind,
                "actor": native.get("actor"),
                "family": native.get("family"),
                "confidence": native.get("confidence"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """ESET TI connector is read-only."""
        return {
            "note": (
                "ESET Threat Intelligence connector is read-only. Use "
                "list_iocs, list_reports, list_samples, list_yara, "
                "list_botnet, get_report, or get_sample to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_eset_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an ESET response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "items", "results", "iocs", "reports", "samples", "rules"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
