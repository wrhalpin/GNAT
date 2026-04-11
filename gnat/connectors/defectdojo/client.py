# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.defectdojo.client
=================================

DefectDojo (Open Source Vulnerability Management & Orchestration) connector — full client.

Authentication
--------------
API Token via ``Authorization: Token`` header::

    [defectdojo]
    host  = https://your-defectdojo-instance.com
    token = <your-defectdojo-api-token>

Generate token in DefectDojo UI (API v2 section) or via admin.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | DefectDojo Resource              |
+================+==================================+
| vulnerability  | Findings                         |
+----------------+----------------------------------+
| report         | Engagements / Tests              |
+----------------+----------------------------------+

Key Endpoints (API v2)
----------------------
* /api/v2/findings/          — List/create findings (core vuln data)
* /api/v2/engagements/       — Engagements (projects/tests)
* /api/v2/tests/             — Individual tests/scans
* /api/v2/products/          — Products (high-level grouping)

Notes
-----
* DefectDojo is writable (supports import/upsert of findings).
* Strong support for severity, CVSS, CWE, MITRE ATT&CK, endpoints, and tags.
* OpenAPI/Swagger available at /api/v2/oa3/swagger-ui/ on your instance.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

_STIX_NS = _uuid.UUID("c7d8e9f0-a1b2-3c4d-5e6f-7a8b9c0d1e2f")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class DefectDojoClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for DefectDojo API v2.

    Parameters
    ----------
    host : str
        Base URL of your DefectDojo instance.
    token : str
        DefectDojo API token.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "vulnerability": "findings",
        "report": "engagements",
    }

    def __init__(self, host: str, token: str = "", **kwargs: Any):
        """Initialize DefectDojoClient."""
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Token auth header."""
        self._auth_headers["Authorization"] = f"Token {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via findings endpoint."""
        self.get("/api/v2/findings/", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        if stix_type == "vulnerability":
            return self.get(f"/api/v2/findings/{object_id}/")
        if stix_type == "report":
            return self.get(f"/api/v2/engagements/{object_id}/")
        from gnat.clients.base import GNATClientError

        raise GNATClientError(f"Unsupported STIX type for DefectDojo: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        params.update(filters)

        if stix_type == "report":
            resp = self.get("/api/v2/engagements/", params=params)
        else:
            resp = self.get("/api/v2/findings/", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        if stix_type == "vulnerability":
            obj_id = payload.get("id")
            if obj_id:
                return self.put(f"/api/v2/findings/{obj_id}/", json=payload)
            return self.post("/api/v2/findings/", json=payload)
        if stix_type == "report":
            obj_id = payload.get("id")
            if obj_id:
                return self.put(f"/api/v2/engagements/{obj_id}/", json=payload)
            return self.post("/api/v2/engagements/", json=payload)
        from gnat.clients.base import GNATClientError

        raise GNATClientError(f"Unsupported STIX type for DefectDojo: {stix_type}")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        if stix_type == "vulnerability":
            self.delete(f"/api/v2/findings/{object_id}/")
        elif stix_type == "report":
            self.delete(f"/api/v2/engagements/{object_id}/")
        else:
            from gnat.clients.base import GNATClientError

            raise GNATClientError(f"Unsupported STIX type for DefectDojo: {stix_type}")

    # ── Expanded Domain-specific helpers ──────────────────────────────────

    def fetch_findings(
        self,
        limit: int = 50,
        severity: str | None = None,
        active: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch vulnerability findings with optional filters."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        if active is not None:
            params["active"] = str(active).lower()
        resp = self.get("/api/v2/findings/", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def fetch_engagements(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch engagements (projects/tests)."""
        resp = self.get("/api/v2/engagements/", params={"limit": limit})
        return resp.get("results", []) if isinstance(resp, dict) else []

    def fetch_products(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch products (high-level application grouping)."""
        resp = self.get("/api/v2/products/", params={"limit": limit})
        return resp.get("results", []) if isinstance(resp, dict) else []

    def import_scan(
        self,
        scan_type: str,
        file_content: str,
        engagement_id: int,
    ) -> dict[str, Any]:
        """Import a scan result into DefectDojo."""
        payload = {
            "scan_type": scan_type,
            "file": file_content,
            "engagement": engagement_id,
        }
        return self.post("/api/v2/import-scan/", json=payload)

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch finding (vulnerability) vs. engagement (report)."""
        if "severity" in native or "cve" in native or "cwe" in native:
            return self._finding_to_stix(native)
        return self._engagement_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        stix_type = stix_dict.get("type", "")
        if stix_type == "vulnerability":
            return {
                "title": stix_dict.get("name", ""),
                "description": stix_dict.get("description", ""),
                "severity": stix_dict.get("x_severity", "Info"),
                "active": True,
                "verified": False,
            }
        return {
            "name": stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "status": "In Progress",
        }

    def _finding_to_stix(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for finding to stix."""
        now = _now_ts()
        fid = str(finding.get("id", ""))
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'defectdojo:{fid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": CURRENT_SPEC_VERSION,
            "created": finding.get("date") or now,
            "modified": now,
            "name": finding.get("title", "DefectDojo Finding"),
            "description": finding.get("description", ""),
            "external_references": [{"source_name": "defectdojo", "external_id": fid}],
            "x_severity": finding.get("severity", ""),
            "x_defectdojo": {
                "finding_id": fid,
                "severity": finding.get("severity"),
                "cve": finding.get("cve"),
                "cwe": finding.get("cwe"),
                "active": finding.get("active"),
                "verified": finding.get("verified"),
                "product": self._extract_product_name(finding),
            },
        }

    @staticmethod
    def _extract_product_name(finding: dict[str, Any]) -> str | None:
        """Extract the product name from the nested finding.test.engagement.product path."""
        test = finding.get("test")
        if not isinstance(test, dict):
            return None
        engagement = test.get("engagement")
        if not isinstance(engagement, dict):
            return None
        product = engagement.get("product")
        if not isinstance(product, dict):
            return None
        return product.get("name")

    def _engagement_to_stix(self, engagement: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for engagement to stix."""
        now = _now_ts()
        eid = str(engagement.get("id", ""))
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'defectdojo:{eid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": CURRENT_SPEC_VERSION,
            "created": engagement.get("target_start") or now,
            "modified": now,
            "name": engagement.get("name", "DefectDojo Engagement"),
            "description": engagement.get("description", ""),
            "report_types": ["vulnerability-assessment"],
            "x_defectdojo": {
                "engagement_id": eid,
                "status": engagement.get("status"),
                "product": engagement.get("product"),
            },
        }
