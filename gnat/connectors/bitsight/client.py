# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.bitsight.client
===============================

BitSight (Security Ratings + Vendor Risk Management) connector — full client.

Authentication
--------------
API Token via ``Authorization: Token`` header::

    [bitsight]
    host  = https://api.bitsighttech.com
    token = <your-bitsight-api-token>

Generate the token in BitSight UI (Settings → API Access).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | BitSight Resource                |
+================+==================================+
| vulnerability  | Findings / Compromised systems   |
+----------------+----------------------------------+
| report         | Companies / Ratings / Ratings history |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/companies                  — Company ratings and details
* /v1/companies/{id}/findings    — Detailed security findings
* /v1/companies/{id}/ratings     — Historical ratings
* /v1/companies/{id}/breaches    — Breach insights
* /v1/portfolios                 — Portfolio management (for vendor groups)
* /v1/alerts                     — Security alerts and notifications

Notes
-----
* Excellent for third-party/vendor risk intelligence and continuous ratings.
* Strong peer benchmarking and breach context.
* Complements UpGuard, Axonius, and your DRP/ASM stack with quantitative security ratings.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f6a7b8c9-d0e1-2f3a-4b5c-6d7e8f9a0b1c")


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class BitSightClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for BitSight API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.bitsighttech.com").
    token : str
        BitSight API token.
    """

    stix_type_map: dict[str, str] = {
        "vulnerability": "findings",
        "report": "companies",
    }

    def __init__(self, host: str = "https://api.bitsighttech.com", token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Token header."""
        self._auth_headers["Authorization"] = f"Token {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via companies endpoint."""
        self.get("/v1/companies", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "report":
            return self.get(f"/v1/companies/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/v1/companies/{object_id}/findings")
        raise GNATClientError(f"Unsupported STIX type for BitSight: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        params: dict[str, Any] = {"limit": page_size}
        params.update(filters)

        if stix_type == "vulnerability":
            # Findings are usually fetched per company
            company_id = filters.pop("company_id", None)
            if company_id:
                resp = self.get(f"/v1/companies/{company_id}/findings", params=params)
            else:
                resp = self.get("/v1/findings", params=params)  # global findings if supported
            return resp.get("data", []) if isinstance(resp, dict) else []
        # Default: companies/ratings
        resp = self.get("/v1/companies", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("BitSight connector is primarily read-only.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not supported in this connector.")

    # ── Expanded Domain-specific helpers ───────────────────────────────────

    def fetch_companies(
        self,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch company ratings and details."""
        params: dict[str, Any] = {"limit": limit, **(filters or {})}
        resp = self.get("/v1/companies", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_findings(
        self,
        company_id: str,
        limit: int = 50,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch detailed security findings for a specific company."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity.lower()
        resp = self.get(f"/v1/companies/{company_id}/findings", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_ratings_history(
        self,
        company_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch historical security ratings for a company."""
        resp = self.get(f"/v1/companies/{company_id}/ratings", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_breaches(
        self,
        company_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch breach insights for a company."""
        resp = self.get(f"/v1/companies/{company_id}/breaches", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    def fetch_alerts(
        self,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch security alerts and notifications."""
        resp = self.get("/v1/alerts", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Dispatch findings (vulnerability) vs. company/ratings (report)."""
        if "severity" in native and (
            "finding" in str(native).lower() or "breach" in str(native).lower()
        ):
            return self._finding_to_stix(native)
        return self._company_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "BitSight is primarily read-only for security ratings and vendor risk data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _finding_to_stix(self, finding: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        fid = finding.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'bitsight:{fid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": finding.get("date") or now,
            "modified": now,
            "name": finding.get("title", "BitSight Finding"),
            "description": finding.get("description", ""),
            "external_references": [{"source_name": "bitsight", "external_id": fid}],
            "x_bitsight": {
                "finding_id": fid,
                "severity": finding.get("severity"),
                "category": finding.get("category"),
                "company": finding.get("company_name"),
            },
        }

    def _company_to_stix(self, company: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        cid = company.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'bitsight:{cid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"BitSight Company: {company.get('name', cid)}",
            "description": f"Security rating and risk profile for {company.get('name')}",
            "report_types": ["vendor-risk"],
            "x_bitsight": {
                "company_id": cid,
                "rating": company.get("rating"),
                "rating_letter": company.get("rating_letter"),
                "peer_comparison": company.get("peer_comparison"),
                "breach_count": company.get("breach_count"),
            },
        }
