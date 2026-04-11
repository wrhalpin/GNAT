# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abuseipdb.client
====================================

AbuseIPDB community IP reputation connector.

Authentication
--------------
Free tier API key via the ``Key`` header::

    [abuseipdb]
    host    = https://api.abuseipdb.com
    api_key = abuseipdb_...

Key endpoints
-------------
* ``GET  /api/v2/check?ipAddress={ip}``      — single IP reputation
* ``GET  /api/v2/check-block?network={cidr}`` — CIDR block reputation
* ``GET  /api/v2/blacklist``                 — paginated blacklist
* ``POST /api/v2/report``                    — submit an abuse report
* ``GET  /api/v2/reports?ipAddress={ip}``    — historical reports for an IP
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_ABUSEIPDB = uuid.UUID("ab051d80-0001-4a1e-9b1e-ab051d80c0fe")


class AbuseIPDBClient(BaseClient, ConnectorMixin):
    """HTTP client for AbuseIPDB."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api/v2"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"indicator": "check"}

    def __init__(
        self,
        host: str = "https://api.abuseipdb.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize AbuseIPDBClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    def authenticate(self) -> None:
        """Set the proprietary ``Key`` header from the configured key."""
        if not self.api_key:
            raise GNATClientError("AbuseIPDB connector requires api_key in config.")
        self._auth_headers["Key"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Look up a known-clean IP as a liveness probe."""
        try:
            self.get("/api/v2/check", params={"ipAddress": "8.8.8.8", "maxAgeInDays": 30})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch reputation data for a single IP."""
        if not object_id:
            raise GNATClientError(
                "AbuseIPDB get_object requires a non-empty IP address"
            )
        if stix_type != "indicator":
            raise GNATClientError(
                f"AbuseIPDB get_object does not support stix_type={stix_type!r}"
            )
        resp = self.get(
            "/api/v2/check",
            params={"ipAddress": object_id, "maxAgeInDays": 90, "verbose": True},
        )
        data = _unwrap_abuseipdb(resp)
        if not isinstance(data, dict):
            raise GNATClientError(
                f"AbuseIPDB returned unexpected payload for {object_id!r}"
            )
        return dict(data, _ai_kind="reputation", _ai_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List AbuseIPDB records.

        ``filters`` keys:

        * ``confidence_min`` — minimum abuse confidence (default 90 for blacklist)
        * ``cidr`` — CIDR block for ``check-block`` endpoint
        * ``ip`` — IP address for the historical reports endpoint
        """
        filters = dict(filters or {})

        if stix_type != "indicator":
            raise GNATClientError(
                f"AbuseIPDB list_objects does not support stix_type={stix_type!r}"
            )
        kind = (filters.get("kind") or "blacklist").lower()
        if kind == "check_block":
            cidr = filters.get("cidr")
            if not cidr:
                raise GNATClientError(
                    "AbuseIPDB check_block requires a 'cidr' filter"
                )
            resp = self.get(
                "/api/v2/check-block",
                params={"network": cidr, "maxAgeInDays": 30},
            )
            data = _unwrap_abuseipdb(resp)
            reported = data.get("reportedAddress", []) if isinstance(data, dict) else []
            return [dict(r, _ai_kind="reputation") for r in reported if isinstance(r, dict)]
        if kind == "reports":
            ip = filters.get("ip")
            if not ip:
                raise GNATClientError(
                    "AbuseIPDB reports requires an 'ip' filter"
                )
            resp = self.get(
                "/api/v2/reports",
                params={"ipAddress": ip, "maxAgeInDays": 90, "perPage": int(page_size)},
            )
            data = _unwrap_abuseipdb(resp)
            results = (
                data.get("results", [])
                if isinstance(data, dict)
                else []
            )
            return [dict(r, _ai_kind="report") for r in results if isinstance(r, dict)]
        # default → blacklist
        params: dict[str, Any] = {
            "confidenceMinimum": int(filters.get("confidence_min") or 90),
            "limit": int(page_size),
        }
        resp = self.get("/api/v2/blacklist", params=params)
        data = _unwrap_abuseipdb(resp)
        if isinstance(data, list):
            return [dict(r, _ai_kind="reputation") for r in data if isinstance(r, dict)]
        return []

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Submit an abuse report (write operation; not part of the
        standard CRUD contract).
        """
        raise GNATClientError(
            "AbuseIPDB upsert_object is read-only via CRUD — use the "
            "submit_report() domain helper to file an abuse report."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """AbuseIPDB connector is read-only."""
        raise GNATClientError(
            "AbuseIPDB connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def check_ip(self, ip: str) -> dict[str, Any]:
        """Return AbuseIPDB reputation data for a single IP."""
        return self.get_object("indicator", ip)

    def check_block(self, cidr: str) -> list[dict[str, Any]]:
        """Return reputation data for every reported IP in a CIDR block."""
        return self.list_objects(
            "indicator", filters={"kind": "check_block", "cidr": cidr}
        )

    def get_blacklist(
        self, confidence_min: int = 90, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """Return the AbuseIPDB blacklist (high-confidence reported IPs)."""
        return self.list_objects(
            "indicator",
            filters={"confidence_min": confidence_min},
            page_size=limit,
        )

    def get_reports(self, ip: str) -> list[dict[str, Any]]:
        """Return historical abuse reports for an IP."""
        return self.list_objects(
            "indicator", filters={"kind": "reports", "ip": ip}
        )

    def submit_report(
        self,
        ip: str,
        categories: list[int],
        comment: str = "",
    ) -> dict[str, Any]:
        """
        Submit an abuse report for an IP.

        ``categories`` is a list of AbuseIPDB category ids
        (e.g. ``[18, 22]`` for "Brute-Force" + "SSH").
        """
        body: dict[str, Any] = {
            "ip": ip,
            "categories": ",".join(str(c) for c in categories),
        }
        if comment:
            body["comment"] = comment
        resp = self.post("/api/v2/report", data=body)
        return _unwrap_abuseipdb(resp) if isinstance(resp, dict) else {"raw": resp}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an AbuseIPDB record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("AbuseIPDB to_stix expects a dict input")

        kind = native.get("_ai_kind") or "reputation"
        ip = (
            native.get("ipAddress")
            or native.get("_ai_query")
            or native.get("ip", "")
        )
        pattern = make_indicator_pattern("ipv4-addr", ip) if ip else "[ipv4-addr:value = '']"
        stix_uuid = uuid.uuid5(_NAMESPACE_ABUSEIPDB, f"indicator|{ip}")
        confidence = native.get("abuseConfidenceScore") or native.get("confidence") or 0
        try:
            conf_num = int(confidence)
        except (TypeError, ValueError):
            conf_num = 0
        labels = ["malicious-activity"] if conf_num >= 50 else ["benign"]

        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": "2.1",
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"AbuseIPDB: {ip}",
            "description": native.get("description")
            or "AbuseIPDB community IP reputation",
            "labels": labels,
            "confidence": conf_num,
            "x_abuseipdb": {
                "kind": kind,
                "abuse_confidence_score": conf_num,
                "country_code": native.get("countryCode"),
                "isp": native.get("isp"),
                "domain": native.get("domain"),
                "total_reports": native.get("totalReports"),
                "num_distinct_users": native.get("numDistinctUsers"),
                "last_reported_at": native.get("lastReportedAt"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """AbuseIPDB connector is read-only via CRUD."""
        return {
            "note": (
                "AbuseIPDB connector is read-only via CRUD. Use check_ip, "
                "check_block, get_blacklist, get_reports, or submit_report "
                "to interact with the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _unwrap_abuseipdb(resp: Any) -> Any:
    """Strip the AbuseIPDB ``{"data": ...}`` envelope."""
    if isinstance(resp, dict) and "data" in resp:
        return resp["data"]
    return resp
