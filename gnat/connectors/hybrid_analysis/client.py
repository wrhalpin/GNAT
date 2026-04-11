# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hybrid_analysis.client
==========================================

Hybrid Analysis (CrowdStrike Falcon Sandbox) connector.

Authentication
--------------
API key via ``api-key`` header with a mandatory ``User-Agent``::

    [hybrid_analysis]
    host    = https://www.hybrid-analysis.com
    api_key = ha_...

Key endpoints
-------------
* ``POST /api/v2/submit/file``      — submit a file
* ``POST /api/v2/submit/url``       — submit a URL
* ``GET  /api/v2/report/{job_id}/summary``  — condensed report
* ``GET  /api/v2/overview/{sha256}``        — hash lookup
* ``POST /api/v2/search/hash``              — search by hash
* ``POST /api/v2/search/terms``             — full-text search
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    sandbox_report_envelope,
    utcnow,
)

_NAMESPACE_HYBRID = uuid.UUID("7be1d0a4-0001-4a7b-9c0e-7be1d0a4c0fe")


class HybridAnalysisClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Hybrid Analysis / Falcon Sandbox.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://www.hybrid-analysis.com"``.
    api_key : str
        Hybrid Analysis API key.
    user_agent : str, optional
        Required ``User-Agent`` header.  Defaults to ``"Falcon Sandbox"``.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api/v2"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "observed-data": "report",
        "malware": "overview",
        "indicator": "search/hash",
    }

    def __init__(
        self,
        host: str = "https://www.hybrid-analysis.com",
        api_key: str = "",
        user_agent: str = "Falcon Sandbox",
        **kwargs: Any,
    ) -> None:
        """Initialize HybridAnalysisClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        self.user_agent = user_agent or "Falcon Sandbox"

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set api-key + mandatory User-Agent headers."""
        if not self.api_key:
            raise GNATClientError(
                "Hybrid Analysis connector requires api_key in config."
            )
        self._auth_headers["api-key"] = self.api_key
        self._auth_headers["User-Agent"] = self.user_agent
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/api/v2/system/heartbeat`` as a liveness probe."""
        try:
            self.get("/api/v2/system/heartbeat")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single record.

        ``stix_type`` values:

        * ``"observed-data"`` — report summary by ``job_id``
        * ``"malware"`` — overview by SHA-256
        """
        if not object_id:
            raise GNATClientError(
                "Hybrid Analysis get_object requires a non-empty id"
            )
        if stix_type == "observed-data":
            resp = self.get(f"/api/v2/report/{object_id}/summary")
        elif stix_type == "malware":
            resp = self.get(f"/api/v2/overview/{object_id}")
        else:
            raise GNATClientError(
                f"Hybrid Analysis get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Hybrid Analysis returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _ha_kind=stix_type, _ha_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Hybrid Analysis.

        ``filters`` keys:

        * ``hash`` — SHA-256 / SHA-1 / MD5 lookup
        * ``query`` — free-text search body
        """
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(
                f"Hybrid Analysis list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        if filters.get("hash"):
            resp = self.post("/api/v2/search/hash", data={"hash": filters["hash"]})
        else:
            body = filters.get("query") or filters
            resp = self.post("/api/v2/search/terms", data=body)
        items = _extract_hybrid_list(resp)
        start = max(0, (int(page) - 1) * int(page_size))
        return [
            dict(r, _ha_kind=stix_type) for r in items[start : start + int(page_size)]
        ]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Sandbox submissions are domain helpers, not upsert."""
        raise GNATClientError(
            "Hybrid Analysis connector is read-only via CRUD — use submit_file / "
            "submit_url domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Hybrid Analysis connector is read-only."""
        raise GNATClientError(
            "Hybrid Analysis connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def submit_file(
        self, filepath: str, environment_id: int = 100
    ) -> dict[str, Any]:
        """Submit a local file.  ``environment_id`` selects the VM (default Windows 10 64-bit)."""
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"file": (os.path.basename(filepath), fh.read())}
        return self.post(
            "/api/v2/submit/file",
            data={"environment_id": environment_id},
            files=files,
        )

    def submit_url(self, url: str, environment_id: int = 100) -> dict[str, Any]:
        """Submit a URL."""
        return self.post(
            "/api/v2/submit/url",
            data={"url": url, "environment_id": environment_id},
        )

    def get_report_summary(self, job_id: str) -> dict[str, Any]:
        """Fetch the condensed report summary."""
        return self.get_object("observed-data", job_id)

    def hash_lookup(self, sha256: str) -> dict[str, Any]:
        """Fetch a sample overview by SHA-256."""
        return self.get_object("malware", sha256)

    def search_hash(self, hash_value: str) -> list[dict[str, Any]]:
        """Search for a hash across all analyses."""
        return self.list_objects("observed-data", filters={"hash": hash_value})

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Hybrid Analysis record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Hybrid Analysis to_stix expects a dict input")

        kind = native.get("_ha_kind") or "observed-data"

        if kind == "malware":
            family = (
                native.get("threat_level_human")
                or native.get("vx_family")
                or native.get("verdict", "unknown")
            )
            stix_uuid = uuid.uuid5(_NAMESPACE_HYBRID, f"malware|{family}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": f"Hybrid Analysis: {native.get('verdict', 'unknown')}",
                "malware_types": _ha_malware_types(native),
                "x_hybrid_analysis": {"raw": native},
            }

        if kind == "indicator":
            ioc_type = (native.get("type") or "").lower()
            value = native.get("value") or native.get("ioc") or ""
            if ioc_type in ("ip", "ipv4"):
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif ioc_type == "domain":
                pattern = make_indicator_pattern("domain-name", value)
            elif ioc_type == "url":
                pattern = make_indicator_pattern("url", value)
            else:
                pattern = f"[x-hybridanalysis:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_HYBRID, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"Hybrid Analysis: {value}",
                "description": "Hybrid Analysis extracted IOC",
                "labels": ["malicious-activity"],
                "x_hybrid_analysis": {"raw": native},
            }

        # Default — observed-data envelope
        hosts = native.get("hosts") or []
        domains = native.get("domains") or []
        urls = native.get("extracted_urls") or []
        processes = [
            p.get("name") or p.get("normalizedPath")
            for p in (native.get("processes") or [])
            if isinstance(p, dict)
        ]
        return sandbox_report_envelope(
            source_name="hybrid_analysis",
            analysis_id=str(native.get("job_id") or native.get("sha256", "")),
            submitted_sha256=native.get("sha256") or "",
            submitted_filename=native.get("submit_name")
            or native.get("file_name", ""),
            processes=[p for p in processes if p],
            contacted_ips=[h for h in hosts if isinstance(h, str)],
            contacted_domains=[d for d in domains if isinstance(d, str)],
            contacted_urls=[u for u in urls if isinstance(u, str)],
            first_observed=native.get("analysis_start_time") or "",
            last_observed=native.get("last_multi_scan") or "",
            verdict=native.get("verdict") or native.get("threat_level_human", ""),
            score=native.get("threat_score"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Hybrid Analysis CRUD is read-only."""
        return {
            "note": (
                "Hybrid Analysis connector is read-only via CRUD. Use "
                "submit_file, submit_url, get_report_summary, hash_lookup, "
                "or search_hash to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_hybrid_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Hybrid Analysis response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("result", "results", "data", "search_results", "hits"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _ha_malware_types(native: dict[str, Any]) -> list[str]:
    """Map Hybrid Analysis classification to STIX malware_types."""
    level = (native.get("threat_level_human") or "").lower()
    if "ransom" in level:
        return ["ransomware"]
    if "trojan" in level:
        return ["trojan"]
    if "backdoor" in level:
        return ["backdoor"]
    return ["unknown"]
