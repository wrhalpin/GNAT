# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.intezer.client
==================================

Intezer Analyze connector — binary-DNA / code-reuse malware family
attribution.

Authentication
--------------
API key exchanged for a short-lived JWT Bearer token::

    [intezer]
    host    = https://analyze.intezer.com
    api_key = intezer_...

``authenticate()`` POSTs to ``/api/v2-0/get-access-token`` with
``{"api_key": api_key}`` and caches the returned JWT as
``Authorization: Bearer <jwt>``.

Key endpoints
-------------
* ``POST /api/v2-0/get-access-token`` — exchange api_key for JWT
* ``POST /api/v2-0/analyze``           — submit a file
* ``POST /api/v2-0/analyze-by-hash``   — submit a SHA-256
* ``GET  /api/v2-0/analyses/{id}``     — analysis result
* ``GET  /api/v2-0/analyses/{id}/sub-analyses`` — sub-analyses
* ``GET  /api/v2-0/analyses/{id}/iocs``         — extracted IOCs
* ``GET  /api/v2-0/families/{family_id}``       — family metadata
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

_NAMESPACE_INTEZER = uuid.UUID("0c7e9e4e-0001-4a1e-9b1e-0c7e9e4ec0fe")


class IntezerClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Intezer Analyze.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://analyze.intezer.com"``.
    api_key : str
        Intezer API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2-0"
    API_PREFIX: str = "/api/v2-0"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "observed-data": "analyses",
        "malware": "families",
        "indicator": "analyses/{id}/iocs",
    }

    def __init__(
        self,
        host: str = "https://analyze.intezer.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize IntezerClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange the API key for a JWT Bearer token."""
        if not self.api_key:
            raise GNATClientError(
                "Intezer connector requires api_key in config."
            )
        resp = self.post(
            "/api/v2-0/get-access-token", json={"api_key": self.api_key}
        )
        jwt = ""
        if isinstance(resp, dict):
            jwt = resp.get("result") or resp.get("access_token") or ""
        if not jwt:
            raise GNATClientError(
                "Intezer authentication failed — no result token in response"
            )
        self._auth_headers["Authorization"] = f"Bearer {jwt}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/api/v2-0/is-available`` as an authenticated probe."""
        try:
            self.get("/api/v2-0/is-available")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Intezer resource.

        ``stix_type``:

        * ``"observed-data"`` — analysis report via ``/analyses/{id}``
        * ``"malware"`` — family metadata via ``/families/{id}``
        """
        if not object_id:
            raise GNATClientError("Intezer get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v2-0/analyses/{object_id}")
            kind = "analysis"
        elif stix_type == "malware":
            resp = self.get(f"/api/v2-0/families/{object_id}")
            kind = "family"
        else:
            raise GNATClientError(
                f"Intezer get_object does not support stix_type={stix_type!r}"
            )
        data = _unwrap_intezer(resp)
        if not isinstance(data, dict):
            raise GNATClientError(
                f"Intezer returned unexpected payload for {object_id!r}"
            )
        return dict(data, _iz_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List analyses, sub-analyses, or IOCs for an analysis."""
        filters = dict(filters or {})
        analysis_id = filters.get("analysis_id", "")

        if stix_type == "observed-data":
            if analysis_id:
                resp = self.get(
                    f"/api/v2-0/analyses/{analysis_id}/sub-analyses"
                )
                kind = "sub_analysis"
            else:
                raise GNATClientError(
                    "Intezer list_objects(observed-data) requires 'analysis_id' filter"
                )
        elif stix_type == "indicator":
            if not analysis_id:
                raise GNATClientError(
                    "Intezer list_objects(indicator) requires 'analysis_id' filter"
                )
            resp = self.get(f"/api/v2-0/analyses/{analysis_id}/iocs")
            kind = "ioc"
        else:
            raise GNATClientError(
                f"Intezer list_objects does not support stix_type={stix_type!r}"
            )
        data = _unwrap_intezer(resp)
        if isinstance(data, list):
            return [dict(r, _iz_kind=kind) for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("sub_analyses", "iocs", "files", "network"):
                val = data.get(key)
                if isinstance(val, list):
                    return [dict(r, _iz_kind=kind) for r in val if isinstance(r, dict)]
        return []

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Sandbox submissions are domain helpers, not upsert."""
        raise GNATClientError(
            "Intezer connector is read-only via CRUD — use analyze_file / "
            "analyze_hash domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Intezer connector is read-only."""
        raise GNATClientError(
            "Intezer connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def analyze_file(self, filepath: str) -> dict[str, Any]:
        """Submit a local file for analysis."""
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"analyze_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"file": (os.path.basename(filepath), fh.read())}
        return self.post("/api/v2-0/analyze", files=files)

    def analyze_hash(self, sha256: str) -> dict[str, Any]:
        """Submit a SHA-256 hash for analysis (no upload)."""
        return self.post(
            "/api/v2-0/analyze-by-hash", json={"hash": sha256}
        )

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Fetch an analysis result by id."""
        return self.get_object("observed-data", analysis_id)

    def get_sub_analyses(self, analysis_id: str) -> list[dict[str, Any]]:
        """Return the sub-analysis breakdown for an analysis."""
        return self.list_objects(
            "observed-data", filters={"analysis_id": analysis_id}
        )

    def get_iocs(self, analysis_id: str) -> list[dict[str, Any]]:
        """Return extracted IOCs for an analysis."""
        return self.list_objects(
            "indicator", filters={"analysis_id": analysis_id}
        )

    def get_family(self, family_id: str) -> dict[str, Any]:
        """Fetch metadata for a malware family by id."""
        return self.get_object("malware", family_id)

    def get_file_analysis(self, sha256: str) -> dict[str, Any]:
        """Fetch an existing analysis for a given SHA-256."""
        resp = self.get(f"/api/v2-0/files/{sha256}")
        data = _unwrap_intezer(resp)
        return dict(data, _iz_kind="analysis") if isinstance(data, dict) else {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an Intezer record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Intezer to_stix expects a dict input")

        kind = native.get("_iz_kind") or "analysis"

        if kind == "family":
            family = (
                native.get("family_name")
                or native.get("name")
                or native.get("family_id", "unknown")
            )
            stix_uuid = uuid.uuid5(_NAMESPACE_INTEZER, f"malware|{family}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": native.get("description")
                or f"Intezer family {family}",
                "malware_types": _intezer_malware_types(native),
                "x_intezer": {
                    "family_id": native.get("family_id"),
                    "family_type": native.get("family_type"),
                    "code_reuse_pct": native.get("reused_gene_count_ratio"),
                    "raw": native,
                },
            }

        if kind == "ioc":
            ioc_type = (native.get("type") or "").lower()
            value = native.get("ioc") or native.get("value") or ""
            if ioc_type in ("ip", "ipv4"):
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif ioc_type == "domain":
                pattern = make_indicator_pattern("domain-name", value)
            elif ioc_type == "url":
                pattern = make_indicator_pattern("url", value)
            elif ioc_type in ("sha256", "sha1", "md5"):
                pattern = make_indicator_pattern(f"file:{ioc_type}", value)
            else:
                pattern = f"[x-intezer:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_INTEZER, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"Intezer: {value}",
                "description": "Intezer-extracted IOC",
                "labels": ["malicious-activity"],
                "x_intezer": {"raw": native},
            }

        # Analysis → observed-data envelope
        return sandbox_report_envelope(
            source_name="intezer",
            analysis_id=str(
                native.get("analysis_id") or native.get("sub_analysis_id", "")
            ),
            submitted_sha256=native.get("sha256") or "",
            submitted_filename=native.get("file_name")
            or native.get("filename", ""),
            processes=[],
            contacted_ips=[],
            contacted_domains=[],
            contacted_urls=[],
            first_observed=native.get("analysis_time") or "",
            last_observed=native.get("analysis_time") or "",
            verdict=native.get("verdict") or native.get("sub_verdict", ""),
            score=native.get("family_confidence"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Intezer CRUD is read-only."""
        return {
            "note": (
                "Intezer connector is read-only via CRUD. Use analyze_file, "
                "analyze_hash, get_analysis, get_sub_analyses, get_iocs, "
                "get_family, or get_file_analysis to interact with Intezer."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _unwrap_intezer(resp: Any) -> Any:
    """Strip Intezer's ``{"result": ..., "status": "..."}`` envelope."""
    if isinstance(resp, dict) and "result" in resp:
        return resp["result"]
    return resp


def _intezer_malware_types(native: dict[str, Any]) -> list[str]:
    """Map Intezer family_type to STIX malware_types."""
    fam_type = (native.get("family_type") or "").lower()
    if "ransom" in fam_type:
        return ["ransomware"]
    if "trojan" in fam_type:
        return ["trojan"]
    if "backdoor" in fam_type:
        return ["backdoor"]
    if "stealer" in fam_type:
        return ["trojan"]
    return ["unknown"]
