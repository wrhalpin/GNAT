# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.alienvault.client
======================================

AlienVault OTX (Open Threat Exchange) connector.

Authentication
--------------
API key via ``X-OTX-API-KEY`` header::

    [alienvault_otx]
    host    = https://otx.alienvault.com
    api_key = <otx-api-key>

OTX keys are free — register at https://otx.alienvault.com.

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | OTX Resource                     |
+====================+==================================+
| indicator          | pulse indicators (IOCs)          |
+--------------------+----------------------------------+
| report             | pulses                           |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``/api/v1/pulses/subscribed``  — subscribed pulse feed
* ``/api/v1/pulses/{id}``        — single pulse detail
* ``/api/v1/indicators/export``  — flat indicator export by type
* ``/api/v1/user/me``            — profile / health check

Notes
-----
* OTX is **read-only** — pulses and indicators are fetched, not written.
* Pagination uses ``page`` + ``limit`` query parameters.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# OTX indicator type → STIX SCO type
_OTX_TO_STIX: dict[str, str] = {
    "IPv4": "ipv4-addr",
    "IPv6": "ipv6-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "URL": "url",
    "URI": "url",
    "email": "email-addr",
    "FileHash-MD5": "file",
    "FileHash-SHA1": "file",
    "FileHash-SHA256": "file",
    "FileHash-SHA512": "file",
    "CVE": "vulnerability",
}

# OTX hash type → STIX hash algorithm name
_HASH_ALGO: dict[str, str] = {
    "FileHash-MD5": "MD5",
    "FileHash-SHA1": "SHA-1",
    "FileHash-SHA256": "SHA-256",
    "FileHash-SHA512": "SHA-512",
}

# STIX pattern templates
_PATTERNS: dict[str, str] = {
    "ipv4-addr": "[ipv4-addr:value = '{v}']",
    "ipv6-addr": "[ipv6-addr:value = '{v}']",
    "domain-name": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email-addr": "[email-addr:value = '{v}']",
}


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AlienVaultClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the AlienVault OTX REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://otx.alienvault.com"``.
    api_key : str
        OTX API key.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "indicators",
        "report": "pulses",
    }

    def __init__(self, host: str, api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the OTX API key header."""
        self._auth_headers["X-OTX-API-KEY"] = self._api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the OTX user profile endpoint."""
        self.get("/api/v1/user/me")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single OTX pulse by id.

        Parameters
        ----------
        object_id : str
            OTX pulse id.
        """
        return self.get(f"/api/v1/pulses/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Fetch subscribed pulses or exported indicators.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:

            * ``modified_since`` — ISO 8601 timestamp filter
            * ``indicator_type`` — OTX type (used when stix_type == "indicator")
        """
        filters = dict(filters or {})
        if stix_type == "indicator":
            ind_type = filters.pop("indicator_type", "IPv4")
            modified = filters.pop("modified_since", None)
            return self.get_indicators(
                indicator_type=ind_type,
                modified_since=modified,
                limit=page_size,
            )
        # Default: fetch subscribed pulses
        modified = filters.pop("modified_since", None)
        return self.get_subscribed_pulses(
            modified_since=modified,
            limit=page_size,
            page=page,
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("AlienVault OTX is read-only — object creation is not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("AlienVault OTX is read-only — object deletion is not supported.")

    # ── Domain-specific operations ────────────────────────────────────────

    def get_subscribed_pulses(
        self,
        modified_since: str | None = None,
        limit: int = 50,
        page: int = 1,
    ) -> list[dict[str, Any]]:
        """
        Fetch pulses from the subscription feed.

        Parameters
        ----------
        modified_since : str, optional
            ISO 8601 timestamp — only pulses modified after this date.
        limit : int
            Page size (max results).
        page : int
            Page number (1-indexed).

        Returns
        -------
        list of dict
            Pulse objects.
        """
        params: dict[str, Any] = {"limit": limit, "page": page}
        if modified_since:
            params["modified_since"] = modified_since
        resp = self.get("/api/v1/pulses/subscribed", params=params)
        return resp.get("results", []) if isinstance(resp, dict) else []

    def get_pulse(self, pulse_id: str) -> dict[str, Any]:
        """Fetch a single pulse by id."""
        return self.get(f"/api/v1/pulses/{pulse_id}")

    def get_pulse_indicators(self, pulse_id: str) -> list[dict[str, Any]]:
        """
        Fetch indicators for a specific pulse.

        Returns
        -------
        list of dict
        """
        resp = self.get(f"/api/v1/pulses/{pulse_id}/indicators")
        return resp.get("results", []) if isinstance(resp, dict) else []

    def get_indicators(
        self,
        indicator_type: str = "IPv4",
        modified_since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Fetch a flat indicator export by type.

        Parameters
        ----------
        indicator_type : str
            OTX type: ``"IPv4"``, ``"domain"``, ``"URL"``,
            ``"FileHash-SHA256"``, etc.
        modified_since : str, optional
            ISO 8601 filter.
        limit : int
            Max results.

        Returns
        -------
        list of dict
        """
        params: dict[str, Any] = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since
        resp = self.get(
            "/api/v1/indicators/export",
            params={"type": indicator_type, **params},
        )
        return resp.get("results", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate an OTX pulse or indicator to a STIX 2.1 object.

        Dispatches on presence of ``indicators`` (pulse) vs. IOC value.

        Parameters
        ----------
        native : dict
            Raw OTX pulse dict or normalised indicator dict.

        Returns
        -------
        dict
            STIX report (pulse) or STIX indicator SDO.
        """
        # Pulse → STIX report
        if "indicators" in native or "name" in native and "id" in native:
            return self._pulse_to_stix(native)
        # Single indicator → STIX indicator
        return self._indicator_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """OTX is read-only — from_stix returns an informational dict."""
        return {
            "note": "AlienVault OTX is read-only. No write API available.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _pulse_to_stix(self, pulse: dict[str, Any]) -> dict[str, Any]:
        """Convert an OTX pulse to a STIX report SDO."""
        now = _now_ts()
        pulse_id = pulse.get("id", "")
        report_id = f"report--{_det_uuid('report', pulse_id)}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": pulse.get("created") or now,
            "modified": pulse.get("modified") or now,
            "name": pulse.get("name", "OTX Pulse"),
            "description": pulse.get("description", ""),
            "report_types": ["threat-report"],
            "published": pulse.get("created") or now,
            "labels": pulse.get("tags", []),
            "x_otx_pulse": {
                "pulse_id": pulse_id,
                "author": pulse.get("author_name"),
                "tlp": pulse.get("tlp"),
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "targeted_countries": pulse.get("targeted_countries", []),
            },
        }

    def _indicator_to_stix(self, ind: dict[str, Any]) -> dict[str, Any]:
        """Convert an OTX indicator to a STIX indicator SDO."""
        now = _now_ts()
        otx_type = ind.get("type", "")
        value = ind.get("indicator", ind.get("value", ""))
        stix_type = _OTX_TO_STIX.get(otx_type, "")

        if stix_type == "file":
            algo = _HASH_ALGO.get(otx_type, "SHA-256")
            pattern = f"[file:hashes.'{algo}' = '{value}']"
        elif stix_type == "vulnerability":
            pattern = f"[vulnerability:name = '{value}']"
        else:
            tmpl = _PATTERNS.get(stix_type, "[unknown:value = '{v}']")
            pattern = tmpl.format(v=value.replace("'", "\\'"))

        ind_id = f"indicator--{_det_uuid('indicator', value or now)}"
        return {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": ind.get("created") or now,
            "modified": now,
            "name": value,
            "description": ind.get("description", ind.get("title", "")),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ind.get("created") or now,
            "indicator_types": ["malicious-activity"],
            "x_otx_type": otx_type,
        }
