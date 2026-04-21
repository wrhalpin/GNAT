# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.any_run.client
==================================

ANY.RUN interactive sandbox connector.

Authentication
--------------
API key via ``Authorization: API-Key <key>`` header::

    [any_run]
    host    = https://api.any.run
    api_key = ar_...

Key endpoints
-------------
* ``GET  /v1/analysis``              — list the team's recent analyses
* ``GET  /v1/analysis/{task_id}``    — full analysis report
* ``POST /v1/analysis``              — submit a file / URL for analysis
* ``GET  /v1/environment``           — list available VM environments

STIX Type Mapping
-----------------
``observed-data`` (via :func:`sandbox_report_envelope`) wraps the
submitted sample + network IOCs + process tree.  ``malware`` emitted
for family attribution when the report carries a verdict tag.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    sandbox_report_envelope,
    utcnow,
)

_NAMESPACE_ANYRUN = uuid.UUID("a17e7e00-0001-4a1c-9b1e-a17e7e00c0de")


class AnyRunClient(BaseClient, ConnectorMixin):
    """
    HTTP client for ANY.RUN.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.any.run"``.
    api_key : str
        ANY.RUN API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "observed-data": "analysis",
        "malware": "analysis",
        "indicator": "analysis/ioc",
    }

    def __init__(
        self,
        host: str = "https://api.any.run",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize AnyRunClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set ``Authorization: API-Key`` from the configured key."""
        if not self.api_key:
            raise GNATClientError("ANY.RUN connector requires api_key in config.")
        self._auth_headers["Authorization"] = f"API-Key {self.api_key}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/environment`` as a cheap authenticated probe."""
        try:
            self.get("/v1/environment")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single analysis by ``task_id``."""
        if not object_id:
            raise GNATClientError("ANY.RUN get_object requires a non-empty id")
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(f"ANY.RUN get_object does not support stix_type={stix_type!r}")
        resp = self.get(f"/v1/analysis/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"ANY.RUN returned unexpected payload for {object_id!r}")
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        return dict(data, _ar_kind=stix_type, _ar_task_id=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List recent team analyses."""
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(f"ANY.RUN list_objects does not support stix_type={stix_type!r}")
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "limit": int(page_size),
            "skip": max(0, (int(page) - 1) * int(page_size)),
        }
        for key in ("team", "status", "tag", "verdict"):
            if filters.get(key):
                params[key] = filters[key]
        resp = self.get("/v1/analysis", params=params)
        items = _extract_any_run_list(resp)
        return [dict(r, _ar_kind=stix_type) for r in items]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """ANY.RUN submissions are exposed as domain helpers."""
        raise GNATClientError(
            "ANY.RUN connector is read-only via CRUD — use submit_file / "
            "submit_url domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ANY.RUN connector is read-only."""
        raise GNATClientError("ANY.RUN connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_environments(self) -> list[dict[str, Any]]:
        """List available VM environments (OS + bitness + build)."""
        resp = self.get("/v1/environment")
        return _extract_any_run_list(resp)

    def submit_file(self, filepath: str, **opts: Any) -> dict[str, Any]:
        """Submit a local file for analysis."""
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"file": (os.path.basename(filepath), fh.read())}
        form = {k: v for k, v in opts.items() if v is not None}
        return self.post("/v1/analysis", data=form, files=files)

    def submit_url(self, url: str, **opts: Any) -> dict[str, Any]:
        """Submit a URL for analysis."""
        body: dict[str, Any] = {"obj_type": "url", "obj_url": url}
        body.update({k: v for k, v in opts.items() if v is not None})
        return self.post("/v1/analysis", json=body)

    def get_analysis(self, task_id: str) -> dict[str, Any]:
        """Fetch the full analysis report for a task."""
        return self.get_object("observed-data", task_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an ANY.RUN record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("ANY.RUN to_stix expects a dict input")

        kind = native.get("_ar_kind") or "observed-data"

        if kind == "indicator":
            ioc_type = (native.get("type") or "").lower()
            value = native.get("value") or native.get("ioc") or ""
            if ioc_type in ("ip", "ipv4"):
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif ioc_type == "domain":
                pattern = make_indicator_pattern("domain-name", value)
            elif ioc_type == "url":
                pattern = make_indicator_pattern("url", value)
            elif ioc_type in ("sha256", "sha1", "md5"):
                pattern = make_indicator_pattern(f"file:{ioc_type}", value)
            else:
                pattern = f"[x-anyrun:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_ANYRUN, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"ANY.RUN: {value}",
                "description": "ANY.RUN extracted IOC",
                "labels": ["malicious-activity"],
                "x_any_run": {"task_id": native.get("_ar_task_id"), "raw": native},
            }

        if kind == "malware":
            verdict = native.get("verdict") or native.get("threatLevel") or "unknown"
            family = (
                native.get("threatName") or native.get("mainObject", {}).get("name") or "unknown"
            )
            stix_uuid = uuid.uuid5(_NAMESPACE_ANYRUN, f"malware|{family}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": f"ANY.RUN: {verdict}",
                "malware_types": ["unknown"],
                "x_any_run": {"verdict": verdict, "raw": native},
            }

        # Default: observed-data envelope
        main = native.get("mainObject") or {}
        network = native.get("network") or {}
        ips = _extract_values(network.get("ipAddresses") or network.get("ips"))
        domains = _extract_values(network.get("domainNames") or network.get("domains"))
        urls = _extract_values(network.get("urls"))
        processes = [
            p.get("commandLine") or p.get("name")
            for p in (native.get("processes") or [])
            if isinstance(p, dict)
        ]

        return sandbox_report_envelope(
            source_name="any_run",
            analysis_id=str(native.get("uuid") or native.get("_ar_task_id", "")),
            submitted_sha256=main.get("hashes", {}).get("sha256", ""),
            submitted_filename=main.get("name", ""),
            submitted_url=main.get("url", ""),
            processes=[p for p in processes if p],
            contacted_ips=ips,
            contacted_domains=domains,
            contacted_urls=urls,
            first_observed=native.get("creation") or native.get("created", ""),
            last_observed=native.get("finish") or native.get("updated", ""),
            verdict=native.get("verdict") or native.get("threatLevel", ""),
            score=native.get("score"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """ANY.RUN CRUD is read-only (submissions are domain helpers)."""
        return {
            "note": (
                "ANY.RUN connector is read-only via CRUD. Use submit_file, "
                "submit_url, get_analysis, or list_environments."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_any_run_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of an ANY.RUN response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data") if isinstance(resp.get("data"), (list, dict)) else resp
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("tasks", "analyses", "items", "results"):
            val = data.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
    return []


def _extract_values(container: Any) -> list[str]:
    """Normalize a mixed list/dict into a flat list of string values."""
    if container is None:
        return []
    if isinstance(container, list):
        out: list[str] = []
        for item in container:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                val = item.get("value") or item.get("ip") or item.get("domain") or item.get("url")
                if isinstance(val, str):
                    out.append(val)
        return out
    if isinstance(container, str):
        return [container]
    return []
