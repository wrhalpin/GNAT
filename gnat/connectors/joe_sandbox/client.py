# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.joe_sandbox.client
======================================

Joe Sandbox Cloud connector — dynamic malware analysis.

Authentication
--------------
Joe Sandbox sends the API key as a POST form field on every request
rather than an HTTP header::

    [joe_sandbox]
    host    = https://jbxcloud.joesecurity.org
    api_key = jbx_...

Key endpoints
-------------
* ``POST /api/v2/submission/new`` — submit a file or URL
* ``POST /api/v2/submission/info`` — status of a submission
* ``POST /api/v2/analysis/info`` — metadata for a completed analysis
* ``POST /api/v2/analysis/search`` — search prior analyses
* ``POST /api/v2/analysis/download`` — fetch report / PCAP / HTML / JSON
* ``POST /api/v2/analysis/ioc`` — extracted IOCs

STIX Type Mapping
-----------------
``observed-data`` (via :func:`sandbox_report_envelope`) wraps the
submitted sample + behavioral artifacts; ``malware`` is emitted for
family attribution.  ``indicator`` may be emitted for each extracted
C2 / dropper IOC via :meth:`JoeSandboxClient.iocs_to_indicators`.
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

_NAMESPACE_JOESANDBOX = uuid.UUID("10e5a4b0-0001-4d0a-9c1e-10e5a4b0c0fe")


class JoeSandboxClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Joe Sandbox Cloud.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://jbxcloud.joesecurity.org"``.
    api_key : str
        Joe Sandbox API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/api/v2"
    COST_UNIT: int = 5  # sandbox submissions are expensive

    stix_type_map: dict[str, str] = {
        "observed-data": "analysis/info",
        "malware": "analysis/info",
        "indicator": "analysis/ioc",
    }

    def __init__(
        self,
        host: str = "https://jbxcloud.joesecurity.org",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize JoeSandboxClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Joe Sandbox has no header auth; just stamp the accept type."""
        if not self.api_key:
            raise GNATClientError(
                "Joe Sandbox connector requires api_key in config."
            )
        self._auth_headers["Accept"] = "application/json"

    def _authed_form(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a POST form dict with ``apikey`` injected."""
        form: dict[str, Any] = {"apikey": self.api_key, "accept-tac": "1"}
        if extra:
            form.update(extra)
        return form

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/api/v2/server/online`` as an authenticated liveness probe."""
        try:
            self.post("/api/v2/server/online", data=self._authed_form())
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single analysis record by ``webid``."""
        if not object_id:
            raise GNATClientError("Joe Sandbox get_object requires a non-empty id")
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(
                f"Joe Sandbox get_object does not support stix_type={stix_type!r}"
            )
        resp = self.post(
            "/api/v2/analysis/info", data=self._authed_form({"webid": object_id})
        )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Joe Sandbox returned unexpected payload for {object_id!r}"
            )
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        return dict(data, _jb_kind=stix_type, _jb_webid=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search prior analyses.

        ``filters`` keys: ``q`` (free-text query), ``filename``, ``sha256``,
        ``detection`` (``clean``/``suspicious``/``malicious``/``unknown``).
        """
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(
                f"Joe Sandbox list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        form_extra: dict[str, Any] = {}
        for key in ("q", "filename", "sha256", "detection"):
            if filters.get(key):
                form_extra[key] = filters[key]
        resp = self.post(
            "/api/v2/analysis/search", data=self._authed_form(form_extra)
        )
        items = _extract_joe_list(resp)
        start = max(0, (int(page) - 1) * int(page_size))
        return [
            dict(r, _jb_kind=stix_type) for r in items[start : start + int(page_size)]
        ]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Sandbox submissions are exposed as domain helpers, not upsert."""
        raise GNATClientError(
            "Joe Sandbox connector is read-only via CRUD — use submit_file / "
            "submit_url domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Joe Sandbox connector is read-only."""
        raise GNATClientError(
            "Joe Sandbox connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def submit_file(
        self, filepath: str, comments: str = ""
    ) -> dict[str, Any]:
        """Submit a local file for analysis."""
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"sample": (os.path.basename(filepath), fh.read())}
        form = self._authed_form({"comments": comments} if comments else None)
        return self.post("/api/v2/submission/new", data=form, files=files)

    def submit_url(self, url: str, comments: str = "") -> dict[str, Any]:
        """Submit a URL for analysis."""
        form = self._authed_form({"url": url})
        if comments:
            form["comments"] = comments
        return self.post("/api/v2/submission/new", data=form)

    def get_submission(self, submission_id: str) -> dict[str, Any]:
        """Return the status of an active submission."""
        return self.post(
            "/api/v2/submission/info",
            data=self._authed_form({"submission_id": submission_id}),
        )

    def get_analysis(self, webid: str) -> dict[str, Any]:
        """Fetch full analysis metadata for a completed webid."""
        return self.get_object("observed-data", webid)

    def get_iocs(self, webid: str) -> list[dict[str, Any]]:
        """Return IOCs extracted from a completed analysis."""
        resp = self.post(
            "/api/v2/analysis/ioc", data=self._authed_form({"webid": webid})
        )
        items = _extract_joe_list(resp)
        return [dict(r, _jb_kind="indicator", _jb_webid=webid) for r in items]

    def iocs_to_indicators(self, webid: str) -> list[dict[str, Any]]:
        """Return STIX indicators for all IOCs on a given analysis."""
        return [self.to_stix(ioc) for ioc in self.get_iocs(webid)]

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Joe Sandbox record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Joe Sandbox to_stix expects a dict input")

        kind = native.get("_jb_kind") or "observed-data"

        if kind == "indicator":
            ioc_type = (native.get("type") or native.get("ioc_type") or "").lower()
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
                pattern = f"[x-joesandbox:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_JOESANDBOX, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": utcnow(),
                "name": f"Joe Sandbox: {value}",
                "description": native.get("description") or "Joe Sandbox extracted IOC",
                "labels": ["malicious-activity"],
                "x_joe_sandbox": {
                    "webid": native.get("_jb_webid"),
                    "ioc_type": ioc_type,
                    "raw": native,
                },
            }

        if kind == "malware":
            detection = native.get("detection") or native.get("verdict") or "unknown"
            family = (
                native.get("malwarename")
                or native.get("family")
                or native.get("threatname")
                or "unknown"
            )
            stix_uuid = uuid.uuid5(_NAMESPACE_JOESANDBOX, f"malware|{family}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": family,
                "is_family": True,
                "description": f"Joe Sandbox: {detection} ({family})",
                "malware_types": _joe_malware_types(native),
                "x_joe_sandbox": {
                    "detection": detection,
                    "score": native.get("score"),
                    "raw": native,
                },
            }

        # Default: observed-data envelope
        network = native.get("network") or {}
        ips = _as_list(network.get("ips"))
        domains = _as_list(network.get("domains"))
        urls = _as_list(network.get("urls"))
        processes = [
            p.get("name") if isinstance(p, dict) else str(p)
            for p in (native.get("processes") or [])
        ]

        return sandbox_report_envelope(
            source_name="joe_sandbox",
            analysis_id=str(native.get("webid") or native.get("_jb_webid", "")),
            submitted_sha256=native.get("sha256") or "",
            submitted_filename=native.get("filename") or "",
            processes=[p for p in processes if p],
            contacted_ips=ips,
            contacted_domains=domains,
            contacted_urls=urls,
            first_observed=native.get("time") or "",
            last_observed=native.get("lastmodified") or "",
            verdict=native.get("detection") or native.get("verdict", ""),
            score=native.get("score"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Joe Sandbox CRUD is read-only (submissions are domain helpers)."""
        return {
            "note": (
                "Joe Sandbox connector is read-only via CRUD. Use submit_file, "
                "submit_url, get_submission, get_analysis, or get_iocs to "
                "interact with the platform."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_joe_list(resp: Any) -> list[dict[str, Any]]:
    """Pull the list of records out of a Joe Sandbox response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data") if isinstance(resp.get("data"), (list, dict)) else resp
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("analyses", "iocs", "results", "items"):
            val = data.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
    return []


def _as_list(value: Any) -> list[Any]:
    """Normalize scalar / list / None into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return [value]


def _joe_malware_types(native: dict[str, Any]) -> list[str]:
    """Map Joe Sandbox tags to STIX malware_types."""
    tags = [str(t).lower() for t in (native.get("tags") or [])]
    out: list[str] = []
    for tag in tags:
        if "trojan" in tag:
            out.append("trojan")
        elif "ransom" in tag:
            out.append("ransomware")
        elif "backdoor" in tag:
            out.append("backdoor")
        elif "worm" in tag:
            out.append("worm")
        elif "rootkit" in tag:
            out.append("rootkit")
    return out or ["unknown"]
