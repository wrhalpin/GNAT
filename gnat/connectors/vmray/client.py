# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.vmray.client
================================

VMRay connector — hypervisor-level dynamic malware analysis.

Authentication
--------------
API key via ``Authorization: api_key <key>`` header::

    [vmray]
    host    = https://cloud.vmray.com
    api_key = vmray_...

Key endpoints
-------------
* ``POST /rest/sample/submit``              — submit a file or URL
* ``GET  /rest/sample/{sample_id}``         — sample metadata
* ``GET  /rest/submission/{submission_id}`` — submission state
* ``GET  /rest/analysis``                   — list analyses
* ``GET  /rest/analysis/{analysis_id}``     — analysis metadata
* ``GET  /rest/analysis/{analysis_id}/archive/logs/summary_v2.json``
  — full behavioral summary (v2 summary format)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import sandbox_report_envelope, utcnow

_NAMESPACE_VMRAY = uuid.UUID("00403a11-0001-4a1c-9b1d-00403a11c0fe")


class VMRayClient(BaseClient, ConnectorMixin):
    """
    HTTP client for VMRay.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://cloud.vmray.com"``.
    api_key : str
        VMRay API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/rest"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "observed-data": "analysis",
        "malware": "sample",
    }

    def __init__(
        self,
        host: str = "https://cloud.vmray.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize VMRayClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: api_key header from the configured key."""
        if not self.api_key:
            raise GNATClientError(
                "VMRay connector requires api_key in config."
            )
        self._auth_headers["Authorization"] = f"api_key {self.api_key}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/rest/system_info`` as a cheap authenticated probe."""
        try:
            self.get("/rest/system_info")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single VMRay record.

        ``stix_type``:

        * ``"observed-data"`` — analysis metadata via
          ``/rest/analysis/{id}``
        * ``"malware"`` — sample metadata via ``/rest/sample/{id}``
        """
        if not object_id:
            raise GNATClientError("VMRay get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/rest/analysis/{object_id}")
            kind = "analysis"
        elif stix_type == "malware":
            resp = self.get(f"/rest/sample/{object_id}")
            kind = "sample"
        else:
            raise GNATClientError(
                f"VMRay get_object does not support stix_type={stix_type!r}"
            )
        data = _unwrap_vmray(resp)
        if not isinstance(data, dict):
            raise GNATClientError(
                f"VMRay returned unexpected payload for {object_id!r}"
            )
        return dict(data, _vmr_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List recent analyses or samples."""
        if stix_type not in ("observed-data", "malware"):
            raise GNATClientError(
                f"VMRay list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        params: dict[str, Any] = {"_limit": int(page_size)}
        if filters.get("offset") is not None:
            params["_offset"] = int(filters["offset"])
        else:
            params["_offset"] = max(0, (int(page) - 1) * int(page_size))
        for key in ("sample_sha256", "severity", "verdict"):
            if filters.get(key):
                params[key] = filters[key]

        if stix_type == "observed-data":
            resp = self.get("/rest/analysis", params=params)
            kind = "analysis"
        else:
            resp = self.get("/rest/sample", params=params)
            kind = "sample"
        data = _unwrap_vmray(resp)
        if isinstance(data, list):
            return [dict(r, _vmr_kind=kind) for r in data if isinstance(r, dict)]
        return []

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Sandbox submissions are domain helpers, not upsert."""
        raise GNATClientError(
            "VMRay connector is read-only via CRUD — use submit_file / "
            "submit_url domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """VMRay connector is read-only."""
        raise GNATClientError(
            "VMRay connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def submit_file(self, filepath: str, **opts: Any) -> dict[str, Any]:
        """Submit a local file for analysis."""
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"sample_file": (os.path.basename(filepath), fh.read())}
        form = {k: v for k, v in opts.items() if v is not None}
        return self.post("/rest/sample/submit", data=form, files=files)

    def submit_url(self, url: str, **opts: Any) -> dict[str, Any]:
        """Submit a URL for analysis."""
        form: dict[str, Any] = {"sample_url": url}
        form.update({k: v for k, v in opts.items() if v is not None})
        return self.post("/rest/sample/submit", data=form)

    def get_sample(self, sample_id: str) -> dict[str, Any]:
        """Fetch sample metadata by id."""
        return self.get_object("malware", sample_id)

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Fetch analysis metadata by id."""
        return self.get_object("observed-data", analysis_id)

    def get_submission(self, submission_id: str) -> dict[str, Any]:
        """Fetch submission state by id."""
        resp = self.get(f"/rest/submission/{submission_id}")
        data = _unwrap_vmray(resp)
        return data if isinstance(data, dict) else {}

    def get_summary_v2(self, analysis_id: str) -> dict[str, Any]:
        """Fetch the full v2 behavioral summary JSON."""
        path = f"/rest/analysis/{analysis_id}/archive/logs/summary_v2.json"
        resp = self.get(path)
        return resp if isinstance(resp, dict) else {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a VMRay record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("VMRay to_stix expects a dict input")

        kind = native.get("_vmr_kind") or "analysis"

        if kind == "sample":
            family = (
                native.get("sample_classifications")
                or native.get("sample_vti_score")
                or native.get("sample_type")
                or "unknown"
            )
            if isinstance(family, list):
                family = family[0] if family else "unknown"
            stix_uuid = uuid.uuid5(_NAMESPACE_VMRAY, f"malware|{family}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": "2.1",
                "created": utcnow(),
                "modified": utcnow(),
                "name": str(family),
                "is_family": True,
                "description": f"VMRay sample (severity={native.get('sample_severity', 'unknown')})",
                "malware_types": ["unknown"],
                "x_vmray": {"raw": native},
            }

        # Analysis → observed-data envelope
        network = native.get("analysis_network") or native.get("network") or {}
        contacted_ips = _values(network.get("hosts") or network.get("ips"))
        contacted_domains = _values(network.get("domains"))
        contacted_urls = _values(network.get("urls"))
        processes = _values(
            native.get("analysis_process_list") or native.get("processes")
        )
        return sandbox_report_envelope(
            source_name="vmray",
            analysis_id=str(
                native.get("analysis_id") or native.get("sample_id", "")
            ),
            submitted_sha256=native.get("sample_sha256") or "",
            submitted_filename=native.get("sample_filename") or "",
            processes=processes,
            contacted_ips=contacted_ips,
            contacted_domains=contacted_domains,
            contacted_urls=contacted_urls,
            first_observed=native.get("analysis_created") or "",
            last_observed=native.get("analysis_finished") or "",
            verdict=native.get("analysis_verdict")
            or native.get("sample_verdict", ""),
            score=native.get("analysis_severity")
            or native.get("sample_severity"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """VMRay CRUD is read-only."""
        return {
            "note": (
                "VMRay connector is read-only via CRUD. Use submit_file, "
                "submit_url, get_sample, get_analysis, get_submission, or "
                "get_summary_v2 to interact with the platform."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _unwrap_vmray(resp: Any) -> Any:
    """Strip VMRay's ``{"data": ..., "result": "ok"}`` envelope."""
    if isinstance(resp, dict) and "data" in resp:
        return resp["data"]
    return resp


def _values(container: Any) -> list[str]:
    """Normalize a list/dict of network observables into plain strings."""
    if container is None:
        return []
    if isinstance(container, list):
        out: list[str] = []
        for item in container:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                val = (
                    item.get("value")
                    or item.get("ip_address")
                    or item.get("ip")
                    or item.get("hostname")
                    or item.get("domain")
                    or item.get("url")
                    or item.get("command_line")
                    or item.get("name")
                )
                if isinstance(val, str):
                    out.append(val)
        return out
    if isinstance(container, str):
        return [container]
    return []
