# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.runzero.client
==================================

runZero CAASM connector.

Authentication
--------------
Organization Export API key via ``Authorization: Bearer <token>``::

    [runzero]
    host         = https://console.runzero.com
    export_token = rZ_...

Key endpoints
-------------
* ``GET /api/v1.0/export/org/assets.json`` — bulk asset export
* ``GET /api/v1.0/export/org/services.json`` — bulk service export
* ``GET /api/v1.0/export/org/software.json`` — bulk software inventory
* ``GET /api/v1.0/export/org/vulnerabilities.json`` — bulk vuln inventory
* ``GET /api/v1.0/org/assets/{id}`` — single asset lookup
* ``GET /api/v1.0/org/sites`` — list scan sites
* ``GET /api/v1.0/org/tasks`` — scan task state

STIX Type Mapping
-----------------
* ``observed-data`` → ``export/org/assets.json`` (each asset becomes
  an ``observed-data`` envelope wrapping synthetic ``ipv4-addr`` /
  ``mac-addr`` / ``software`` observable refs)
* ``software`` → ``export/org/software.json``
* ``vulnerability`` → ``export/org/vulnerabilities.json``

Notes
-----
* **Read-only.**  ``upsert_object`` / ``delete_object`` raise
  :class:`GNATClientError`.
* Scan triggering (``POST /api/v1.0/org/sites/{site}/scan``) is a
  domain helper, not part of the standard CRUD contract.
* Trust level is ``trusted_internal`` because runZero data represents
  the customer's own asset inventory, not external intel.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    cvss_to_external_reference,
    make_observed_data_envelope,
    utcnow,
)

# Deterministic UUID-5 namespace for runZero observable ids.
_NAMESPACE_RUNZERO = uuid.UUID("d3a4b5c6-7890-4a12-9b34-5e6f7a8b9c01")


class RunZeroClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the runZero CAASM platform.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://console.runzero.com"``.
    export_token : str
        runZero Organization Export API key.
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1.0"
    API_PREFIX: str = "/api/v1.0"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "export/org/assets.json",
        "software": "export/org/software.json",
        "vulnerability": "export/org/vulnerabilities.json",
    }

    def __init__(
        self,
        host: str = "https://console.runzero.com",
        export_token: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize RunZeroClient."""
        super().__init__(host=host, **kwargs)
        self.export_token = export_token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header from the configured export token."""
        if not self.export_token:
            raise GNATClientError("runZero connector requires export_token in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.export_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping ``/api/v1.0/account/orgs`` as an authenticated liveness probe."""
        try:
            self.get("/api/v1.0/account/orgs")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single runZero resource.

        ``stix_type`` values:

        * ``"observed-data"`` — single asset via ``/api/v1.0/org/assets/{id}``
        * ``"vulnerability"`` — single vulnerability via
          ``/api/v1.0/org/vulnerabilities/{id}`` (when supported)
        """
        if not object_id:
            raise GNATClientError("runZero get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(f"/api/v1.0/org/assets/{object_id}")
        elif stix_type == "vulnerability":
            resp = self.get(f"/api/v1.0/org/vulnerabilities/{object_id}")
        else:
            raise GNATClientError(f"runZero get_object does not support stix_type={stix_type!r}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"runZero returned unexpected payload for {object_id!r}")
        return resp

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List runZero records via the bulk export endpoints.

        ``filters`` keys:

        * ``search`` — runZero search expression
        * ``site`` — restrict to a named site
        * ``fields`` — comma-separated field list for narrower payloads
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {}
        if filters.get("search"):
            params["search"] = filters["search"]
        if filters.get("site"):
            params["site"] = filters["site"]
        if filters.get("fields"):
            params["fields"] = filters["fields"]

        if stix_type == "observed-data":
            resp = self.get("/api/v1.0/export/org/assets.json", params=params)
        elif stix_type == "software":
            resp = self.get("/api/v1.0/export/org/software.json", params=params)
        elif stix_type == "vulnerability":
            resp = self.get("/api/v1.0/export/org/vulnerabilities.json", params=params)
        else:
            raise GNATClientError(f"runZero list_objects does not support stix_type={stix_type!r}")

        items: list[dict[str, Any]]
        if isinstance(resp, list):
            items = [r for r in resp if isinstance(r, dict)]
        elif isinstance(resp, dict):
            data = resp.get("data") or resp.get("assets") or resp.get("results") or []
            items = data if isinstance(data, list) else []
        else:
            items = []

        # Tag records with their logical kind so to_stix can dispatch.
        kind_tag = stix_type
        tagged = [dict(item, _rz_kind=kind_tag) for item in items]

        start = max(0, (int(page) - 1) * int(page_size))
        return tagged[start : start + int(page_size)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """runZero connector is read-only."""
        raise GNATClientError("runZero connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """runZero connector is read-only."""
        raise GNATClientError("runZero connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def export_assets(self, search: str = "", site: str = "") -> list[dict[str, Any]]:
        """Return the asset export, optionally filtered by search or site."""
        filters: dict[str, Any] = {}
        if search:
            filters["search"] = search
        if site:
            filters["site"] = site
        return self.list_objects("observed-data", filters=filters, page_size=10_000)

    def export_software(self) -> list[dict[str, Any]]:
        """Return the software inventory export."""
        return self.list_objects("software", page_size=10_000)

    def export_vulnerabilities(self) -> list[dict[str, Any]]:
        """Return the vulnerability inventory export."""
        return self.list_objects("vulnerability", page_size=10_000)

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        """Fetch a single asset by id."""
        return self.get_object("observed-data", asset_id)

    def list_sites(self) -> list[dict[str, Any]]:
        """List runZero scan sites."""
        resp = self.get("/api/v1.0/org/sites")
        if isinstance(resp, list):
            return [r for r in resp if isinstance(r, dict)]
        return []

    def list_tasks(self) -> list[dict[str, Any]]:
        """List runZero scan tasks and their state."""
        resp = self.get("/api/v1.0/org/tasks")
        if isinstance(resp, list):
            return [r for r in resp if isinstance(r, dict)]
        return []

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a runZero record to STIX 2.1.

        Dispatch is driven by the ``_rz_kind`` marker stamped by
        ``list_objects``, with a fallback to field-shape heuristics.
        """
        if not isinstance(native, dict):
            raise GNATClientError("runZero to_stix expects a dict input")

        kind = native.get("_rz_kind")
        if kind == "software" or (native.get("name") and native.get("vendor") and "cpe" in native):
            return _software_to_stix(native)
        if kind == "vulnerability" or native.get("cve"):
            return _vulnerability_to_stix(native)
        # Default: asset → observed-data envelope
        return _asset_to_observed_data(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """runZero connector is read-only."""
        return {
            "note": (
                "runZero connector is read-only. Use export_assets, "
                "export_software, export_vulnerabilities, get_asset, "
                "list_sites, or list_tasks to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


# ---------------------------------------------------------------------------
# Module-private STIX mappers
# ---------------------------------------------------------------------------


def _asset_to_observed_data(asset: dict[str, Any]) -> dict[str, Any]:
    """Convert a runZero asset dict to a STIX ``observed-data`` envelope."""
    asset_id = asset.get("id") or asset.get("asset_id") or ""
    refs: list[str] = []

    for ip in _as_list(asset.get("addresses")) + _as_list(asset.get("ipv4")):
        if ip:
            ip_uuid = uuid.uuid5(_NAMESPACE_RUNZERO, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{ip_uuid}")

    for mac in _as_list(asset.get("macs")) + _as_list(asset.get("mac")):
        if mac:
            mac_uuid = uuid.uuid5(_NAMESPACE_RUNZERO, f"mac-addr|{mac}")
            refs.append(f"mac-addr--{mac_uuid}")

    for hw in _as_list(asset.get("hw")) + _as_list(asset.get("os")):
        if hw:
            sw_uuid = uuid.uuid5(_NAMESPACE_RUNZERO, f"software|{hw}")
            refs.append(f"software--{sw_uuid}")

    first = (
        asset.get("first_seen") or asset.get("detected_at") or asset.get("created_at") or utcnow()
    )
    last = asset.get("last_seen") or asset.get("updated_at") or first

    envelope = make_observed_data_envelope(
        first_observed=first,
        last_observed=last,
        number_observed=1,
        object_refs=refs,
        source_name="runzero",
        x_extensions={
            "runzero": {
                "asset_id": asset_id,
                "os": asset.get("os"),
                "os_vendor": asset.get("os_vendor"),
                "hw": asset.get("hw"),
                "type": asset.get("type"),
                "site_name": asset.get("site_name"),
                "services_count": asset.get("service_count"),
                "rtt": asset.get("rtt_ms") or asset.get("rtt"),
                "tags": asset.get("tags", []),
                "risk": asset.get("risk"),
                "raw": asset,
            }
        },
    )
    return envelope


def _software_to_stix(sw: dict[str, Any]) -> dict[str, Any]:
    """Convert a runZero software record to a STIX ``software`` SCO."""
    name = sw.get("name") or sw.get("product") or ""
    vendor = sw.get("vendor") or ""
    version = sw.get("version") or ""
    cpe = sw.get("cpe") or ""

    sw_uuid = uuid.uuid5(_NAMESPACE_RUNZERO, f"software|{vendor}|{name}|{version}")
    return {
        "type": "software",
        "id": f"software--{sw_uuid}",
        "spec_version": CURRENT_SPEC_VERSION,
        "name": name,
        "vendor": vendor,
        "version": version,
        "cpe": cpe,
        "x_runzero_software": {
            "asset_count": sw.get("asset_count"),
            "first_seen": sw.get("first_seen"),
            "last_seen": sw.get("last_seen"),
            "raw": sw,
        },
    }


def _vulnerability_to_stix(vuln: dict[str, Any]) -> dict[str, Any]:
    """Convert a runZero vulnerability record to a STIX ``vulnerability`` SDO."""
    cve = vuln.get("cve") or vuln.get("vuln_id") or ""
    vuln_uuid = uuid.uuid5(_NAMESPACE_RUNZERO, f"vulnerability|{cve}")
    now = utcnow()

    external_refs: list[dict[str, str]] = []
    if cve:
        external_refs.append(
            {
                "source_name": "cve",
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
        )

    cvss_vector = vuln.get("cvss_vector") or vuln.get("cvss3_vector") or ""
    cvss_score = vuln.get("cvss_score") or vuln.get("cvss3_base_score")
    if cvss_vector:
        version = "3.1"
        if "CVSS:4" in cvss_vector:
            version = "4.0"
        elif "CVSS:2" in cvss_vector:
            version = "2.0"
        external_refs.append(
            cvss_to_external_reference(cvss_vector, cvss_score=cvss_score, cvss_version=version)
        )

    return {
        "type": "vulnerability",
        "id": f"vulnerability--{vuln_uuid}",
        "spec_version": CURRENT_SPEC_VERSION,
        "created": vuln.get("created_at") or now,
        "modified": vuln.get("updated_at") or now,
        "name": cve or vuln.get("name", "runzero-vulnerability"),
        "description": vuln.get("description") or vuln.get("summary") or "",
        "external_references": external_refs,
        "x_runzero_vulnerability": {
            "asset_count": vuln.get("asset_count"),
            "severity": vuln.get("severity"),
            "first_seen": vuln.get("first_seen"),
            "last_seen": vuln.get("last_seen"),
            "raw": vuln,
        },
    }


def _as_list(value: Any) -> list[Any]:
    """Normalize scalar / list / None into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        # runZero often returns comma-separated addresses
        return [v.strip() for v in value.split(",") if v.strip()]
    return [value]
