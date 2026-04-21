# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.vulncheck.client
====================================

VulnCheck connector — vulnerability and exploit intelligence.

Authentication
--------------
Bearer token (API key).  Free community tier available::

    [vulncheck]
    host    = https://api.vulncheck.com
    api_key = vulncheck_sk_...

Key indices
-----------
* ``vulncheck-kev`` — VulnCheck's own Known Exploited Vulnerabilities
  catalog (broader than CISA KEV)
* ``initial-access`` — exploits leading to initial access
* ``exploits`` — publicly available exploit code
* ``canary-intelligence`` — telemetry from VulnCheck's canary network
* ``mitre-cve`` — MITRE CVE mirror
* ``nist-nvd2`` — NVD 2.0 API mirror

STIX Type Mapping
-----------------
``vulnerability`` → ``index/vulncheck-kev`` (and the other CVE-indexed
indices).  Mapping uses
:func:`~gnat.utils.stix_helpers.osv_to_stix_vulnerability` when OSV-compatible
records are returned, otherwise a direct CVE → STIX vulnerability builder.

Notes
-----
* **Read-only** for Phase 1.  Write endpoints are not supported.
* ``list_objects`` paginates via a cursor when the index returns one.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import cvss_to_external_reference, utcnow

# Deterministic namespace for VulnCheck-derived STIX ids.
_NAMESPACE_VULNCHECK = uuid.UUID("a76c1b2d-9e4f-4a8b-bc3a-5e1f0d2e4a93")

_VALID_INDICES: frozenset[str] = frozenset(
    {
        "vulncheck-kev",
        "initial-access",
        "exploits",
        "canary-intelligence",
        "mitre-cve",
        "nist-nvd2",
    }
)


class VulnCheckClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the VulnCheck API.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.vulncheck.com"``.
    api_key : str
        VulnCheck API key (Bearer token).
    default_index : str, optional
        Index queried when ``list_objects`` / ``get_object`` don't specify
        one via ``filters["index"]``.  Defaults to ``"vulncheck-kev"``.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/v3"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "vulnerability": "index/vulncheck-kev",
        "indicator": "index/initial-access",
        "malware": "index/exploits",
    }

    def __init__(
        self,
        host: str = "https://api.vulncheck.com",
        api_key: str = "",
        default_index: str = "vulncheck-kev",
        **kwargs: Any,
    ) -> None:
        """Initialize VulnCheckClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        if default_index not in _VALID_INDICES:
            raise GNATClientError(
                f"Unknown VulnCheck index {default_index!r}. Valid: {sorted(_VALID_INDICES)}"
            )
        self.default_index = default_index

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header from the configured API key."""
        if not self.api_key:
            raise GNATClientError("VulnCheck connector requires api_key in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_key}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v3/indices`` as a lightweight authenticated ping."""
        try:
            self.get("/v3/indices")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single record by CVE id.

        Queries the default index unless the caller wraps the request with
        a helper that specifies another index.
        """
        if stix_type not in ("vulnerability", "indicator", "malware"):
            raise GNATClientError(f"VulnCheck get_object does not support stix_type={stix_type!r}")
        if not object_id:
            raise GNATClientError("VulnCheck get_object requires a non-empty id")
        resp = self.get(
            f"/v3/index/{self.default_index}",
            params={"cve": object_id},
        )
        items = _extract_items(resp)
        if not items:
            raise GNATClientError(
                f"VulnCheck: no record for {object_id!r} in index {self.default_index}"
            )
        return items[0]

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List records from a VulnCheck index.

        ``filters`` keys:

        * ``index``: one of the values in :data:`_VALID_INDICES`
          (defaults to ``self.default_index``)
        * ``cve``: filter by CVE id
        * ``cpe``: filter by CPE string
        * ``vendor``, ``product``: string filters
        * ``cursor``: opaque continuation token returned in previous call
        """
        if stix_type not in ("vulnerability", "indicator", "malware"):
            raise GNATClientError(
                f"VulnCheck list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        index = filters.pop("index", self.default_index)
        if index not in _VALID_INDICES:
            raise GNATClientError(f"Unknown VulnCheck index {index!r}")

        params: dict[str, Any] = {}
        for key in ("cve", "cpe", "vendor", "product", "cursor"):
            val = filters.get(key)
            if val:
                params[key] = val
        params["limit"] = int(page_size)
        params["start_cursor"] = int(max(0, (page - 1) * page_size))

        resp = self.get(f"/v3/index/{index}", params=params)
        return _extract_items(resp)

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """VulnCheck connector is read-only."""
        raise GNATClientError("VulnCheck connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """VulnCheck connector is read-only."""
        raise GNATClientError("VulnCheck connector is read-only — no delete operations supported.")

    # ── Domain-specific helpers ────────────────────────────────────────────

    def get_kev(self, cve_id: str) -> dict[str, Any]:
        """Fetch a record from VulnCheck's KEV index by CVE id."""
        resp = self.get("/v3/index/vulncheck-kev", params={"cve": cve_id})
        items = _extract_items(resp)
        if not items:
            raise GNATClientError(f"VulnCheck KEV: no record for {cve_id!r}")
        return items[0]

    def get_exploits(self, cve_id: str) -> list[dict[str, Any]]:
        """Return all publicly-known exploits for a CVE."""
        resp = self.get("/v3/index/exploits", params={"cve": cve_id})
        return _extract_items(resp)

    def get_initial_access(self, cve_id: str = "") -> list[dict[str, Any]]:
        """Return initial-access exploits (optionally filtered by CVE)."""
        params: dict[str, Any] = {}
        if cve_id:
            params["cve"] = cve_id
        resp = self.get("/v3/index/initial-access", params=params)
        return _extract_items(resp)

    def list_indices(self) -> list[str]:
        """Return the valid VulnCheck index names."""
        return sorted(_VALID_INDICES)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a VulnCheck record to a STIX 2.1 ``vulnerability``.

        VulnCheck records vary by index, but CVE-indexed records generally
        expose ``cve``, ``description``, ``cvssBaseScore``/``cvssV3Vector``,
        and ``dateAdded`` / ``dateLastUpdated`` fields.
        """
        if not isinstance(native, dict):
            raise GNATClientError("VulnCheck to_stix expects a dict input")

        cve = (
            native.get("cve")
            or (native.get("cveMetadata") or {}).get("cveId")
            or native.get("_id")
            or ""
        )
        if isinstance(cve, list):
            cve = cve[0] if cve else ""

        now = utcnow()
        vuln_uuid = uuid.uuid5(_NAMESPACE_VULNCHECK, f"vulncheck|{cve or native.get('_id', '')}")

        description = (
            native.get("shortDescription")
            or native.get("description")
            or (native.get("cveMetadata") or {}).get("description")
            or ""
        )

        external_refs: list[dict[str, str]] = []
        if cve:
            external_refs.append(
                {
                    "source_name": "cve",
                    "external_id": cve,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                }
            )
        external_refs.append(
            {
                "source_name": "vulncheck",
                "external_id": cve or native.get("_id", ""),
            }
        )

        vector = native.get("cvssV3Vector") or native.get("cvssV4Vector") or ""
        score = native.get("cvssBaseScore")
        if vector:
            version = "3.1"
            if "CVSS:4" in vector:
                version = "4.0"
            elif "CVSS:2" in vector:
                version = "2.0"
            external_refs.append(
                cvss_to_external_reference(vector, cvss_score=score, cvss_version=version)
            )

        return {
            "type": "vulnerability",
            "id": f"vulnerability--{vuln_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": native.get("dateAdded") or now,
            "modified": native.get("dateLastUpdated") or now,
            "name": cve or "vulncheck-record",
            "description": description,
            "external_references": external_refs,
            "x_vulncheck": {
                "raw": native,
                "vendor_project": native.get("vendorProject"),
                "product": native.get("product"),
                "known_exploited": native.get("knownExploited", False),
                "ransomware_use": native.get("knownRansomwareCampaignUse"),
                "due_date": native.get("dueDate"),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """VulnCheck is read-only. Returns an informational stub."""
        return {
            "note": (
                "VulnCheck connector is read-only. Use get_kev, get_exploits, "
                "get_initial_access, or list_objects to query indices."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_items(resp: Any) -> list[dict[str, Any]]:
    """Pull the list of records out of a VulnCheck API response."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    # Common envelope shapes across VulnCheck indices
    for key in ("data", "results", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
