# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.osv.client
==============================

OSV.dev connector — open-source vulnerability intelligence for package
ecosystems (PyPI, npm, Maven, Go, Rust, RubyGems, Debian, Alpine, …).

Authentication
--------------
None.  The OSV API is free and anonymous.

Configuration::

    [osv]
    host = https://api.osv.dev

Key endpoints
-------------
* ``POST /v1/query`` — single-package / single-version query
* ``POST /v1/querybatch`` — batched queries
* ``GET  /v1/vulns/{id}`` — fetch a specific vulnerability by id
  (``CVE-…``, ``GHSA-…``, ``PYSEC-…``, etc.)

STIX Type Mapping
-----------------
``vulnerability`` → OSV ``vulns`` endpoint.  Translation is delegated to
:func:`~gnat.utils.stix_helpers.osv_to_stix_vulnerability`.

Notes
-----
* **Read-only.**  ``upsert_object`` and ``delete_object`` raise
  :class:`GNATClientError`.
* ``list_objects`` relies on the ``package`` filter
  (``{"ecosystem": "PyPI", "name": "django"}``) plus an optional
  ``version`` — OSV has no generic "list all" endpoint.
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import osv_to_stix_vulnerability


class OSVClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the OSV.dev vulnerability database.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.osv.dev"``.
    """

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "vulnerability": "vulns",
    }

    def __init__(self, host: str = "https://api.osv.dev", **kwargs: Any) -> None:
        """Initialize OSVClient."""
        super().__init__(host=host, **kwargs)

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No authentication required for the OSV public API."""
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query a known-good CVE as a lightweight liveness probe."""
        try:
            self.get("/v1/vulns/CVE-2021-44228")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single OSV vulnerability by its id."""
        if stix_type != "vulnerability":
            raise GNATClientError(
                "OSV get_object only supports stix_type='vulnerability'"
            )
        if not object_id:
            raise GNATClientError("OSV get_object requires a non-empty id")
        resp = self.get(f"/v1/vulns/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"OSV returned unexpected payload for {object_id!r}: {type(resp).__name__}"
            )
        return resp

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Query OSV for vulnerabilities affecting a package.

        ``filters`` keys:

        * ``ecosystem`` (required) — e.g. ``"PyPI"``, ``"npm"``, ``"Go"``
        * ``name`` (required) — package name
        * ``version`` (optional) — pinned version to query
        * ``commit`` (optional) — commit hash (mutually exclusive with
          ``version`` for Go/Rust)

        If neither ``ecosystem`` + ``name`` nor ``commit`` is provided, the
        caller gets an empty list — OSV has no "all vulns" endpoint.
        """
        if stix_type != "vulnerability":
            raise GNATClientError(
                "OSV list_objects only supports stix_type='vulnerability'"
            )
        filters = dict(filters or {})
        ecosystem = filters.get("ecosystem", "")
        name = filters.get("name", "")
        version = filters.get("version", "")
        commit = filters.get("commit", "")

        body: dict[str, Any] = {}
        if commit:
            body["commit"] = commit
        elif ecosystem and name:
            pkg: dict[str, str] = {"ecosystem": ecosystem, "name": name}
            body["package"] = pkg
            if version:
                body["version"] = version
        else:
            return []

        resp = self.post("/v1/query", json=body)
        vulns = resp.get("vulns", []) if isinstance(resp, dict) else []
        if not isinstance(vulns, list):
            return []

        start = max(0, (int(page) - 1) * int(page_size))
        return vulns[start : start + int(page_size)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """OSV is read-only."""
        raise GNATClientError(
            "OSV connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """OSV is read-only."""
        raise GNATClientError(
            "OSV connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def query_package(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
    ) -> list[dict[str, Any]]:
        """Return all OSV vulnerabilities affecting an ecosystem/package/version."""
        return self.list_objects(
            "vulnerability",
            filters={"ecosystem": ecosystem, "name": name, "version": version},
        )

    def query_batch(self, queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """
        Execute a batched query against ``/v1/querybatch``.

        Parameters
        ----------
        queries : list of dict
            One OSV query dict per item; each follows the same schema as
            the ``POST /v1/query`` body.

        Returns
        -------
        list of list
            For each input query, the list of matching vulnerability dicts.
        """
        resp = self.post("/v1/querybatch", json={"queries": queries})
        if not isinstance(resp, dict):
            return [[] for _ in queries]
        results = resp.get("results", [])
        if not isinstance(results, list):
            return [[] for _ in queries]
        out: list[list[dict[str, Any]]] = []
        for r in results:
            vulns = r.get("vulns", []) if isinstance(r, dict) else []
            out.append(vulns if isinstance(vulns, list) else [])
        return out

    def get_vuln(self, osv_id: str) -> dict[str, Any]:
        """Fetch a single vulnerability by OSV id."""
        return self.get_object("vulnerability", osv_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an OSV vulnerability dict to STIX 2.1 ``vulnerability``."""
        if not isinstance(native, dict):
            raise GNATClientError("OSV to_stix expects a dict input")
        return osv_to_stix_vulnerability(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """OSV is read-only. Returns an informational stub."""
        return {
            "note": (
                "OSV connector is read-only. Use query_package, get_vuln, "
                "or list_objects to search vulnerabilities."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
