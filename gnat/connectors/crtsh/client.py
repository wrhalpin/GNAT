# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.crtsh.client
================================

crt.sh — free public Certificate Transparency log search.

crt.sh is operated by Sectigo and aggregates every public CT log,
exposing a JSON-search API at ``https://crt.sh/?q=...&output=json``.
No authentication is required.

Configuration::

    [crtsh]
    host = https://crt.sh

Filter keys (passed via ``list_objects(filters=...)``):

* ``query`` — domain or substring (default ``%`` for exact-match
  semantics, prefix ``%.`` for sub-domain expansion)
* ``identity`` — alias for ``query`` (matches the ``q`` parameter)
* ``deduplicate`` — collapse repeated cert serials when True
* ``exclude_expired`` — drop entries whose ``not_after`` is in the past
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import utcnow

_NAMESPACE_CRTSH = uuid.UUID("c47ac111-0001-4a1e-9b1e-c47ac111c0fe")


class CrtShClient(BaseClient, ConnectorMixin):
    """HTTP client for crt.sh."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"x509-certificate": "certificates"}

    def __init__(
        self,
        host: str = "https://crt.sh",
        **kwargs: Any,
    ) -> None:
        """Initialize CrtShClient."""
        super().__init__(host=host, **kwargs)

    def authenticate(self) -> None:
        """crt.sh has no authentication; just set Accept header."""
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Search for example.com as a liveness probe."""
        try:
            self.get("/", params={"q": "example.com", "output": "json"})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single certificate by crt.sh ``id``."""
        if not object_id:
            raise GNATClientError("crt.sh get_object requires a non-empty id")
        if stix_type != "x509-certificate":
            raise GNATClientError(
                f"crt.sh get_object does not support stix_type={stix_type!r}"
            )
        resp = self.get(
            "/",
            params={"id": object_id, "output": "json"},
        )
        record: dict[str, Any] | None = None
        if isinstance(resp, list) and resp:
            record = resp[0] if isinstance(resp[0], dict) else None
        elif isinstance(resp, dict):
            record = resp
        if not isinstance(record, dict):
            raise GNATClientError(
                f"crt.sh returned unexpected payload for id={object_id!r}"
            )
        return dict(record, _crtsh_kind="certificate")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Search the CT logs by domain or identity substring."""
        filters = dict(filters or {})
        if stix_type != "x509-certificate":
            raise GNATClientError(
                f"crt.sh list_objects does not support stix_type={stix_type!r}"
            )
        query = filters.get("query") or filters.get("identity")
        if not query:
            raise GNATClientError(
                "crt.sh list_objects requires a 'query' or 'identity' filter"
            )
        params: dict[str, Any] = {
            "q": str(query),
            "output": "json",
        }
        if filters.get("deduplicate"):
            params["dedup"] = "Y"
        if filters.get("exclude_expired"):
            params["exclude"] = "expired"
        resp = self.get("/", params=params)
        items: list[dict[str, Any]] = []
        if isinstance(resp, list):
            for r in resp:
                if isinstance(r, dict):
                    items.append(dict(r, _crtsh_kind="certificate"))
        return items

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """crt.sh connector is read-only."""
        raise GNATClientError(
            "crt.sh connector is read-only — Certificate Transparency logs "
            "are append-only and write operations are not supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """crt.sh connector is read-only."""
        raise GNATClientError(
            "crt.sh connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def search_domain(
        self,
        domain: str,
        include_subdomains: bool = True,
        deduplicate: bool = True,
        exclude_expired: bool = False,
    ) -> list[dict[str, Any]]:
        """Return all certificates issued for a domain (and optional subs)."""
        query = f"%.{domain}" if include_subdomains else domain
        return self.list_objects(
            "x509-certificate",
            filters={
                "query": query,
                "deduplicate": deduplicate,
                "exclude_expired": exclude_expired,
            },
        )

    def get_certificate(self, crtsh_id: str) -> dict[str, Any]:
        """Fetch a single certificate record by crt.sh id."""
        return self.get_object("x509-certificate", crtsh_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a crt.sh certificate record to a STIX 2.1 x509-certificate."""
        if not isinstance(native, dict):
            raise GNATClientError("crt.sh to_stix expects a dict input")

        crtsh_id = native.get("id") or native.get("min_cert_id") or ""
        serial = native.get("serial_number") or ""
        issuer = native.get("issuer_name") or ""
        subject = native.get("name_value") or native.get("common_name", "")
        not_before = native.get("not_before")
        not_after = native.get("not_after")

        stix_uuid = uuid.uuid5(
            _NAMESPACE_CRTSH, f"x509-certificate|{crtsh_id}|{serial}"
        )

        return {
            "type": "x509-certificate",
            "id": f"x509-certificate--{stix_uuid}",
            "spec_version": "2.1",
            "issuer": issuer,
            "subject": subject,
            "serial_number": serial,
            "validity_not_before": not_before,
            "validity_not_after": not_after,
            "x_crtsh": {
                "crtsh_id": crtsh_id,
                "ca_id": native.get("issuer_ca_id"),
                "name_value": native.get("name_value"),
                "entry_timestamp": native.get("entry_timestamp"),
                "result_count": native.get("result_count"),
                "raw": native,
            },
            "x_crtsh_observed": utcnow(),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """crt.sh connector is read-only."""
        return {
            "note": (
                "crt.sh connector is read-only. Use search_domain or "
                "get_certificate to query the Certificate Transparency logs."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
