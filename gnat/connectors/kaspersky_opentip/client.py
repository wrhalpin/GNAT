# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.kaspersky_opentip.client
============================================

Kaspersky OpenTIP connector — free public threat lookups backed by
Kaspersky Security Network.

Authentication
--------------
Optional ``x-api-key`` header (registration gives higher rate limits)::

    [kaspersky_opentip]
    host    = https://opentip.kaspersky.com
    api_key =

Key endpoints
-------------
* ``GET /api/v1/search/ip?request={ip}``
* ``GET /api/v1/search/domain?request={domain}``
* ``GET /api/v1/search/url?request={url}``
* ``GET /api/v1/search/hash?request={md5|sha1|sha256}``
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_KASPERSKY = uuid.UUID("ca5ce1a7-0001-4a1e-9b1e-ca5ce1a7c0fe")


class KasperskyOpenTIPClient(BaseClient, ConnectorMixin):
    """HTTP client for Kaspersky OpenTIP."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "search",
    }

    def __init__(
        self,
        host: str = "https://opentip.kaspersky.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize KasperskyOpenTIPClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set optional x-api-key header."""
        self._auth_headers["Accept"] = "application/json"
        if self.api_key:
            self._auth_headers["x-api-key"] = self.api_key

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query a known-good domain lookup."""
        try:
            self.get(
                "/api/v1/search/domain", params={"request": "kaspersky.com"}
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch Kaspersky reputation for an IOC."""
        if stix_type != "indicator":
            raise GNATClientError(
                f"Kaspersky OpenTIP get_object does not support stix_type={stix_type!r}"
            )
        if not object_id:
            raise GNATClientError("Kaspersky OpenTIP get_object requires a non-empty id")

        ioc_type = _guess_ioc_type(object_id)
        resp = self.get(
            f"/api/v1/search/{ioc_type}", params={"request": object_id}
        )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Kaspersky OpenTIP returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _kt_ioc_type=ioc_type, _kt_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        OpenTIP has no bulk listing; this wraps a single lookup via
        ``filters['value']``.
        """
        if stix_type != "indicator":
            raise GNATClientError(
                f"Kaspersky OpenTIP list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        value = filters.get("value")
        if not value:
            return []
        return [self.get_object("indicator", value)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Kaspersky OpenTIP connector is read-only."""
        raise GNATClientError(
            "Kaspersky OpenTIP connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Kaspersky OpenTIP connector is read-only."""
        raise GNATClientError(
            "Kaspersky OpenTIP connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Return Kaspersky reputation for an IP."""
        return self.get_object("indicator", ip)

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Return Kaspersky reputation for a domain."""
        return self.get_object("indicator", domain)

    def lookup_url(self, url: str) -> dict[str, Any]:
        """Return Kaspersky reputation for a URL."""
        return self.get_object("indicator", url)

    def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        """Return Kaspersky reputation for a file hash."""
        return self.get_object("indicator", hash_value)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an OpenTIP lookup result to STIX 2.1 indicator."""
        if not isinstance(native, dict):
            raise GNATClientError("Kaspersky OpenTIP to_stix expects a dict input")

        query = native.get("_kt_query", "")
        ioc_type = native.get("_kt_ioc_type", "domain")

        if ioc_type == "ip":
            pattern = make_indicator_pattern("ipv4-addr", query)
        elif ioc_type == "url":
            pattern = make_indicator_pattern("url", query)
        elif ioc_type == "hash":
            algo = _hash_algo(query)
            pattern = make_indicator_pattern(f"file:{algo}", query)
        else:
            pattern = make_indicator_pattern("domain-name", query)

        stix_uuid = uuid.uuid5(_NAMESPACE_KASPERSKY, f"indicator|{query}")
        zone = (
            (native.get("Zone") or native.get("zone") or "")
            if isinstance(native, dict)
            else ""
        )
        labels = (
            ["malicious-activity"]
            if str(zone).lower() in {"red", "orange"}
            else ["benign"]
        )
        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": "2.1",
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"Kaspersky OpenTIP: {query}",
            "description": native.get("CategoriesWithZone")
            or native.get("description")
            or "Kaspersky OpenTIP lookup",
            "labels": labels,
            "x_kaspersky_opentip": {
                "zone": zone,
                "categories": native.get("CategoriesWithZone"),
                "first_seen": native.get("FirstSeen"),
                "hits_count": native.get("HitsCount"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Kaspersky OpenTIP connector is read-only."""
        return {
            "note": (
                "Kaspersky OpenTIP connector is read-only. Use lookup_ip, "
                "lookup_domain, lookup_url, or lookup_hash to query."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _guess_ioc_type(value: str) -> str:
    """Heuristically pick an OpenTIP endpoint from the IOC value."""
    if _looks_like_ipv4(value):
        return "ip"
    if value.startswith(("http://", "https://")):
        return "url"
    if len(value) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in value
    ):
        return "hash"
    return "domain"


def _looks_like_ipv4(value: str) -> bool:
    """Return True if *value* looks like an IPv4 dotted-quad."""
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _hash_algo(value: str) -> str:
    """Return the STIX hash algo name for a hex hash value."""
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    return "sha256"
