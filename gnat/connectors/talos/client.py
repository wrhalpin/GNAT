# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.talos.client
================================

Cisco Talos Intelligence connector.

Talos publishes most of its data through two public channels:

* ``talosintelligence.com`` — web reputation lookups (IP, domain,
  email); no authentication required for basic reputation queries.
* ``sb_api`` — SenderBase reputation sub-API used internally by the
  public reputation pages.

This connector wraps the public reputation endpoints and the Talos RSS
feeds for threat advisories::

    [talos]
    host = https://talosintelligence.com

Key endpoints
-------------
* ``GET /sb_api/query_lookup?query_entry={value}&query_type={ip|domain}``
* ``GET /sb_api/query_rep?ip_hostname={value}``
* ``GET /feeds/blog.xml``       — Talos blog RSS
* ``GET /feeds/advisory.xml``   — Talos vulnerability disclosures RSS

STIX Type Mapping
-----------------
* ``indicator``  → IP / domain reputation lookups (pattern + x-talos
  extensions for reputation category and score)
* ``report``     → Talos advisory blog entries

Notes
-----
* **Read-only.**  No authentication required for the public endpoints,
  but Talos may rate-limit aggressive clients.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_TALOS = uuid.UUID("1a105000-0001-4a1e-9b1e-1a10500ca5ca")


class TalosClient(BaseClient, ConnectorMixin):
    """HTTP client for Cisco Talos public reputation endpoints."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "sb_api/query_rep",
        "report": "feeds/advisory.xml",
    }

    def __init__(
        self,
        host: str = "https://talosintelligence.com",
        **kwargs: Any,
    ) -> None:
        """Initialize TalosClient."""
        super().__init__(host=host, **kwargs)

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Talos public endpoints are anonymous."""
        self._auth_headers["Accept"] = "application/json"
        # Talos's web endpoints reject bot-like User-Agents
        self._auth_headers["User-Agent"] = (
            "GNAT/1.5 (+https://github.com/wrhalpin/GNAT)"
        )

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query a known-good domain as a cheap reputation probe."""
        try:
            self.get(
                "/sb_api/query_lookup",
                params={"query_entry": "cisco.com", "query_type": "domain"},
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Talos reputation record.

        * ``"indicator"`` + ``object_id="8.8.8.8"`` → IP reputation
        * ``"indicator"`` + ``object_id="example.com"`` → domain reputation
        """
        if not object_id:
            raise GNATClientError("Talos get_object requires a non-empty id")
        if stix_type != "indicator":
            raise GNATClientError(
                f"Talos get_object does not support stix_type={stix_type!r}"
            )
        query_type = "ip" if _looks_like_ipv4(object_id) else "domain"
        resp = self.get(
            "/sb_api/query_lookup",
            params={"query_entry": object_id, "query_type": query_type},
        )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Talos returned unexpected payload for {object_id!r}"
            )
        return dict(
            resp, _ts_kind="reputation", _ts_query=object_id, _ts_query_type=query_type
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Talos has no generic 'list all indicators' endpoint.  Use
        :meth:`get_object` for per-IOC lookups or :meth:`get_advisories`
        for the vulnerability RSS feed.
        """
        filters = dict(filters or {})
        if stix_type == "indicator":
            value = filters.get("value")
            if not value:
                return []
            return [self.get_object("indicator", value)]
        if stix_type == "report":
            # Cheap JSON advisory index, if Talos exposes one; otherwise
            # callers should use get_advisories() for the RSS feed.
            resp = self.get(
                "/feeds/advisory-summary.json", params={"limit": int(page_size)}
            )
            items = _extract_talos_list(resp)
            return [dict(r, _ts_kind="advisory") for r in items]
        raise GNATClientError(
            f"Talos list_objects does not support stix_type={stix_type!r}"
        )

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Talos connector is read-only."""
        raise GNATClientError(
            "Talos connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Talos connector is read-only."""
        raise GNATClientError(
            "Talos connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def ip_reputation(self, ip: str) -> dict[str, Any]:
        """Fetch Talos reputation for an IP."""
        return self.get_object("indicator", ip)

    def domain_reputation(self, domain: str) -> dict[str, Any]:
        """Fetch Talos reputation for a domain."""
        return self.get_object("indicator", domain)

    def get_advisories(self) -> dict[str, Any]:
        """Fetch the Talos vulnerability advisory RSS feed (raw XML)."""
        resp = self.get("/feeds/advisory.xml")
        return {"xml": resp} if isinstance(resp, (str, bytes)) else resp

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Talos record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Talos to_stix expects a dict input")

        kind = native.get("_ts_kind") or "reputation"

        if kind == "advisory":
            adv_id = native.get("id") or native.get("title", "unknown")
            stix_uuid = uuid.uuid5(_NAMESPACE_TALOS, f"report|{adv_id}")
            return {
                "type": "report",
                "id": f"report--{stix_uuid}",
                "spec_version": "2.1",
                "created": native.get("published") or utcnow(),
                "modified": native.get("updated") or utcnow(),
                "name": native.get("title") or str(adv_id),
                "description": native.get("summary") or native.get("description", ""),
                "published": native.get("published") or utcnow(),
                "report_types": ["vulnerability"],
                "object_refs": [],
                "x_talos": {"raw": native},
            }

        # reputation → indicator
        query = native.get("_ts_query", "")
        query_type = native.get("_ts_query_type", "domain")
        if query_type == "ip":
            pattern = make_indicator_pattern("ipv4-addr", query)
        else:
            pattern = make_indicator_pattern("domain-name", query)
        stix_uuid = uuid.uuid5(_NAMESPACE_TALOS, f"indicator|{query}")
        reputation = (
            native.get("reputation")
            or native.get("rep")
            or native.get("rep_score")
            or ""
        )
        labels = (
            ["malicious-activity"]
            if str(reputation).lower() in {"untrusted", "poor", "malicious"}
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
            "name": f"Talos: {query}",
            "description": native.get("description") or "Cisco Talos reputation",
            "labels": labels,
            "x_talos": {
                "reputation": reputation,
                "email_reputation": native.get("email_reputation"),
                "web_category": native.get("web_category"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Talos connector is read-only."""
        return {
            "note": (
                "Talos connector is read-only. Use ip_reputation, "
                "domain_reputation, or get_advisories to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


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


def _extract_talos_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a Talos list response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("advisories", "data", "items", "results"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
