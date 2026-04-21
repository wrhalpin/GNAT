# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.silent_push.client
======================================

Silent Push connector — "future attack infrastructure" detection and
actor-behavior profiling.

Authentication
--------------
``X-API-KEY`` header::

    [silent_push]
    host    = https://api.silentpush.com
    api_key = sp_...

Key endpoints
-------------
* ``GET  /api/v1/merge-api/explore/ipv4/{ip}``
* ``GET  /api/v1/merge-api/explore/domain/{domain}``
* ``GET  /api/v1/merge-api/scan/{asset}``
* ``GET  /api/v1/merge-api/padns/lookup/{qtype}/{qvalue}``
* ``POST /api/v1/merge-api/iocs/{type}/search``

STIX Type Mapping
-----------------
* ``indicator``    → IOC search results / future-attack indicators
* ``observed-data`` → passive DNS lookups
* ``threat-actor`` → actor-profile records

Notes
-----
* **Read-only.**  ``upsert_object`` / ``delete_object`` raise.
* Every record emits a deterministic UUID-5 id for idempotent ingest.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    make_observed_data_envelope,
    utcnow,
)

_NAMESPACE_SILENTPUSH = uuid.UUID("517e4705-0d00-4d0a-b10c-517e4705b10c")


class SilentPushClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Silent Push.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.silentpush.com"``.
    api_key : str
        Silent Push API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "observed-data": "padns",
        "threat-actor": "threat-ranking",
    }

    def __init__(
        self,
        host: str = "https://api.silentpush.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SilentPushClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set the X-API-KEY header from the configured key."""
        if not self.api_key:
            raise GNATClientError("Silent Push connector requires api_key in config.")
        self._auth_headers["X-API-KEY"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping a known-good domain explore endpoint as a liveness probe."""
        try:
            self.get("/api/v1/merge-api/explore/domain/example.com")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Silent Push record.

        ``stix_type`` values:

        * ``"indicator"`` — ``/explore/{domain|ipv4}/{value}`` enrichment
        * ``"observed-data"`` — ``/padns/lookup/...`` passive DNS (use
          :meth:`padns` helper)
        """
        if not object_id:
            raise GNATClientError("Silent Push get_object requires a non-empty id")
        if stix_type == "indicator":
            if _looks_like_ipv4(object_id):
                resp = self.get(f"/api/v1/merge-api/explore/ipv4/{object_id}")
                kind = "ipv4"
            else:
                resp = self.get(f"/api/v1/merge-api/explore/domain/{object_id}")
                kind = "domain"
            if not isinstance(resp, dict):
                raise GNATClientError(f"Silent Push returned unexpected payload for {object_id!r}")
            return dict(resp, _sp_kind="indicator", _sp_subkind=kind, _sp_query=object_id)
        raise GNATClientError(f"Silent Push get_object does not support stix_type={stix_type!r}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Silent Push records.

        ``filters`` keys:

        * ``ioc_type`` — ``"domain"``, ``"ipv4"``, ``"url"``, ``"sha256"``
        * ``query`` — JSON body passed to ``/iocs/{type}/search``
        """
        filters = dict(filters or {})

        if stix_type == "indicator":
            ioc_type = filters.get("ioc_type") or "domain"
            query = filters.get("query") or {}
            resp = self.post(f"/api/v1/merge-api/iocs/{ioc_type}/search", json=query)
            data = _extract_sp_items(resp)
            return [dict(r, _sp_kind="indicator", _sp_subkind=ioc_type) for r in data]
        if stix_type == "observed-data":
            qtype = (filters.get("qtype") or "a").lower()
            qvalue = filters.get("qvalue") or ""
            if not qvalue:
                raise GNATClientError(
                    "Silent Push list_objects(observed-data) requires a 'qvalue' filter"
                )
            resp = self.get(f"/api/v1/merge-api/padns/lookup/{qtype}/{qvalue}")
            data = _extract_sp_items(resp)
            return [
                dict(r, _sp_kind="observed-data", _sp_qtype=qtype, _sp_query=qvalue) for r in data
            ]
        raise GNATClientError(f"Silent Push list_objects does not support stix_type={stix_type!r}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Silent Push connector is read-only."""
        raise GNATClientError("Silent Push connector is read-only — no write operations supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Silent Push connector is read-only."""
        raise GNATClientError(
            "Silent Push connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def ipv4_enrich(self, ip: str) -> dict[str, Any]:
        """Return Silent Push enrichment for an IPv4 address."""
        return self.get_object("indicator", ip)

    def domain_enrich(self, domain: str) -> dict[str, Any]:
        """Return Silent Push enrichment for a domain."""
        return self.get_object("indicator", domain)

    def padns(self, qtype: str, qvalue: str) -> list[dict[str, Any]]:
        """Return passive DNS lookups for (*qtype*, *qvalue*)."""
        return self.list_objects("observed-data", filters={"qtype": qtype, "qvalue": qvalue})

    def search_iocs(self, ioc_type: str, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Search Silent Push IOC indices."""
        return self.list_objects("indicator", filters={"ioc_type": ioc_type, "query": query})

    def scan_asset(self, asset: str) -> dict[str, Any]:
        """Trigger a Silent Push scan on *asset* and return the result."""
        resp = self.get(f"/api/v1/merge-api/scan/{asset}")
        if isinstance(resp, dict):
            return dict(resp, _sp_kind="indicator", _sp_query=asset)
        return {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Silent Push record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Silent Push to_stix expects a dict input")

        kind = native.get("_sp_kind") or "indicator"
        subkind = native.get("_sp_subkind") or ""
        query = native.get("_sp_query", "")
        now = utcnow()

        if kind == "indicator":
            if subkind == "ipv4" or _looks_like_ipv4(query):
                value = native.get("ipv4") or query
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif subkind in ("sha256", "md5", "sha1"):
                value = native.get("hash") or query
                pattern = make_indicator_pattern(f"file:{subkind}", value)
            elif subkind == "url":
                value = native.get("url") or query
                pattern = make_indicator_pattern("url", value)
            else:
                value = native.get("domain") or query
                pattern = make_indicator_pattern("domain-name", value)
            stix_uuid = uuid.uuid5(_NAMESPACE_SILENTPUSH, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "name": f"Silent Push: {value}",
                "description": native.get("description") or "Silent Push IOC",
                "labels": _sp_labels(native),
                "x_silentpush": {
                    "sp_risk_score": native.get("sp_risk_score") or native.get("risk_score"),
                    "actor_profile": native.get("actor_profile"),
                    "future_attack_indicator": native.get("future_attack_indicator"),
                    "tags": native.get("tags", []),
                    "raw": native,
                },
            }

        # observed-data — passive DNS record
        refs: list[str] = []
        value = native.get("value") or native.get("answer") or ""
        qtype = native.get("_sp_qtype", "a")
        if qtype in ("a",) and value:
            ip_uuid = uuid.uuid5(_NAMESPACE_SILENTPUSH, f"ipv4-addr|{value}")
            refs.append(f"ipv4-addr--{ip_uuid}")
        elif value:
            dom_uuid = uuid.uuid5(_NAMESPACE_SILENTPUSH, f"domain-name|{value}")
            refs.append(f"domain-name--{dom_uuid}")
        if query:
            q_uuid = uuid.uuid5(_NAMESPACE_SILENTPUSH, f"domain-name|{query}")
            refs.append(f"domain-name--{q_uuid}")

        first = native.get("first_seen") or now
        last = native.get("last_seen") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="silent_push",
            x_extensions={"silentpush_raw": native},
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Silent Push is read-only."""
        return {
            "note": (
                "Silent Push connector is read-only. Use ipv4_enrich, "
                "domain_enrich, padns, search_iocs, or scan_asset to query "
                "the API."
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


def _extract_sp_items(resp: Any) -> list[dict[str, Any]]:
    """Pull the list of records out of a Silent Push API response."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    response = resp.get("response") or resp
    for key in ("records", "results", "items", "data"):
        val = response.get(key) if isinstance(response, dict) else None
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _sp_labels(native: dict[str, Any]) -> list[str]:
    """Choose STIX labels from a Silent Push risk score."""
    score = native.get("sp_risk_score") or native.get("risk_score")
    if isinstance(score, (int, float)) and score >= 50:
        return ["malicious-activity"]
    return ["benign"]
