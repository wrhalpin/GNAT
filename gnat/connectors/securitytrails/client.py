# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.securitytrails.client
=========================================

SecurityTrails connector — passive-DNS / historical DNS / WHOIS pivoting.

Authentication
--------------
Custom ``APIKEY`` header::

    [securitytrails]
    host    = https://api.securitytrails.com
    api_key = st_...

Key endpoints
-------------
* ``GET  /v1/domain/{host}`` — current DNS + metadata
* ``GET  /v1/domain/{host}/subdomains``
* ``GET  /v1/domain/{host}/tags``
* ``GET  /v1/domain/{host}/whois``
* ``GET  /v1/history/{host}/dns/{type}`` (``a``, ``aaaa``, ``mx``, ``ns``,
  ``soa``, ``txt``)
* ``GET  /v1/history/{host}/whois``
* ``POST /v1/domains/list`` — domain search DSL
* ``POST /v1/ips/list`` — IP search DSL

STIX Type Mapping
-----------------
* ``domain-name`` → current DNS / subdomain records
* ``ipv4-addr``   → reverse-IP / A-record resolutions
* ``observed-data`` → historical DNS + historical WHOIS snapshots

Notes
-----
* **Read-only.**  ``upsert_object`` / ``delete_object`` raise.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_SECURITYTRAILS = uuid.UUID("5ec07a71-ab1e-4c0d-9a1b-5e1c07a71bad")

_VALID_DNS_RECORD_TYPES = frozenset({"a", "aaaa", "mx", "ns", "soa", "txt"})


class SecurityTrailsClient(BaseClient, ConnectorMixin):
    """
    HTTP client for SecurityTrails.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.securitytrails.com"``.
    api_key : str
        SecurityTrails API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "domain-name": "domain",
        "ipv4-addr": "ips",
        "observed-data": "history",
    }

    def __init__(
        self,
        host: str = "https://api.securitytrails.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SecurityTrailsClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set the custom ``APIKEY`` header from the configured key."""
        if not self.api_key:
            raise GNATClientError("SecurityTrails connector requires api_key in config.")
        self._auth_headers["APIKEY"] = self.api_key
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call ``/v1/ping`` as an authenticated liveness probe."""
        try:
            self.get("/v1/ping")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single object.

        ``stix_type`` values:

        * ``"domain-name"`` — current DNS record bundle
        * ``"observed-data"`` — current WHOIS record (use history helpers
          for time-series data)
        """
        if not object_id:
            raise GNATClientError("SecurityTrails get_object requires a non-empty id")
        if stix_type == "domain-name":
            resp = self.get(f"/v1/domain/{object_id}")
        elif stix_type == "observed-data":
            resp = self.get(f"/v1/domain/{object_id}/whois")
        else:
            raise GNATClientError(
                f"SecurityTrails get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(f"SecurityTrails returned unexpected payload for {object_id!r}")
        return dict(resp, _st_kind=stix_type, _st_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List objects from a SecurityTrails endpoint.

        ``filters`` keys:

        * ``domain`` — base hostname for subdomain / history queries
        * ``record_type`` — DNS record type (``a``, ``mx``, …) for history
          queries
        * ``ipv4`` — IPv4 for reverse-IP queries
        * ``query`` — SecurityTrails DSL query body for search endpoints
        """
        filters = dict(filters or {})

        if stix_type == "domain-name":
            domain = filters.get("domain", "")
            if not domain:
                raise GNATClientError(
                    "SecurityTrails list_objects(domain-name) requires a 'domain' filter"
                )
            resp = self.get(f"/v1/domain/{domain}/subdomains")
            subs = resp.get("subdomains", []) if isinstance(resp, dict) else []
            items = [
                {"_st_kind": "domain-name", "_st_query": domain, "subdomain": s, "parent": domain}
                for s in subs
                if isinstance(s, str)
            ]
        elif stix_type == "ipv4-addr":
            dsl = filters.get("query")
            if not dsl:
                raise GNATClientError(
                    "SecurityTrails list_objects(ipv4-addr) requires a 'query' filter"
                )
            resp = self.post("/v1/ips/list", json={"query": dsl})
            records = resp.get("records", []) if isinstance(resp, dict) else []
            items = [
                dict(r, _st_kind="ipv4-addr", _st_query=dsl) for r in records if isinstance(r, dict)
            ]
        elif stix_type == "observed-data":
            domain = filters.get("domain", "")
            if not domain:
                raise GNATClientError(
                    "SecurityTrails list_objects(observed-data) requires a 'domain' filter"
                )
            record_type = (filters.get("record_type") or "a").lower()
            if record_type not in _VALID_DNS_RECORD_TYPES:
                raise GNATClientError(
                    f"Invalid SecurityTrails record_type {record_type!r}. "
                    f"Valid: {sorted(_VALID_DNS_RECORD_TYPES)}"
                )
            resp = self.get(f"/v1/history/{domain}/dns/{record_type}")
            records = resp.get("records", []) if isinstance(resp, dict) else []
            items = [
                dict(r, _st_kind="observed-data", _st_query=domain, _st_record_type=record_type)
                for r in records
                if isinstance(r, dict)
            ]
        else:
            raise GNATClientError(
                f"SecurityTrails list_objects does not support stix_type={stix_type!r}"
            )

        start = max(0, (int(page) - 1) * int(page_size))
        return items[start : start + int(page_size)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """SecurityTrails connector is read-only."""
        raise GNATClientError(
            "SecurityTrails connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """SecurityTrails connector is read-only."""
        raise GNATClientError(
            "SecurityTrails connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def domain_info(self, hostname: str) -> dict[str, Any]:
        """Return the current DNS record bundle for *hostname*."""
        return self.get_object("domain-name", hostname)

    def subdomains(self, hostname: str) -> list[str]:
        """Return the list of known subdomains for *hostname*."""
        resp = self.get(f"/v1/domain/{hostname}/subdomains")
        if isinstance(resp, dict):
            subs = resp.get("subdomains", [])
            if isinstance(subs, list):
                return [s for s in subs if isinstance(s, str)]
        return []

    def historical_dns(self, hostname: str, record_type: str = "a") -> list[dict[str, Any]]:
        """Return historical DNS records of *record_type* for *hostname*."""
        return self.list_objects(
            "observed-data",
            filters={"domain": hostname, "record_type": record_type},
        )

    def historical_whois(self, hostname: str) -> dict[str, Any]:
        """Return historical WHOIS snapshots for *hostname*."""
        resp = self.get(f"/v1/history/{hostname}/whois")
        if not isinstance(resp, dict):
            return {}
        return dict(resp, _st_kind="observed-data", _st_query=hostname, _st_whois=True)

    def search_domains(self, dsl_query: dict[str, Any]) -> list[dict[str, Any]]:
        """Execute a SecurityTrails DSL domain search."""
        resp = self.post("/v1/domains/list", json={"filter": dsl_query})
        if isinstance(resp, dict):
            records = resp.get("records", [])
            if isinstance(records, list):
                return [r for r in records if isinstance(r, dict)]
        return []

    def reverse_ip(self, ip: str) -> list[dict[str, Any]]:
        """Return domains that resolve to *ip*."""
        resp = self.get(f"/v1/ips/{ip}/whois")
        if isinstance(resp, dict):
            records = resp.get("records", [])
            if isinstance(records, list):
                return [r for r in records if isinstance(r, dict)]
        return []

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a SecurityTrails record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("SecurityTrails to_stix expects a dict input")

        kind = native.get("_st_kind") or "observed-data"
        query = native.get("_st_query", "")
        now = utcnow()

        if kind == "domain-name":
            sub = native.get("subdomain") or native.get("hostname") or query
            fqdn = f"{sub}.{native.get('parent', '')}".rstrip(".") if native.get("parent") else sub
            stix_uuid = uuid.uuid5(_NAMESPACE_SECURITYTRAILS, f"domain-name|{fqdn}")
            return {
                "type": "domain-name",
                "id": f"domain-name--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "value": fqdn,
                "x_securitytrails": {"parent": native.get("parent"), "raw": native},
            }

        if kind == "ipv4-addr":
            ip = native.get("ip") or native.get("value") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_SECURITYTRAILS, f"ipv4-addr|{ip}")
            return {
                "type": "ipv4-addr",
                "id": f"ipv4-addr--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "value": ip,
                "x_securitytrails": {"raw": native},
            }

        # observed-data — historical DNS / WHOIS
        refs: list[str] = []
        if query:
            dom_uuid = uuid.uuid5(_NAMESPACE_SECURITYTRAILS, f"domain-name|{query}")
            refs.append(f"domain-name--{dom_uuid}")
        for value in native.get("values") or []:
            if isinstance(value, dict):
                ip = value.get("ip") or value.get("ipv4")
                if ip:
                    ip_uuid = uuid.uuid5(_NAMESPACE_SECURITYTRAILS, f"ipv4-addr|{ip}")
                    refs.append(f"ipv4-addr--{ip_uuid}")
        first = native.get("first_seen") or now
        last = native.get("last_seen") or first
        envelope = make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="securitytrails",
            x_extensions={
                "securitytrails_record_type": native.get("_st_record_type"),
                "securitytrails_raw": native,
            },
        )
        return envelope

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """SecurityTrails is read-only."""
        return {
            "note": (
                "SecurityTrails connector is read-only. Use domain_info, "
                "subdomains, historical_dns, historical_whois, search_domains, "
                "or reverse_ip to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
