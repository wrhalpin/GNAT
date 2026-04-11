# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.domaintools.client
======================================

DomainTools Iris connector — WHOIS / passive DNS / domain pivoting.

Authentication
--------------
DomainTools requires both an ``api_username`` and an ``api_key``.  The
simplest supported mode is to append them as query parameters on every
request (the alternative is HMAC signing, which is not exposed by this
connector)::

    [domaintools]
    host         = https://api.domaintools.com
    api_username = my-username
    api_key      = dt_...

Key endpoints
-------------
* ``GET /v1/{domain}/whois`` — current WHOIS
* ``GET /v1/{domain}/whois/history`` — historical WHOIS snapshots
* ``GET /v1/iris-investigate/`` — Iris pivoting by domain / IP / email
* ``GET /v1/{domain}/hosting-history/`` — IP hosting history
* ``GET /v1/reverse-ip/{domain}/`` — shared-host reverse IP
* ``GET /v1/{domain}/reputation/`` — domain risk score

STIX Type Mapping
-----------------
* ``domain-name`` → current WHOIS lookups
* ``ipv4-addr`` → reverse-IP and hosting-history results
* ``observed-data`` → historical WHOIS / hosting history bundles

Notes
-----
* **Read-only.**  ``upsert_object`` / ``delete_object`` raise.
* The connector keeps ``api_username`` and ``api_key`` private; they are
  appended as query parameters by ``_auth_params`` on every request.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_DOMAINTOOLS = uuid.UUID("d0a17007-0d00-4a17-9e57-d0a17007ab1e")


class DomainToolsClient(BaseClient, ConnectorMixin):
    """
    HTTP client for DomainTools Iris.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.domaintools.com"``.
    api_username : str
        DomainTools API username.
    api_key : str
        DomainTools API key.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "domain-name": "whois",
        "ipv4-addr": "reverse-ip",
        "observed-data": "whois/history",
    }

    def __init__(
        self,
        host: str = "https://api.domaintools.com",
        api_username: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize DomainToolsClient."""
        super().__init__(host=host, **kwargs)
        self.api_username = api_username
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Validate credentials and stamp the JSON accept header."""
        if not self.api_username:
            raise GNATClientError(
                "DomainTools connector requires api_username in config."
            )
        if not self.api_key:
            raise GNATClientError(
                "DomainTools connector requires api_key in config."
            )
        self._auth_headers["Accept"] = "application/json"

    # ── Internal helpers ──────────────────────────────────────────────────

    def _auth_params(
        self, extra: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Return a params dict with DomainTools credentials appended."""
        params: dict[str, Any] = {
            "api_username": self.api_username,
            "api_key": self.api_key,
        }
        if extra:
            params.update(extra)
        return params

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping ``/v1/account/`` as an authenticated liveness probe."""
        try:
            self.get("/v1/account/", params=self._auth_params())
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single DomainTools record.

        ``stix_type`` values:

        * ``"domain-name"`` — current WHOIS for *object_id*
        * ``"observed-data"`` — historical WHOIS bundle
        """
        if not object_id:
            raise GNATClientError("DomainTools get_object requires a non-empty id")
        if stix_type == "domain-name":
            resp = self.get(f"/v1/{object_id}/whois", params=self._auth_params())
        elif stix_type == "observed-data":
            resp = self.get(
                f"/v1/{object_id}/whois/history", params=self._auth_params()
            )
        else:
            raise GNATClientError(
                f"DomainTools get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"DomainTools returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _dt_kind=stix_type, _dt_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List records from a DomainTools endpoint.

        ``filters`` keys:

        * ``domain`` — base domain (required for most endpoints)
        * ``query`` — Iris pivot query dict (when stix_type=``domain-name``)
        """
        filters = dict(filters or {})
        domain = filters.get("domain", "")

        if stix_type == "ipv4-addr":
            if not domain:
                raise GNATClientError(
                    "DomainTools list_objects(ipv4-addr) requires a 'domain' filter"
                )
            resp = self.get(
                f"/v1/reverse-ip/{domain}/", params=self._auth_params()
            )
            data = _extract_dt_results(resp)
            items = [
                dict(r, _dt_kind="ipv4-addr", _dt_query=domain) for r in data
            ]
        elif stix_type == "observed-data":
            if not domain:
                raise GNATClientError(
                    "DomainTools list_objects(observed-data) requires a 'domain' filter"
                )
            resp = self.get(
                f"/v1/{domain}/hosting-history/", params=self._auth_params()
            )
            data = _extract_dt_results(resp)
            items = [
                dict(r, _dt_kind="observed-data", _dt_query=domain) for r in data
            ]
        elif stix_type == "domain-name":
            iris_query = filters.get("query") or {}
            if not iris_query:
                raise GNATClientError(
                    "DomainTools list_objects(domain-name) requires a 'query' filter"
                )
            resp = self.get(
                "/v1/iris-investigate/",
                params=self._auth_params(iris_query),
            )
            data = _extract_dt_results(resp)
            items = [
                dict(r, _dt_kind="domain-name", _dt_query=domain) for r in data
            ]
        else:
            raise GNATClientError(
                f"DomainTools list_objects does not support stix_type={stix_type!r}"
            )

        start = max(0, (int(page) - 1) * int(page_size))
        return items[start : start + int(page_size)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """DomainTools connector is read-only."""
        raise GNATClientError(
            "DomainTools connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """DomainTools connector is read-only."""
        raise GNATClientError(
            "DomainTools connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def whois(self, domain: str) -> dict[str, Any]:
        """Return current WHOIS for *domain*."""
        return self.get_object("domain-name", domain)

    def whois_history(self, domain: str) -> dict[str, Any]:
        """Return historical WHOIS snapshots for *domain*."""
        return self.get_object("observed-data", domain)

    def iris_investigate(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Execute an Iris pivoting query."""
        return self.list_objects("domain-name", filters={"query": query})

    def reverse_ip(self, domain: str) -> list[dict[str, Any]]:
        """Return domains sharing an IP with *domain*."""
        return self.list_objects("ipv4-addr", filters={"domain": domain})

    def hosting_history(self, domain: str) -> list[dict[str, Any]]:
        """Return the IP hosting history bundle for *domain*."""
        return self.list_objects("observed-data", filters={"domain": domain})

    def reputation(self, domain: str) -> dict[str, Any]:
        """Return the domain reputation / risk score."""
        resp = self.get(
            f"/v1/{domain}/reputation/", params=self._auth_params()
        )
        if isinstance(resp, dict):
            return dict(resp, _dt_kind="observed-data", _dt_query=domain)
        return {}

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a DomainTools record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("DomainTools to_stix expects a dict input")

        kind = native.get("_dt_kind") or "observed-data"
        query = native.get("_dt_query", "")
        now = utcnow()

        if kind == "domain-name":
            domain = native.get("domain") or query
            stix_uuid = uuid.uuid5(_NAMESPACE_DOMAINTOOLS, f"domain-name|{domain}")
            return {
                "type": "domain-name",
                "id": f"domain-name--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "value": domain,
                "x_domaintools": {
                    "registrar": native.get("registrar"),
                    "registrant": native.get("registrant"),
                    "created": native.get("created") or native.get("create_date"),
                    "expires": native.get("expires") or native.get("expiration_date"),
                    "raw": native,
                },
            }

        if kind == "ipv4-addr":
            ip = native.get("ip") or native.get("ip_address") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_DOMAINTOOLS, f"ipv4-addr|{ip}")
            return {
                "type": "ipv4-addr",
                "id": f"ipv4-addr--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "value": ip,
                "x_domaintools": {
                    "reverse_domain": native.get("domain_name") or query,
                    "raw": native,
                },
            }

        # observed-data — hosting / whois history bundle
        refs: list[str] = []
        if query:
            dom_uuid = uuid.uuid5(_NAMESPACE_DOMAINTOOLS, f"domain-name|{query}")
            refs.append(f"domain-name--{dom_uuid}")
        for entry in native.get("ip_addresses") or native.get("ip") or []:
            ip_val = entry.get("ip") if isinstance(entry, dict) else entry
            if isinstance(ip_val, str) and ip_val:
                ip_uuid = uuid.uuid5(_NAMESPACE_DOMAINTOOLS, f"ipv4-addr|{ip_val}")
                refs.append(f"ipv4-addr--{ip_uuid}")

        first = (
            native.get("first_seen")
            or native.get("created_date")
            or native.get("create_date")
            or now
        )
        last = native.get("last_seen") or native.get("expiration_date") or first

        envelope = make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="domaintools",
            x_extensions={"domaintools_raw": native},
        )
        return envelope

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """DomainTools is read-only."""
        return {
            "note": (
                "DomainTools connector is read-only. Use whois, whois_history, "
                "iris_investigate, reverse_ip, hosting_history, or reputation "
                "to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_dt_results(resp: Any) -> list[dict[str, Any]]:
    """Pull the list of records out of a DomainTools response envelope."""
    if not isinstance(resp, dict):
        return []
    response = resp.get("response") or resp
    if isinstance(response, dict):
        for key in ("ip_addresses", "ip", "results", "records", "hosting_history"):
            val = response.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
    return []
