# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cloudflare_intel.client
===========================================

Cloudflare Threat Intelligence API connector.

Authentication
--------------
Bearer token (Cloudflare API Token) plus an ``account_id``.  Create an API
Token with the **Account → Intelligence: Read** permission and the target
account in scope::

    [cloudflare_intel]
    host       = https://api.cloudflare.com
    api_token  = cf_...
    account_id = 0000000000000000000000000000000000

STIX Type Mapping
-----------------
+----------------+-----------------------------------------------+
| STIX Type      | Cloudflare Intel endpoint                     |
+================+===============================================+
| indicator      | ``/intel/domain``, ``/intel/ip``              |
+----------------+-----------------------------------------------+
| infrastructure | ``/intel/asn``                                |
+----------------+-----------------------------------------------+
| observed-data  | ``/intel/domain-history``, ``/intel/dns``,    |
|                | ``/intel/whois``                              |
+----------------+-----------------------------------------------+

Notes
-----
* **Read-only** in Phase 1.  The ``/intel/miscategorization`` submission
  endpoint is a write operation and is not exposed.
* Cloudflare wraps every response in an envelope of the shape
  ``{"result": ..., "success": true, "errors": [], "messages": []}``.
  The connector unwraps ``result`` before returning data to callers.
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

# Deterministic UUID-5 namespace for Cloudflare-derived STIX ids.
_NAMESPACE_CLOUDFLARE = uuid.UUID("1c0ff1ed-cafe-4d00-9b1a-c10ada71a0fe")


class CloudflareIntelClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Cloudflare Threat Intelligence API.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.cloudflare.com"``.
    api_token : str
        Cloudflare API Token with the **Account → Intelligence: Read**
        permission on the target account.
    account_id : str
        Cloudflare account identifier (32-character hex string).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v4"
    API_PREFIX: str = "/client/v4"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "intel/domain",
        "infrastructure": "intel/asn",
        "observed-data": "intel/domain-history",
    }

    def __init__(
        self,
        host: str = "https://api.cloudflare.com",
        api_token: str = "",
        account_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize CloudflareIntelClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token
        self.account_id = account_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Authorization: Bearer header from the configured API token."""
        if not self.api_token:
            raise GNATClientError("Cloudflare Intel connector requires api_token in config.")
        if not self.account_id:
            raise GNATClientError("Cloudflare Intel connector requires account_id in config.")
        self._auth_headers["Authorization"] = f"Bearer {self.api_token}"
        self._auth_headers["Accept"] = "application/json"

    # ── Internal helpers ──────────────────────────────────────────────────

    def _intel_path(self, suffix: str) -> str:
        """Return ``/client/v4/accounts/{account_id}/intel/{suffix}``."""
        return f"/client/v4/accounts/{self.account_id}/intel/{suffix.lstrip('/')}"

    @staticmethod
    def _unwrap(resp: Any) -> Any:
        """Strip the Cloudflare ``{"result": ..., "success": true}`` envelope."""
        if isinstance(resp, dict) and "result" in resp:
            return resp["result"]
        return resp

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the account endpoint as a lightweight authenticated probe."""
        try:
            self.get(f"/client/v4/accounts/{self.account_id}")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single intel record.

        ``stix_type`` selects the endpoint:

        * ``"indicator"`` → ``/intel/domain?domain={id}`` for non-numeric
          ids, ``/intel/ip?ipv4={id}`` for IPv4 addresses
        * ``"infrastructure"`` → ``/intel/asn/{id}``
        * ``"observed-data"`` → ``/intel/whois?domain={id}``
        """
        if not object_id:
            raise GNATClientError("Cloudflare Intel get_object requires a non-empty id")

        if stix_type == "indicator":
            if _looks_like_ipv4(object_id):
                resp = self.get(self._intel_path("ip"), params={"ipv4": object_id})
            else:
                resp = self.get(self._intel_path("domain"), params={"domain": object_id})
        elif stix_type == "infrastructure":
            asn = object_id.upper().removeprefix("AS")
            resp = self.get(self._intel_path(f"asn/{asn}"))
        elif stix_type == "observed-data":
            resp = self.get(self._intel_path("whois"), params={"domain": object_id})
        else:
            raise GNATClientError(
                f"Cloudflare Intel get_object does not support stix_type={stix_type!r}"
            )

        data = self._unwrap(resp)
        if not isinstance(data, dict):
            raise GNATClientError(f"Cloudflare Intel returned unexpected payload for {object_id!r}")
        return dict(data, _cf_kind=stix_type, _cf_query=object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List intel records.

        ``filters`` keys:

        * ``domain`` — single-domain lookup (returned as a 1-element list)
        * ``ipv4`` — single-IP lookup
        * ``asn`` — ASN integer
        * ``whois`` — domain to WHOIS query (stix_type must be
          ``observed-data``)
        """
        filters = dict(filters or {})
        domain = filters.get("domain", "")
        ipv4 = filters.get("ipv4", "")
        asn = filters.get("asn", "")

        if stix_type == "indicator":
            if ipv4:
                return [self.get_object("indicator", ipv4)]
            if domain:
                return [self.get_object("indicator", domain)]
            raise GNATClientError(
                "Cloudflare Intel list_objects(indicator) requires a 'domain' or 'ipv4' filter"
            )
        if stix_type == "infrastructure":
            if not asn:
                raise GNATClientError(
                    "Cloudflare Intel list_objects(infrastructure) requires an 'asn' filter"
                )
            return [self.get_object("infrastructure", str(asn))]
        if stix_type == "observed-data":
            if ipv4:
                resp = self.get(self._intel_path("dns"), params={"ipv4": ipv4})
                data = self._unwrap(resp) or []
                if isinstance(data, dict):
                    data = [data]
                return [dict(d, _cf_kind="observed-data", _cf_query=ipv4) for d in data]
            if domain:
                resp = self.get(
                    self._intel_path("domain-history"),
                    params={"domain": domain},
                )
                data = self._unwrap(resp) or []
                if isinstance(data, dict):
                    data = [data]
                return [dict(d, _cf_kind="observed-data", _cf_query=domain) for d in data]
            raise GNATClientError(
                "Cloudflare Intel list_objects(observed-data) requires a 'domain' or 'ipv4' filter"
            )
        raise GNATClientError(
            f"Cloudflare Intel list_objects does not support stix_type={stix_type!r}"
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Cloudflare Intel connector is read-only."""
        raise GNATClientError(
            "Cloudflare Intel connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Cloudflare Intel connector is read-only."""
        raise GNATClientError(
            "Cloudflare Intel connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def get_domain_intel(self, domain: str) -> dict[str, Any]:
        """Return reputation, category, and risk metadata for *domain*."""
        return self.get_object("indicator", domain)

    def get_ip_intel(self, ipv4: str) -> dict[str, Any]:
        """Return reputation and risk metadata for an IPv4 address."""
        return self.get_object("indicator", ipv4)

    def get_asn_intel(self, asn: int | str) -> dict[str, Any]:
        """Return ASN metadata (organization, registrar, country)."""
        return self.get_object("infrastructure", str(asn))

    def get_whois(self, domain: str) -> dict[str, Any]:
        """Return WHOIS data for *domain*."""
        return self.get_object("observed-data", domain)

    def get_passive_dns(self, ipv4: str) -> list[dict[str, Any]]:
        """Return passive-DNS records observed for an IPv4 address."""
        return self.list_objects("observed-data", filters={"ipv4": ipv4})

    def get_domain_history(self, domain: str) -> list[dict[str, Any]]:
        """Return historical category / reputation transitions for *domain*."""
        return self.list_objects("observed-data", filters={"domain": domain})

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Cloudflare Intel record to a STIX 2.1 object.

        The shape of the record is inferred from the ``_cf_kind`` marker
        (set by ``get_object`` / ``list_objects``) or from the fields
        present in *native*.
        """
        if not isinstance(native, dict):
            raise GNATClientError("Cloudflare Intel to_stix expects a dict input")

        kind = native.get("_cf_kind")
        query = native.get("_cf_query", "")
        now = utcnow()

        # Indicator: domain or IP reputation
        if kind == "indicator" or "risk_score" in native or "risk_types" in native:
            if "ipv4" in native or _looks_like_ipv4(query):
                ip = native.get("ipv4") or query
                pattern = make_indicator_pattern("ipv4-addr", ip)
                key = ip
            else:
                dom = native.get("domain") or query
                pattern = make_indicator_pattern("domain-name", dom)
                key = dom
            stix_uuid = uuid.uuid5(_NAMESPACE_CLOUDFLARE, f"indicator|{key}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "name": f"Cloudflare Intel: {key}",
                "description": _cf_description(native),
                "labels": _cf_labels(native),
                "x_cloudflare": {
                    "risk_score": native.get("risk_score"),
                    "risk_types": native.get("risk_types", []),
                    "content_categories": native.get("content_categories", []),
                    "popularity_rank": native.get("popularity_rank"),
                    "application": native.get("application"),
                    "resolves_to_refs": native.get("resolves_to_refs", []),
                    "additional_information": native.get("additional_information"),
                },
            }

        # Infrastructure: ASN metadata
        if kind == "infrastructure" or "asn" in native or native.get("type") == "asn":
            asn_id = native.get("asn") or query or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_CLOUDFLARE, f"infrastructure|{asn_id}")
            return {
                "type": "infrastructure",
                "id": f"infrastructure--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "name": f"AS{asn_id}",
                "infrastructure_types": ["network"],
                "description": native.get("description") or native.get("name") or "",
                "x_cloudflare_asn": {
                    "asn": asn_id,
                    "country": native.get("country"),
                    "name": native.get("name"),
                    "description": native.get("description"),
                    "organization": native.get("organization"),
                    "type": native.get("type"),
                },
            }

        # Observed-data: WHOIS / passive DNS / domain history
        refs: list[str] = []
        if "ipv4" in native or _looks_like_ipv4(query):
            ip = native.get("ipv4") or query
            obs_uuid = uuid.uuid5(_NAMESPACE_CLOUDFLARE, f"ipv4-addr|{ip}")
            refs.append(f"ipv4-addr--{obs_uuid}")
        else:
            dom = native.get("domain") or query
            obs_uuid = uuid.uuid5(_NAMESPACE_CLOUDFLARE, f"domain-name|{dom}")
            refs.append(f"domain-name--{obs_uuid}")

        first = native.get("first_seen") or native.get("start") or now
        last = native.get("last_seen") or native.get("end") or now

        envelope = make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=1,
            object_refs=refs,
            source_name="cloudflare_intel",
            x_extensions={
                "cloudflare_whois": native if "registrar" in native else None,
                "cloudflare_pdns": native if "rrs" in native else None,
                "cloudflare_raw": native,
            },
        )
        return envelope

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Cloudflare Intel is read-only."""
        return {
            "note": (
                "Cloudflare Intel connector is read-only. Use "
                "get_domain_intel / get_ip_intel / get_asn_intel / "
                "get_whois / get_passive_dns to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


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


def _cf_description(native: dict[str, Any]) -> str:
    """Compose a short human description from a Cloudflare intel record."""
    score = native.get("risk_score")
    rtypes = native.get("risk_types", [])
    cats = native.get("content_categories", [])
    parts: list[str] = []
    if score is not None:
        parts.append(f"risk_score={score}")
    if rtypes:
        names = [(rt.get("name") if isinstance(rt, dict) else str(rt)) for rt in rtypes]
        parts.append("risk=" + ",".join(n for n in names if n))
    if cats:
        names = [(c.get("name") if isinstance(c, dict) else str(c)) for c in cats]
        parts.append("categories=" + ",".join(n for n in names if n))
    return "Cloudflare Intel: " + "; ".join(parts) if parts else "Cloudflare Intel"


def _cf_labels(native: dict[str, Any]) -> list[str]:
    """Choose STIX labels from a Cloudflare risk score."""
    score = native.get("risk_score")
    if isinstance(score, (int, float)) and score >= 50:
        return ["malicious-activity"]
    return ["benign"]
