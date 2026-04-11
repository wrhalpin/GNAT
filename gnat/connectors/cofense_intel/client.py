# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cofense_intel.client
========================================

Cofense Intelligence connector — human-verified phishing and malware
threat intel from the Cofense PhishMe reporting network and Triage
analyst workflow.

Authentication
--------------
HTTP Basic with username + password (Cofense ThreatHQ convention)::

    [cofense_intel]
    host     = https://www.threathq.com
    username = my-user
    password = my-password

Key endpoints
-------------
* ``GET /apiv1/threat/search`` — threat search by IOC type/value
* ``GET /apiv1/threat/{threat_id}`` — full threat record
* ``GET /apiv1/threat/updates`` — recently updated threats
* ``GET /apiv1/malware/families`` — malware family taxonomy

STIX Type Mapping
-----------------
* ``indicator``     → block-set IOCs (IP / domain / URL / hash)
* ``malware``       → malware families referenced by threats
* ``threat-actor``  → threat_groups referenced by threats
* ``report``        → full threat records (aggregate intel)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_COFENSE = uuid.UUID("c0fe3513-0001-4d1c-9b1e-c0fe35130fff")


class CofenseIntelClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Cofense Intelligence (ThreatHQ).

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://www.threathq.com"``.
    username : str
        Cofense ThreatHQ username.
    password : str
        Cofense ThreatHQ password.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/apiv1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "threat/search",
        "malware": "malware/families",
        "report": "threat",
        "threat-actor": "threat/actors",
    }

    def __init__(
        self,
        host: str = "https://www.threathq.com",
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize CofenseIntelClient."""
        super().__init__(host=host, **kwargs)
        self.username = username
        self.password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set HTTP Basic Authorization header from the configured creds."""
        if not self.username or not self.password:
            raise GNATClientError(
                "Cofense Intelligence connector requires username and password."
            )
        self._auth_headers["Authorization"] = self._basic_auth(
            self.username, self.password
        )
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Query ``/apiv1/malware/families`` as an authenticated probe."""
        try:
            self.get("/apiv1/malware/families", params={"page": 0, "resultsPerPage": 1})
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Cofense resource by id."""
        if not object_id:
            raise GNATClientError("Cofense get_object requires a non-empty id")
        if stix_type == "report":
            resp = self.get(f"/apiv1/threat/{object_id}")
            kind = "threat"
        elif stix_type == "malware":
            resp = self.get(f"/apiv1/malware/families/{object_id}")
            kind = "malware_family"
        else:
            raise GNATClientError(
                f"Cofense get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Cofense returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _cf_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Cofense threats / malware families / actors.

        ``filters`` keys (``indicator``):

        * ``ioc_type`` — ``"ipAddress"``, ``"domain"``, ``"url"``,
          ``"fileHash"``
        * ``value`` — value to search for
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {
            "page": max(0, int(page) - 1),
            "resultsPerPage": int(page_size),
        }

        if stix_type == "indicator":
            ioc_type = filters.get("ioc_type") or ""
            value = filters.get("value") or ""
            if ioc_type:
                params["type"] = ioc_type
            if value:
                params["value"] = value
            resp = self.get("/apiv1/threat/search", params=params)
            records = _extract_records(resp, ("data", "threats", "results"))
            return [dict(r, _cf_kind="indicator", _cf_ioc_type=ioc_type) for r in records]
        if stix_type == "report":
            # "recently updated threats"
            if filters.get("since"):
                params["timestamp"] = filters["since"]
            resp = self.get("/apiv1/threat/updates", params=params)
            records = _extract_records(resp, ("data", "threats", "results"))
            return [dict(r, _cf_kind="threat") for r in records]
        if stix_type == "malware":
            resp = self.get("/apiv1/malware/families", params=params)
            records = _extract_records(resp, ("data", "families", "results"))
            return [dict(r, _cf_kind="malware_family") for r in records]
        if stix_type == "threat-actor":
            resp = self.get("/apiv1/threat/actors", params=params)
            records = _extract_records(resp, ("data", "actors", "results"))
            return [dict(r, _cf_kind="actor") for r in records]
        raise GNATClientError(
            f"Cofense list_objects does not support stix_type={stix_type!r}"
        )

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Cofense Intelligence connector is read-only."""
        raise GNATClientError(
            "Cofense Intelligence connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Cofense Intelligence connector is read-only."""
        raise GNATClientError(
            "Cofense Intelligence connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def search_threats(
        self, ioc_type: str, value: str
    ) -> list[dict[str, Any]]:
        """Search Cofense for a specific IOC."""
        return self.list_objects(
            "indicator", filters={"ioc_type": ioc_type, "value": value}
        )

    def get_threat(self, threat_id: str) -> dict[str, Any]:
        """Fetch a single threat record."""
        return self.get_object("report", threat_id)

    def recent_threats(self, since: str = "") -> list[dict[str, Any]]:
        """Return recently updated threats."""
        filters: dict[str, Any] = {}
        if since:
            filters["since"] = since
        return self.list_objects("report", filters=filters, page_size=1000)

    def list_malware_families(self) -> list[dict[str, Any]]:
        """Return the Cofense malware family taxonomy."""
        return self.list_objects("malware", page_size=10_000)

    def list_actors(self) -> list[dict[str, Any]]:
        """Return the Cofense threat-actor taxonomy."""
        return self.list_objects("threat-actor", page_size=10_000)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Cofense record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("Cofense to_stix expects a dict input")

        kind = native.get("_cf_kind") or "threat"
        now = utcnow()

        if kind == "indicator":
            ioc_type = (native.get("_cf_ioc_type") or native.get("type", "")).lower()
            value = (
                native.get("value")
                or native.get("indicator")
                or native.get("ipAddress")
                or native.get("domain")
                or native.get("url")
                or native.get("hash", "")
            )
            if ioc_type in ("ipaddress", "ip"):
                pattern = make_indicator_pattern("ipv4-addr", value)
            elif ioc_type == "domain":
                pattern = make_indicator_pattern("domain-name", value)
            elif ioc_type == "url":
                pattern = make_indicator_pattern("url", value)
            elif ioc_type in ("filehash", "hash", "sha256"):
                pattern = make_indicator_pattern("file:sha256", value)
            else:
                pattern = f"[x-cofense:value = '{value}']"
            stix_uuid = uuid.uuid5(_NAMESPACE_COFENSE, f"indicator|{value}")
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": native.get("firstPublished") or now,
                "modified": native.get("lastUpdated") or now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": native.get("firstPublished") or now,
                "name": f"Cofense: {value}",
                "description": native.get("description") or "Cofense human-verified IOC",
                "labels": ["malicious-activity"],
                "confidence": native.get("confidence"),
                "x_cofense": {
                    "threat_id": native.get("threatId"),
                    "impact": native.get("impact"),
                    "malware_family": native.get("malwareFamily"),
                    "human_verified": True,
                    "raw": native,
                },
            }

        if kind == "malware_family":
            fam_id = native.get("id") or native.get("familyName") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_COFENSE, f"malware|{fam_id}")
            return {
                "type": "malware",
                "id": f"malware--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "name": native.get("familyName") or native.get("name") or str(fam_id),
                "is_family": True,
                "description": native.get("description") or "",
                "malware_types": native.get("malwareTypes") or ["unknown"],
                "x_cofense": {"raw": native},
            }

        if kind == "actor":
            actor_id = native.get("id") or native.get("name") or ""
            stix_uuid = uuid.uuid5(_NAMESPACE_COFENSE, f"threat-actor|{actor_id}")
            return {
                "type": "threat-actor",
                "id": f"threat-actor--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "name": native.get("name") or str(actor_id),
                "description": native.get("description") or "",
                "x_cofense": {"raw": native},
            }

        # Default — full threat record as STIX `report`
        threat_id = native.get("id") or native.get("threatId") or ""
        stix_uuid = uuid.uuid5(_NAMESPACE_COFENSE, f"report|{threat_id}")
        return {
            "type": "report",
            "id": f"report--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": native.get("firstPublished") or now,
            "modified": native.get("lastUpdated") or now,
            "name": native.get("label") or f"Cofense threat {threat_id}",
            "description": native.get("executiveSummary") or "",
            "published": native.get("firstPublished") or now,
            "report_types": ["threat-report"],
            "object_refs": [],
            "x_cofense": {
                "threat_id": threat_id,
                "impact": native.get("impact"),
                "campaigns": native.get("campaigns", []),
                "malware_family": native.get("malwareFamily"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Cofense Intelligence is read-only."""
        return {
            "note": (
                "Cofense Intelligence connector is read-only. Use "
                "search_threats, get_threat, recent_threats, "
                "list_malware_families, or list_actors to query ThreatHQ."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_records(resp: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    """Pull records out of a Cofense response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
    if isinstance(data, dict):
        for key in keys:
            val = data.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
    return []
