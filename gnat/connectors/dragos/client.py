# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dragos.client
===============================

Dragos Platform connector.

Dragos is a leading OT/ICS cybersecurity platform providing threat
intelligence, detection, and response for industrial control systems
and critical infrastructure environments.

Authentication
--------------
API key + secret pair using Basic auth or custom header scheme::

    [dragos]
    host       = https://portal.dragos.com
    api_key    = <your-dragos-api-key>
    api_secret = <your-dragos-api-secret>

The connector uses Basic authentication (Base64(api_key:api_secret)).

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | Dragos Resource                              |
+================+==============================================+
| threat-actor   | Activity Groups (ICS threat actors)          |
+----------------+----------------------------------------------+
| indicator      | Indicators of Compromise (IOCs)              |
+----------------+----------------------------------------------+
| malware        | Malware families / tools                     |
+----------------+----------------------------------------------+
| vulnerability  | CVE-based vulnerabilities                    |
+----------------+----------------------------------------------+
| report         | Intelligence reports / advisories            |
+----------------+----------------------------------------------+

Key Endpoints
-------------
* /api/v1/indicators           — IOC list/search
* /api/v1/activity-groups      — ICS threat actor groups
* /api/v1/products             — Intelligence products/reports
* /api/v1/threats              — Threat summaries
* /api/v1/vulnerabilities      — ICS/SCADA CVE data

References
----------
https://portal.dragos.com/api/v1/doc
"""

from __future__ import annotations

import base64
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f6a7b8c9-d0e1-2345-f012-456789012345")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class DragosClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Dragos Platform API v1.

    Parameters
    ----------
    host : str
        Base URL (default ``https://portal.dragos.com``).
    api_key : str
        Dragos API key.
    api_secret : str
        Dragos API secret.
    """

    stix_type_map: dict[str, str] = {
        "threat-actor": "activity-groups",
        "indicator": "indicators",
        "malware": "threats",
        "vulnerability": "vulnerabilities",
        "report": "products",
    }

    def __init__(
        self,
        host: str = "https://portal.dragos.com",
        api_key: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_secret = api_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Basic auth header (api_key:api_secret)."""
        credentials = base64.b64encode(f"{self._api_key}:{self._api_secret}".encode()).decode()
        self._auth_headers["Authorization"] = f"Basic {credentials}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping indicators endpoint."""
        self.get("/api/v1/indicators", params={"page_size": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Dragos object by STIX type and ID."""
        if stix_type == "indicator":
            return self.get(f"/api/v1/indicators/{object_id}")
        if stix_type == "threat-actor":
            return self.get(f"/api/v1/activity-groups/{object_id}")
        if stix_type == "malware":
            return self.get(f"/api/v1/threats/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/api/v1/vulnerabilities/{object_id}")
        if stix_type == "report":
            return self.get(f"/api/v1/products/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Dragos: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List Dragos objects by STIX type."""
        f = filters or {}
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        params.update(f)
        endpoint_map = {
            "indicator": "/api/v1/indicators",
            "threat-actor": "/api/v1/activity-groups",
            "malware": "/api/v1/threats",
            "vulnerability": "/api/v1/vulnerabilities",
            "report": "/api/v1/products",
        }
        endpoint = endpoint_map.get(stix_type)
        if not endpoint:
            raise GNATClientError(f"Unsupported STIX type for Dragos: {stix_type}")
        resp = self.get(endpoint, params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get(
            "indicators",
            resp.get(
                "activity_groups",
                resp.get(
                    "threats",
                    resp.get("vulnerabilities", resp.get("products", resp.get("data", []))),
                ),
            ),
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError("Dragos API is read-only — upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Dragos API is read-only — delete not supported.")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_indicators(
        self,
        indicator_type: str | None = None,
        value: str | None = None,
        updated_after: str | None = None,
        page_size: int = 500,
    ) -> list[dict[str, Any]]:
        """Fetch IOCs with optional type/value/date filters."""
        params: dict[str, Any] = {"page_size": page_size}
        if indicator_type:
            params["type"] = indicator_type
        if value:
            params["value"] = value
        if updated_after:
            params["updated_after"] = updated_after
        resp = self.get("/api/v1/indicators", params=params)
        return resp.get("indicators", []) if isinstance(resp, dict) else []

    def get_activity_groups(self, page_size: int = 50) -> list[dict[str, Any]]:
        """Fetch Dragos activity groups (ICS threat actors)."""
        resp = self.get("/api/v1/activity-groups", params={"page_size": page_size})
        return resp.get("activity_groups", []) if isinstance(resp, dict) else []

    def get_products(
        self,
        product_type: str | None = None,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch intelligence products (reports)."""
        params: dict[str, Any] = {"page_size": page_size}
        if product_type:
            params["type"] = product_type
        resp = self.get("/api/v1/products", params=params)
        return resp.get("products", []) if isinstance(resp, dict) else []

    def get_vulnerabilities(
        self,
        cve_id: str | None = None,
        severity: str | None = None,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch ICS/SCADA vulnerability data."""
        params: dict[str, Any] = {"page_size": page_size}
        if cve_id:
            params["cve_id"] = cve_id
        if severity:
            params["severity"] = severity
        resp = self.get("/api/v1/vulnerabilities", params=params)
        return resp.get("vulnerabilities", []) if isinstance(resp, dict) else []

    def get_threats(self, page_size: int = 50) -> list[dict[str, Any]]:
        """Fetch Dragos threat summaries."""
        resp = self.get("/api/v1/threats", params={"page_size": page_size})
        return resp.get("threats", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Dragos object to STIX."""
        # IOC
        if "value" in native and "indicator_type" in native:
            return self._ioc_to_stix(native)
        # Activity group / threat actor
        if "activity_group" in native or "group_name" in native:
            return self._actor_to_stix(native)
        # Vulnerability
        if "cve_id" in native:
            return self._vuln_to_stix(native)
        # Report / product
        if "executive_summary" in native or "serial" in native:
            return self._product_to_stix(native)
        # Malware / threat
        if "threat_name" in native or "malware_families" in native:
            return self._threat_to_stix(native)
        # Default: IOC
        return self._ioc_to_stix(native)

    def _ioc_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        ioc_id = str(native.get("id", ""))
        value = native.get("value", ioc_id)
        ioc_type = native.get("indicator_type", native.get("type", "domain")).lower()
        uid = str(_uuid.uuid5(_STIX_NS, f"dragos-ioc-{value}"))

        pattern_map = {
            "ip": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "md5": f"[file:hashes.MD5 = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "sha1": f"[file:hashes.SHA1 = '{value}']",
        }
        pattern = pattern_map.get(ioc_type, f"[domain-name:value = '{value}']")
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("first_seen", _now_ts()),
            "modified": native.get("last_updated", _now_ts()),
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "dragos",
            "x_dragos": {
                "indicator_type": ioc_type,
                "confidence": native.get("confidence", ""),
                "kill_chain": native.get("kill_chain", ""),
                "activity_groups": native.get("activity_groups", []),
            },
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        name = native.get("group_name", native.get("name", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"dragos-actor-{name}"))
        return {
            "type": "threat-actor",
            "id": f"threat-actor--{uid}",
            "name": name,
            "description": native.get("profile", native.get("description", ""))[:1000],
            "created": native.get("first_activity", _now_ts()),
            "modified": native.get("last_updated", _now_ts()),
            "threat_actor_types": ["nation-state"],
            "sophistication": "advanced",
            "x_source_platform": "dragos",
            "x_dragos": {
                "group_id": native.get("id", ""),
                "industries": native.get("target_industries", []),
                "countries": native.get("target_countries", []),
                "tools": native.get("tools", []),
            },
        }

    def _vuln_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        cve_id = native.get("cve_id", native.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"dragos-vuln-{cve_id}"))
        cvss = native.get("cvss_score", 0.0)
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": cve_id,
            "description": native.get("description", "")[:1000],
            "created": native.get("published_date", _now_ts()),
            "modified": native.get("updated_date", _now_ts()),
            "x_source_platform": "dragos",
            "x_dragos": {
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": native.get("severity", ""),
                "affected_products": native.get("affected_products", []),
                "patch_available": native.get("patch_available", False),
            },
        }

    def _product_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        serial = native.get("serial", native.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"dragos-product-{serial}"))
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": native.get("title", serial),
            "description": native.get("executive_summary", "")[:1000],
            "created": native.get("release_date", _now_ts()),
            "modified": native.get("updated_date", _now_ts()),
            "published": native.get("release_date", _now_ts()),
            "object_refs": [],
            "x_source_platform": "dragos",
            "x_dragos": {
                "serial": serial,
                "product_type": native.get("type", ""),
                "tlp": native.get("tlp", ""),
                "tags": native.get("tags", []),
            },
        }

    def _threat_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        name = native.get("threat_name", native.get("name", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"dragos-malware-{name}"))
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": name,
            "description": native.get("description", "")[:500],
            "is_family": True,
            "created": native.get("first_seen", _now_ts()),
            "modified": native.get("last_updated", _now_ts()),
            "x_source_platform": "dragos",
            "x_dragos": {
                "malware_families": native.get("malware_families", []),
                "capabilities": native.get("capabilities", []),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract Dragos query parameters from a STIX dict."""
        return {
            "stix_id": stix_dict.get("id", ""),
            "type": stix_dict.get("type", ""),
            "name": stix_dict.get("name", ""),
        }
