"""
gnat.connectors.tanium.client
==============================

Tanium Platform connector.

Tanium is an endpoint management and security platform that provides
real-time endpoint visibility, threat hunting, incident response, and
vulnerability management at scale.

Authentication
--------------
Session token obtained via API token or username/password::

    [tanium]
    host      = https://tanium.corp.example.com
    api_key   = <your-tanium-api-token>

OR::

    [tanium]
    host     = https://tanium.corp.example.com
    username = admin
    password = your_password_here

The connector uses the ``session`` token approach with the Tanium
REST API (v2).

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | Tanium Resource                              |
+================+==============================================+
| indicator      | Threat Response / IOC alerts                 |
+----------------+----------------------------------------------+
| vulnerability  | Comply findings / CVE data                   |
+----------------+----------------------------------------------+
| report         | Threat Response incidents / alerts           |
+----------------+----------------------------------------------+

Key Endpoints
-------------
* /plugin/products/threat-response/api/v1/alerts     — TR alerts
* /plugin/products/threat-response/api/v1/intel      — Intel docs (IOCs)
* /plugin/products/comply/api/v1/findings            — Comply CVE findings
* /api/v2/endpoints                                  — Endpoint inventory
* /api/v2/questions                                  — Tanium questions (live Q&A)

References
----------
https://docs.tanium.com/rest_api/rest_api/overview.html
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TaniumClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Tanium REST API v2.

    Parameters
    ----------
    host : str
        Tanium server base URL.
    api_key : str
        Tanium API token (preferred).
    username : str
        Username for session-based auth (fallback).
    password : str
        Password for session-based auth (fallback).
    """

    stix_type_map: dict[str, str] = {
        "indicator":     "intel",
        "vulnerability": "findings",
        "report":        "alerts",
    }

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Authenticate with Tanium using API token or session login."""
        if self._api_key:
            self._auth_headers["session"] = self._api_key
        elif self._username and self._password:
            resp = self.post(
                "/api/v2/session/login",
                json={"username": self._username, "password": self._password},
            )
            if not isinstance(resp, dict):
                raise GNATClientError("Tanium: authentication failed — invalid response")
            token = resp.get("data", {}).get("session", "")
            if not token:
                raise GNATClientError("Tanium: failed to obtain session token")
            self._auth_headers["session"] = token
        else:
            raise GNATClientError("Tanium: provide api_key or username/password")

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping Tanium server info endpoint."""
        self.get("/api/v2/server_info")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Tanium object by type and ID."""
        if stix_type == "indicator":
            return self.get(
                f"/plugin/products/threat-response/api/v1/intel/{object_id}"
            )
        if stix_type == "report":
            return self.get(
                f"/plugin/products/threat-response/api/v1/alerts/{object_id}"
            )
        if stix_type == "vulnerability":
            resp = self.get(
                "/plugin/products/comply/api/v1/findings",
                params={"cveId": object_id},
            )
            data = resp.get("data", []) if isinstance(resp, dict) else []
            return data[0] if data else {}
        raise GNATClientError(f"Unsupported STIX type for Tanium: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List Tanium objects by STIX type."""
        f = filters or {}
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        params.update(f)
        if stix_type == "indicator":
            resp = self.get(
                "/plugin/products/threat-response/api/v1/intel", params=params
            )
        elif stix_type == "report":
            resp = self.get(
                "/plugin/products/threat-response/api/v1/alerts", params=params
            )
        elif stix_type == "vulnerability":
            resp = self.get(
                "/plugin/products/comply/api/v1/findings", params=params
            )
        else:
            raise GNATClientError(f"Unsupported STIX type for Tanium: {stix_type}")
        if not isinstance(resp, dict):
            return []
        return resp.get("data", resp.get("items", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update a Tanium intel document."""
        if stix_type == "indicator":
            resp = self.post(
                "/plugin/products/threat-response/api/v1/intel", json=payload
            )
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"Tanium: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a Tanium intel document."""
        if stix_type == "indicator":
            self.delete(
                f"/plugin/products/threat-response/api/v1/intel/{object_id}"
            )
            return
        raise GNATClientError(
            f"Tanium: delete not supported for STIX type '{stix_type}'"
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def ask_question(self, question_text: str) -> dict[str, Any]:
        """Ask a Tanium live question and return results."""
        payload = {"query_text": question_text}
        resp = self.post("/api/v2/questions", json=payload)
        return resp if isinstance(resp, dict) else {}

    def get_endpoints(
        self, count: int = 100, filter_text: str | None = None
    ) -> list[dict[str, Any]]:
        """List managed endpoints."""
        params: dict[str, Any] = {"count": count}
        if filter_text:
            params["filter"] = filter_text
        resp = self.get("/api/v2/endpoints", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("data", {}).get("endpoints", [])

    def get_comply_findings(
        self,
        cve_id: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch Comply CVE findings."""
        params: dict[str, Any] = {"limit": limit}
        if cve_id:
            params["cveId"] = cve_id
        if severity:
            params["severity"] = severity
        resp = self.get("/plugin/products/comply/api/v1/findings", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_threat_response_alerts(
        self,
        state: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch Threat Response alerts."""
        params: dict[str, Any] = {"limit": limit}
        if state:
            params["state"] = state
        resp = self.get(
            "/plugin/products/threat-response/api/v1/alerts", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def deploy_action(self, package_name: str, target_filter: str) -> dict[str, Any]:
        """Deploy a Tanium action/package to endpoints."""
        payload = {
            "package_spec": {"name": package_name},
            "target": {"sensor_and_filter": {"sensor": {"name": "Computer Name"},
                                              "filter": target_filter}},
        }
        resp = self.post("/api/v2/actions", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Tanium object to STIX."""
        # Comply finding → vulnerability
        if "cveId" in native or "cvss" in native:
            return self._finding_to_stix(native)
        # Intel doc → indicator
        intel_types = ("openioc", "stix", "yara", "hash")
        if (
            "intelDocId" in native
            or "iocs" in native
            or ("type" in native and native.get("type") in intel_types)
        ):
            return self._intel_to_stix(native)
        # Alert → report
        return self._alert_to_stix(native)

    def _finding_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        cve_id = native.get("cveId", native.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"tanium-vuln-{cve_id}"))
        cvss = native.get("cvss", {})
        score = cvss.get("score", 0.0) if isinstance(cvss, dict) else 0.0
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": cve_id,
            "description": native.get("summary", "")[:1000],
            "created": native.get("publishedAt", _now_ts()),
            "modified": native.get("modifiedAt", _now_ts()),
            "x_source_platform": "tanium",
            "x_tanium": {
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": native.get("severity", ""),
                "affected_count": native.get("affectedSystemsCount", 0),
            },
        }

    def _intel_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        doc_id = str(native.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"tanium-intel-{doc_id}"))
        name = native.get("name", doc_id)
        iocs = native.get("iocs", [])
        # Build pattern from first IOC if available
        pattern = f"[domain-name:value = '{name}']"
        if iocs:
            first = iocs[0] if isinstance(iocs, list) else {}
            ioc_type = first.get("type", "")
            ioc_val = first.get("value", "")
            if ioc_type == "md5_hash":
                pattern = f"[file:hashes.MD5 = '{ioc_val}']"
            elif ioc_type == "sha256_hash":
                pattern = f"[file:hashes.'SHA-256' = '{ioc_val}']"
            elif ioc_type == "ip_address":
                pattern = f"[ipv4-addr:value = '{ioc_val}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{ioc_val}']"
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("createdAt", _now_ts()),
            "modified": native.get("updatedAt", _now_ts()),
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "tanium",
            "x_tanium": {
                "intel_doc_id": doc_id,
                "doc_type": native.get("type", ""),
                "ioc_count": len(iocs),
            },
        }

    def _alert_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        alert_id = str(native.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"tanium-alert-{alert_id}"))
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": native.get("name", f"Tanium Alert {alert_id}"),
            "description": native.get("details", "")[:500],
            "created": native.get("createdAt", _now_ts()),
            "modified": native.get("updatedAt", _now_ts()),
            "published": native.get("createdAt", _now_ts()),
            "object_refs": [],
            "x_source_platform": "tanium",
            "x_tanium": {
                "alert_id": alert_id,
                "state": native.get("state", ""),
                "severity": native.get("severity", ""),
                "computer_name": native.get("computerName", ""),
                "intel_doc_id": native.get("intelDocId", ""),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX dict to a Tanium intel document payload."""
        import re
        pattern = stix_dict.get("pattern", "")
        value_match = re.search(r"= '([^']+)'", pattern)
        value = value_match.group(1) if value_match else stix_dict.get("name", "")
        ioc_type = "domain"
        if "ipv4-addr" in pattern:
            ioc_type = "ip_address"
        elif "SHA-256" in pattern:
            ioc_type = "sha256_hash"
        elif "MD5" in pattern:
            ioc_type = "md5_hash"
        return {
            "name": stix_dict.get("name", value),
            "type": "stix",
            "iocs": [{"type": ioc_type, "value": value}],
            "stix_id": stix_dict.get("id", ""),
        }
