"""
gnat.connectors.trendmicro_visionone.client
============================================

Trend Micro Vision One (XDR) connector.

Vision One provides cross-layer detection and response across endpoint,
email, network, and cloud workloads via a unified XDR platform.

Authentication
--------------
Bearer token (API key) sent as ``Authorization: Bearer <token>`` header::

    [trendmicro_visionone]
    host      = https://api.xdr.trendmicro.com
    token     = <your-vision-one-api-key>
    auth_type = token

Generate the token in Vision One Console under
Administration → API Keys.

STIX Type Mapping
-----------------
+----------------+-------------------------------------------+
| STIX Type      | Vision One Resource                       |
+================+===========================================+
| indicator      | Observed Attack Techniques / IOCs         |
+----------------+-------------------------------------------+
| malware        | Sandbox Analysis / Threat Intelligence    |
+----------------+-------------------------------------------+
| vulnerability  | Risk Insights / Vulnerability data        |
+----------------+-------------------------------------------+
| report         | Workbench Alerts / Incident reports       |
+----------------+-------------------------------------------+

Key Endpoints
-------------
* /v3.0/workbench/alerts           — XDR workbench alerts
* /v3.0/threatintel/iocFilters     — IOC filter/search
* /v3.0/sandbox/analysisResults    — Sandbox results
* /v3.0/eiqs/endpoints             — Endpoint queries (EIQS)
* /v3.0/assetProtection/alerts     — Risk insights

References
----------
https://automation.trendmicro.com/xdr/api-v3
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TrendMicroVisionOneClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Trend Micro Vision One API v3.

    Parameters
    ----------
    host : str
        Base URL (default ``https://api.xdr.trendmicro.com``).
    token : str
        Vision One API key.
    """

    stix_type_map: dict[str, str] = {
        "indicator":     "iocFilters",
        "malware":       "analysisResults",
        "vulnerability": "alerts",
        "report":        "workbench/alerts",
    }

    def __init__(
        self,
        host: str = "https://api.xdr.trendmicro.com",
        token: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._token}"
        self._auth_headers["Content-Type"] = "application/json;charset=utf-8"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping workbench alerts endpoint."""
        self.get("/v3.0/workbench/alerts", params={"top": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Vision One object by STIX type and ID."""
        if stix_type == "report":
            return self.get(f"/v3.0/workbench/alerts/{object_id}")
        if stix_type == "indicator":
            resp = self.get("/v3.0/threatintel/iocFilters", params={"id": object_id})
            items = resp.get("items", []) if isinstance(resp, dict) else []
            return items[0] if items else {}
        if stix_type == "malware":
            return self.get(f"/v3.0/sandbox/analysisResults/{object_id}")
        if stix_type == "vulnerability":
            return self.get(f"/v3.0/assetProtection/alerts/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for Vision One: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List Vision One objects by STIX type."""
        f = filters or {}
        params: dict[str, Any] = {"top": page_size, "skip": (page - 1) * page_size}
        params.update(f)
        if stix_type == "report":
            resp = self.get("/v3.0/workbench/alerts", params=params)
        elif stix_type == "indicator":
            resp = self.get("/v3.0/threatintel/iocFilters", params=params)
        elif stix_type == "malware":
            resp = self.get("/v3.0/sandbox/analysisResults", params=params)
        else:
            resp = self.get("/v3.0/assetProtection/alerts", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("items", resp.get("data", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update an IOC filter or custom object."""
        if stix_type == "indicator":
            resp = self.post("/v3.0/threatintel/iocFilters", json=payload)
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"Vision One: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an IOC filter."""
        if stix_type == "indicator":
            self.delete(f"/v3.0/threatintel/iocFilters/{object_id}")
            return
        raise GNATClientError(
            f"Vision One: delete not supported for STIX type '{stix_type}'"
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_alerts(
        self,
        start_date_time: str | None = None,
        severity: str | None = None,
        top: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch Workbench XDR alerts."""
        params: dict[str, Any] = {"top": top}
        if start_date_time:
            params["startDateTime"] = start_date_time
        if severity:
            params["severity"] = severity
        resp = self.get("/v3.0/workbench/alerts", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def search_iocs(
        self,
        ioc_type: str | None = None,
        value: str | None = None,
        top: int = 50,
    ) -> list[dict[str, Any]]:
        """Search IOC filters."""
        params: dict[str, Any] = {"top": top}
        if ioc_type:
            params["type"] = ioc_type
        if value:
            params["value"] = value
        resp = self.get("/v3.0/threatintel/iocFilters", params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    def submit_sandbox(self, file_url: str, file_type: str = "auto") -> dict[str, Any]:
        """Submit a file URL for sandbox analysis."""
        payload = {"url": file_url, "fileType": file_type}
        resp = self.post("/v3.0/sandbox/files/analyze", json=payload)
        return resp if isinstance(resp, dict) else {}

    def get_sandbox_result(self, task_id: str) -> dict[str, Any]:
        """Retrieve sandbox analysis result."""
        return self.get(f"/v3.0/sandbox/analysisResults/{task_id}")

    def isolate_endpoint(self, agent_guid: str) -> dict[str, Any]:
        """Isolate an endpoint by agent GUID."""
        resp = self.post(
            "/v3.0/response/endpoints/isolate",
            json={"agentGuid": agent_guid},
        )
        return resp if isinstance(resp, dict) else {}

    def restore_endpoint(self, agent_guid: str) -> dict[str, Any]:
        """Restore an isolated endpoint."""
        resp = self.post(
            "/v3.0/response/endpoints/restore",
            json={"agentGuid": agent_guid},
        )
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Vision One alert or IOC object to STIX."""
        obj_type = native.get("type", "")

        # IOC object
        if "value" in native or obj_type in ("domain", "ip", "url", "fileSha256"):
            return self._ioc_to_stix(native)

        # Sandbox result
        if "threatClassification" in native or "riskLevel" in native:
            return self._sandbox_to_stix(native)

        # Default: workbench alert → report
        return self._alert_to_stix(native)

    def _alert_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        alert_id = native.get("id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"visionone-alert-{alert_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        sev = native.get("severity", "medium").lower()
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": native.get("description", f"Vision One Alert {alert_id}"),
            "description": native.get("detail", ""),
            "created": native.get("createdDateTime", _now_ts()),
            "modified": native.get("updatedDateTime", _now_ts()),
            "published": native.get("createdDateTime", _now_ts()),
            "object_refs": [],
            "confidence": severity_map.get(sev, 50),
            "x_source_platform": "trendmicro_visionone",
            "x_visionone": {
                "alert_id": alert_id,
                "severity": native.get("severity", ""),
                "status": native.get("status", ""),
                "model": native.get("model", ""),
                "score": native.get("score", 0),
            },
        }

    def _ioc_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        ioc_id = native.get("id", "")
        value = native.get("value", ioc_id)
        ioc_type = native.get("type", "domain").lower()
        uid = str(_uuid.uuid5(_STIX_NS, f"visionone-ioc-{value}"))

        pattern_map = {
            "ip":          f"[ipv4-addr:value = '{value}']",
            "domain":      f"[domain-name:value = '{value}']",
            "url":         f"[url:value = '{value}']",
            "fileSha256":  f"[file:hashes.'SHA-256' = '{value}']",
            "fileSha1":    f"[file:hashes.SHA1 = '{value}']",
            "fileMd5":     f"[file:hashes.MD5 = '{value}']",
        }
        pattern = pattern_map.get(ioc_type, f"[domain-name:value = '{value}']")
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("lastModifiedDateTime", _now_ts()),
            "modified": native.get("lastModifiedDateTime", _now_ts()),
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "trendmicro_visionone",
            "x_visionone": {
                "ioc_type": ioc_type,
                "notes": native.get("notes", ""),
                "risk_level": native.get("riskLevel", ""),
            },
        }

    def _sandbox_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        task_id = native.get("id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"visionone-sandbox-{task_id}"))
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": native.get("displayName", task_id),
            "is_family": False,
            "created": native.get("createdDateTime", _now_ts()),
            "modified": native.get("createdDateTime", _now_ts()),
            "x_source_platform": "trendmicro_visionone",
            "x_visionone": {
                "risk_level": native.get("riskLevel", ""),
                "threat_classification": native.get("threatClassification", ""),
                "analysis_completion": native.get("analysisCompletionDateTime", ""),
                "detection_names": native.get("detectionNames", []),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX dict to a Vision One IOC filter payload."""
        import re
        pattern = stix_dict.get("pattern", "")
        value_match = re.search(r"= '([^']+)'", pattern)
        value = value_match.group(1) if value_match else stix_dict.get("name", "")
        ioc_type = "domain"
        if "ipv4-addr" in pattern:
            ioc_type = "ip"
        elif "url:value" in pattern:
            ioc_type = "url"
        elif "SHA-256" in pattern:
            ioc_type = "fileSha256"
        elif "SHA1" in pattern:
            ioc_type = "fileSha1"
        elif "MD5" in pattern:
            ioc_type = "fileMd5"
        return {
            "type": ioc_type,
            "value": value,
            "notes": stix_dict.get("description", ""),
            "stix_id": stix_dict.get("id", ""),
        }
