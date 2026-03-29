"""
gnat.connectors.qualys_vmdr.client
==================================

Qualys VMDR (Vulnerability Management, Detection and Response) connector.

Authentication
--------------
Basic Auth (username + password) or API key/session (Qualys supports multiple methods).
Common pattern: Basic Auth with Qualys username/password.

    [qualys_vmdr]
    host     = https://qualysapi.qualys.com          # or your platform URL (e.g. qg2, qg3)
    username = <qualys-username>
    password = <qualys-password>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Qualys Resource                  |
+================+==================================+
| vulnerability  | KnowledgeBase vulns / detections |
+----------------+----------------------------------+
| report         | Scan results / asset findings    |
+----------------+----------------------------------+

Key Endpoints (API v2/v3 recommended — check current versioning)
------------------
* /api/2.0/fo/knowledge_base/vuln/     — vuln details
* /api/2.0/fo/asset/host/vm/detection/ — host detections
* /api/2.0/fo/scan/                    — scan management
* /api/3.0/fo/... (newer versions)

Notes
-----
* Primarily read-oriented for ingestion of vuln intel + asset context.
* Use action=list with filters for efficient pagination.
* Qualys returns XML by default in many legacy endpoints; request JSON where available or parse accordingly.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class QualysVMDRClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Qualys VMDR API.

    Parameters
    ----------
    host : str
        Qualys API base URL (e.g. "https://qualysapi.qualys.com").
    username : str
        Qualys username.
    password : str
        Qualys password (for Basic Auth).
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "knowledge_base/vuln",
        "report":        "asset/host/vm/detection",
    }

    def __init__(self, host: str = "https://qualysapi.qualys.com", username: str = "", password: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Basic Auth headers (Qualys common method)."""
        self._auth_headers["Authorization"] = self._basic_auth(self._username, self._password)
        self._auth_headers["Accept"] = "application/json"  # prefer JSON where supported
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight check via knowledge base or user info endpoint."""
        self.get("/api/2.0/fo/user/", params={"action": "list"})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        if stix_type == "vulnerability":
            return self.get("/api/2.0/fo/knowledge_base/vuln/", params={"action": "list", "ids": object_id})
        raise GNATClientError(f"get_object for {stix_type} not fully implemented yet in Qualys connector.")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        filters = dict(filters or {})
        if stix_type == "vulnerability":
            return self.fetch_vulnerabilities(
                severity=filters.pop("severity", None),
                qid=filters.pop("qid", None),
                limit=page_size,
            )
        # Default: asset detections / scan results as reports
        return self.fetch_detections(
            detection_severity=filters.pop("severity", None),
            limit=page_size,
        )

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError("Qualys VMDR connector is read-focused; write operations not supported here.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Qualys VMDR connector does not support deletion.")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def fetch_vulnerabilities(
        self,
        severity: Optional[str] = None,
        qid: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Fetch from KnowledgeBase (QIDs, severity, etc.)."""
        params: Dict[str, Any] = {"action": "list", "limit": limit}
        if severity:
            params["severity"] = severity
        if qid:
            params["ids"] = qid
        resp = self.get("/api/2.0/fo/knowledge_base/vuln/", params=params)
        # Qualys often wraps in XML/JSON structure — adjust parsing as needed
        return resp.get("VULN_LIST", {}).get("VULN", []) if isinstance(resp, dict) else []

    def fetch_detections(
        self,
        detection_severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Fetch host vulnerability detections."""
        params: Dict[str, Any] = {"action": "list", "limit": limit}
        if detection_severity:
            params["severity"] = detection_severity
        resp = self.get("/api/2.0/fo/asset/host/vm/detection/", params=params)
        return resp.get("HOST_LIST", {}).get("HOST", []) if isinstance(resp, dict) else []

    # ── STIX translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch vulnerability vs. detection/report."""
        if "QID" in native or "title" in native and "severity" in native:
            return self._vuln_to_stix(native)
        return self._detection_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "note": "Qualys VMDR is primarily read-only for this connector.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _vuln_to_stix(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        qid = vuln.get("QID", "")
        vuln_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'qid:{qid}')}"
        return {
            "type": "vulnerability",
            "id": vuln_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": vuln.get("TITLE", f"Qualys QID {qid}"),
            "description": vuln.get("DESCRIPTION", ""),
            "external_references": [{"source_name": "qualys", "external_id": qid}],
            "x_qualys": {
                "qid": qid,
                "severity": vuln.get("SEVERITY"),
                "cvss_score": vuln.get("CVSS"),
                "patchable": vuln.get("PATCHABLE"),
            },
        }

    def _detection_to_stix(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'detection:{detection.get("ID", "")}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Qualys VMDR Detection",
            "description": f"Host detection findings from Qualys scan.",
            "report_types": ["vulnerability-report"],
            "x_qualys": {
                "host_id": detection.get("ID"),
                "severity": detection.get("SEVERITY"),
                "raw": detection,
            },
        }