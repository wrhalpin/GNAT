"""
gnat.connectors.trellix.client
================================

Trellix XDR / ePolicy Orchestrator (ePO) connector.

Authentication
--------------
OAuth2 client-credentials flow::

    [trellix]
    host          = https://api.manage.trellix.com
    client_id     = <client-id>
    client_secret = <client-secret>
    iam_url       = https://iam.mcafee-cloud.com   ; optional, defaults to this value

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Trellix Resource                 |
+================+==================================+
| indicator      | Threats / IOCs                   |
+----------------+----------------------------------+
| malware        | Detections                       |
+----------------+----------------------------------+
| vulnerability  | Vulnerabilities                  |
+----------------+----------------------------------+

Key Endpoints (Trellix MVISION API)
------------------------------------
* /mvision/detection-service/api/v1/threats  — List threats/detections
* /mvision/epo/api/v2/iocs                   — Threat Intelligence IOCs
* /mvision/epo/api/v2/vulnerabilities        — Vulnerability findings
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
_DEFAULT_IAM = "https://iam.mcafee-cloud.com"


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TrellixClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Trellix XDR / ePO REST API (MVISION).

    Parameters
    ----------
    host : str
        Trellix API base URL (e.g. ``"https://api.manage.trellix.com"``).
    client_id : str
        OAuth2 client ID.
    client_secret : str
        OAuth2 client secret.
    iam_url : str
        IAM token endpoint base URL.  Defaults to ``"https://iam.mcafee-cloud.com"``.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "iocs",
        "malware": "detections",
        "vulnerability": "vulnerabilities",
    }

    def __init__(
        self,
        host: str = "https://api.manage.trellix.com",
        client_id: str = "",
        client_secret: str = "",
        iam_url: str = _DEFAULT_IAM,
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._iam_url = iam_url.rstrip("/")

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Exchange client credentials for an OAuth2 Bearer token via Trellix IAM."""
        resp = self.post(
            "/iam/v1.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "soc.act.tie",
            },
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("Trellix: failed to obtain OAuth2 access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight ping via threats list endpoint."""
        self.get("/mvision/detection-service/api/v1/threats", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single threat, IOC, or vulnerability by ID."""
        if stix_type == "indicator":
            resp = self.get(f"/mvision/epo/api/v2/iocs/{object_id}")
            return resp.get("data", {}) if isinstance(resp, dict) else {}
        if stix_type == "malware":
            resp = self.get(f"/mvision/detection-service/api/v1/threats/{object_id}")
            return resp.get("data", {}) if isinstance(resp, dict) else {}
        if stix_type == "vulnerability":
            resp = self.get(f"/mvision/epo/api/v2/vulnerabilities/{object_id}")
            return resp.get("data", {}) if isinstance(resp, dict) else {}
        raise GNATClientError(f"Trellix: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "indicator",
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List threats, IOCs, or vulnerabilities with optional filters."""
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)

        if stix_type == "indicator":
            resp = self.get("/mvision/epo/api/v2/iocs", params=params)
        elif stix_type == "malware":
            resp = self.get("/mvision/detection-service/api/v1/threats", params=params)
        elif stix_type == "vulnerability":
            resp = self.get("/mvision/epo/api/v2/vulnerabilities", params=params)
        else:
            raise GNATClientError(f"Trellix: unsupported STIX type '{stix_type}'")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update an IOC in Trellix TIE."""
        if stix_type != "indicator":
            raise GNATClientError(
                f"Trellix: upsert only supported for 'indicator', got '{stix_type}'"
            )
        resp = self.post("/mvision/epo/api/v2/iocs", json={"data": payload})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an IOC by ID."""
        if stix_type != "indicator":
            raise GNATClientError("Trellix: delete only supported for 'indicator'")
        self.delete(f"/mvision/epo/api/v2/iocs/{object_id}")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_threats(
        self,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List active detections from Trellix XDR.

        Parameters
        ----------
        severity : str, optional
            Filter by severity (e.g. ``"HIGH"``, ``"CRITICAL"``).
        limit : int
            Maximum records to return.
        """
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        resp = self.get("/mvision/detection-service/api/v1/threats", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def list_iocs(
        self,
        ioc_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Threat Intelligence IOCs from Trellix TIE.

        Parameters
        ----------
        ioc_type : str, optional
            Filter by IOC type (e.g. ``"ip"``, ``"domain"``, ``"hash"``).
        limit : int
            Maximum records to return.
        """
        params: dict[str, Any] = {"limit": limit}
        if ioc_type:
            params["type"] = ioc_type
        resp = self.get("/mvision/epo/api/v2/iocs", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def list_vulnerabilities(self, limit: int = 100) -> list[dict[str, Any]]:
        """List vulnerability findings from Trellix ePO."""
        resp = self.get("/mvision/epo/api/v2/vulnerabilities", params={"limit": limit})
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Trellix threat/IOC/vulnerability to a STIX 2.1 object."""
        native_type = native.get("type", "")
        if native_type in ("sha256", "md5", "sha1", "ip", "domain", "url"):
            return self._ioc_to_stix(native)
        if "cve_id" in native or "cvss_score" in native or "cvss" in native:
            return self._vuln_to_stix(native)
        return self._threat_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX indicator to a Trellix IOC payload."""
        name = stix_dict.get("name", "")
        pattern = stix_dict.get("pattern", "")
        return {
            "type": stix_dict.get("x_trellix_ioc_type", "domain"),
            "value": name,
            "pattern": pattern,
            "confidence": stix_dict.get("confidence", 50),
            "action": "block",
        }

    def _ioc_to_stix(self, ioc: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        ioc_id = str(ioc.get("id", ""))
        value = ioc.get("value", "")
        ioc_type = ioc.get("type", "domain")
        type_map = {
            "ip": "ipv4-addr:value",
            "domain": "domain-name:value",
            "url": "url:value",
            "md5": "file:hashes.MD5",
            "sha256": "file:hashes.'SHA-256'",
            "sha1": "file:hashes.'SHA-1'",
        }
        stix_prop = type_map.get(ioc_type, "domain-name:value")
        return {
            "type": "indicator",
            "id": f"indicator--{_uuid.uuid5(_STIX_NS, f'trellix:{ioc_id}')}",
            "spec_version": "2.1",
            "created": ioc.get("created_at", now),
            "modified": ioc.get("updated_at", now),
            "name": value,
            "description": ioc.get("description", ""),
            "pattern": f"[{stix_prop} = '{value}']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "confidence": ioc.get("confidence", 50),
            "x_trellix_ioc_type": ioc_type,
        }

    def _threat_to_stix(self, threat: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        tid = str(threat.get("id", ""))
        return {
            "type": "malware",
            "id": f"malware--{_uuid.uuid5(_STIX_NS, f'trellix:{tid}')}",
            "spec_version": "2.1",
            "created": threat.get("detected_at", now),
            "modified": threat.get("updated_at", now),
            "name": threat.get("name", "Unknown Trellix Threat"),
            "description": threat.get("description", ""),
            "malware_types": [threat.get("category", "unknown")],
            "is_family": False,
            "x_trellix": {
                "threat_id": tid,
                "severity": threat.get("severity"),
                "status": threat.get("status"),
                "host": threat.get("host_name"),
            },
        }

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        now = _now_ts()
        vid = str(vuln.get("id", ""))
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{_uuid.uuid5(_STIX_NS, f'trellix:{vid}')}",
            "spec_version": "2.1",
            "created": vuln.get("published_at", now),
            "modified": vuln.get("updated_at", now),
            "name": vuln.get("cve_id", vuln.get("name", "Trellix Vulnerability")),
            "description": vuln.get("description", ""),
            "external_references": [
                {"source_name": "trellix", "external_id": vid},
            ],
            "x_trellix": {
                "vuln_id": vid,
                "cvss_score": vuln.get("cvss_score"),
                "severity": vuln.get("severity"),
            },
        }
