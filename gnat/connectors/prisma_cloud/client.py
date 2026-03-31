"""
gnat.connectors.prisma_cloud.client
======================================

Palo Alto Networks Prisma Cloud connector.

Prisma Cloud is a cloud-native security platform covering Cloud Security
Posture Management (CSPM), Cloud Workload Protection (CWP), Cloud
Infrastructure Entitlement Management (CIEM), and Data Security.

Authentication
--------------
JWT token obtained by posting access key ID + secret key to ``/login``::

    [prisma_cloud]
    host              = https://api.prismacloud.io
    access_key_id     = <access key ID>
    secret_key        = <secret key>
    auth_type         = api_key

The token expires after ~10 minutes; this connector re-authenticates
automatically on 401 responses.

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | Prisma Cloud Resource                        |
+================+==============================================+
| indicator      | alerts (policy violations / anomalies)       |
+----------------+----------------------------------------------+
| vulnerability  | vulnerabilities (CVEs in container images)   |
+----------------+----------------------------------------------+
| report         | compliance posture reports                   |
+----------------+----------------------------------------------+

Key Endpoints
-------------
* POST /login                        — Obtain JWT
* GET  /alert/v2/alert               — List alerts
* POST /alert/v2/alert               — Filter/search alerts
* GET  /v2/vulnerability/assets      — Container CVEs
* GET  /compliance/posture           — Compliance posture
* GET  /policy/v2/policy             — List security policies
* GET  /resource/scan_info           — Cloud resource scan info

References
----------
https://pan.dev/prisma-cloud/api/cspm/
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c2d3e4f5-a6b7-8901-bcde-f01234567890")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class PrismaCloudClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Palo Alto Prisma Cloud CSPM/CWP APIs.

    Parameters
    ----------
    host : str
        Prisma Cloud API base URL (e.g. ``https://api.prismacloud.io``).
    access_key_id : str
        Prisma Cloud access key ID.
    secret_key : str
        Prisma Cloud secret key.
    """

    stix_type_map: dict[str, str] = {
        "indicator":     "alert",
        "vulnerability": "vulnerability",
        "report":        "compliance",
    }

    def __init__(
        self,
        host: str = "https://api.prismacloud.io",
        access_key_id: str = "",
        secret_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._access_key_id = access_key_id
        self._secret_key = secret_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """POST /login to obtain a JWT and set the Bearer token header."""
        resp = self.post("/login", json={
            "username": self._access_key_id,
            "password": self._secret_key,
        })
        token = resp.get("token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("Prisma Cloud: failed to obtain auth token")
        self._auth_headers["x-redlock-auth"] = token
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the alert endpoint with a minimal filter."""
        self.get("/alert/v2/alert", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single alert, vulnerability, or compliance report by ID."""
        if stix_type == "indicator":
            resp = self.get(f"/alert/v2/alert/{object_id}")
            return resp if isinstance(resp, dict) else {}

        if stix_type == "vulnerability":
            resp = self.get(f"/v2/vulnerability/assets/{object_id}")
            return resp if isinstance(resp, dict) else {}

        if stix_type == "report":
            resp = self.get(f"/compliance/posture/{object_id}")
            return resp if isinstance(resp, dict) else {}

        raise GNATClientError(f"Unsupported STIX type for Prisma Cloud: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Prisma Cloud alerts, vulnerabilities, or compliance findings."""
        f = filters or {}
        offset = (page - 1) * page_size

        if stix_type == "indicator":
            params: dict[str, Any] = {"limit": page_size, "offset": offset}
            if "status" in f:
                params["status"] = f["status"]
            if "policy.severity" in f:
                params["policy.severity"] = f["policy.severity"]
            resp = self.get("/alert/v2/alert", params=params)
            if not isinstance(resp, dict):
                return []
            return resp.get("items", [])

        if stix_type == "vulnerability":
            params_v: dict[str, Any] = {"limit": page_size, "offset": offset}
            if "severity" in f:
                params_v["severity"] = f["severity"]
            resp = self.get("/v2/vulnerability/assets", params=params_v)
            return resp.get("items", []) if isinstance(resp, dict) else []

        if stix_type == "report":
            resp = self.get("/compliance/posture", params={"limit": page_size})
            return resp.get("complianceDetails", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"Unsupported STIX type for Prisma Cloud: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Dismiss or snooze a Prisma Cloud alert."""
        if stix_type == "indicator":
            alert_id = payload.get("alertId", payload.get("id", ""))
            dismissal_note = payload.get("dismissalNote", "Acknowledged via GNAT")
            resp = self.post("/alert/dismiss", json={
                "ids": [alert_id],
                "dismissalNote": dismissal_note,
            })
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"Prisma Cloud: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Dismiss a Prisma Cloud alert (no hard delete available)."""
        if stix_type == "indicator":
            self.post("/alert/dismiss", json={
                "ids": [object_id],
                "dismissalNote": "Dismissed via GNAT",
            })
            return
        raise GNATClientError(
            f"Prisma Cloud: delete not supported for STIX type '{stix_type}'"
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_policies(self, policy_type: str | None = None) -> list[dict[str, Any]]:
        """Retrieve Prisma Cloud security policies."""
        params: dict[str, Any] = {}
        if policy_type:
            params["policy.type"] = policy_type
        resp = self.get("/policy/v2/policy", params=params)
        return resp if isinstance(resp, list) else []

    def get_assets(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve cloud assets from resource scan results."""
        resp = self.get("/resource/scan_info", params={"limit": limit})
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_compliance_posture(
        self, compliance_id: str | None = None
    ) -> dict[str, Any]:
        """Return overall compliance posture or a specific standard's status."""
        path = f"/compliance/{compliance_id}/posture" if compliance_id else "/compliance/posture"
        resp = self.get(path)
        return resp if isinstance(resp, dict) else {}

    def search_config(self, rql_query: str, limit: int = 100) -> list[dict[str, Any]]:
        """Run a Prisma Cloud RQL config query."""
        resp = self.post("/search/config", json={
            "query": rql_query,
            "limit": limit,
            "withResourceJson": False,
        })
        return resp.get("data", {}).get("items", []) if isinstance(resp, dict) else []

    def search_event(self, rql_query: str, limit: int = 100) -> list[dict[str, Any]]:
        """Run a Prisma Cloud RQL event query."""
        resp = self.post("/search/event", json={"query": rql_query, "limit": limit})
        return resp.get("data", {}).get("items", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Prisma Cloud object to STIX."""
        # Dispatch by object shape
        if "id" in native and "policy" in native:
            return self._alert_to_stix(native)
        if "cveId" in native or "cvssScore" in native:
            return self._vuln_to_stix(native)
        if "complianceDetails" in native or "passedResources" in native:
            return self._compliance_to_stix(native)
        # Default: treat as alert
        return self._alert_to_stix(native)

    def _alert_to_stix(self, alert: dict[str, Any]) -> dict[str, Any]:
        alert_id = str(alert.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"prisma-alert-{alert_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25,
                        "informational": 10}
        policy = alert.get("policy", {}) if isinstance(alert.get("policy"), dict) else {}
        sev = str(policy.get("severity", alert.get("severity", "low"))).lower()
        ts = alert.get("alertTime", "")
        if isinstance(ts, int):
            ts = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        ts = ts or _now_ts()

        resource = alert.get("resource", {}) if isinstance(alert.get("resource"), dict) else {}
        res_name = resource.get("name", "")
        cloud_type = resource.get("cloudType", "")

        # Represent the cloud resource as a file artifact in STIX
        pattern = (
            f"[file:name = '{res_name}']"
            if res_name
            else f"[file:name = 'prisma-alert-{alert_id[:32]}']"
        )
        sectors = alert.get("x_target_sectors", [])
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": policy.get("name", f"Prisma Alert {alert_id}"),
            "description": policy.get("description", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": severity_map.get(sev, 25),
            "x_source_platform": "prisma_cloud",
            "x_prisma_cloud": {
                "alert_id": alert_id,
                "severity": sev,
                "status": alert.get("status", ""),
                "policy_id": policy.get("policyId", ""),
                "policy_type": policy.get("policyType", ""),
                "cloud_type": cloud_type,
                "resource_id": resource.get("id", ""),
                "resource_region": resource.get("region", ""),
                "account_id": alert.get("accountId", ""),
            },
        }
        if isinstance(sectors, list) and sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        cve_id = vuln.get("cveId", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"prisma-cve-{cve_id}"))
        cvss = vuln.get("cvssScore", 0.0)
        ts = vuln.get("publishedDate", _now_ts())
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": cve_id or f"Prisma CVE {uid[:8]}",
            "description": vuln.get("description", "")[:500],
            "external_references": (
                [{"source_name": "cve", "external_id": cve_id}] if cve_id else []
            ),
            "created": ts,
            "modified": ts,
            "x_source_platform": "prisma_cloud",
            "x_prisma_cloud": {
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": vuln.get("severity", ""),
                "package_name": vuln.get("packageName", ""),
                "package_version": vuln.get("packageVersion", ""),
                "image_id": vuln.get("imageId", ""),
                "status": vuln.get("status", ""),
            },
        }

    def _compliance_to_stix(self, report: dict[str, Any]) -> dict[str, Any]:
        standard = report.get("name", "Prisma Compliance Report")
        uid = str(_uuid.uuid5(_STIX_NS, f"prisma-compliance-{standard}"))
        ts = report.get("scanTime", _now_ts())
        if isinstance(ts, int):
            ts = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": standard,
            "description": f"Prisma Cloud compliance posture for {standard}",
            "published": ts,
            "created": ts,
            "modified": ts,
            "object_refs": [],
            "x_source_platform": "prisma_cloud",
            "x_prisma_cloud": {
                "compliance_id": report.get("id", ""),
                "passed_resources": report.get("passedResources", 0),
                "failed_resources": report.get("failedResources", 0),
                "total_resources": report.get("totalResources", 0),
                "pass_percentage": report.get("passPercentage", 0.0),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract Prisma Cloud-compatible fields from a STIX dict."""
        return {
            "alertId": stix_dict.get("id", "").replace("indicator--", ""),
            "dismissalNote": stix_dict.get("name", ""),
            "stix_id": stix_dict.get("id", ""),
        }
