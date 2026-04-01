"""
gnat.connectors.nozomi.client
================================

Nozomi Networks Guardian / Vantage connector.

Nozomi Networks provides OT/IoT network visibility, security monitoring, and
threat detection for industrial control systems (ICS), SCADA environments,
and converged IT/OT networks. Guardian is the on-premises sensor appliance;
Vantage is the cloud-managed SaaS version.

Authentication
--------------
API token passed as the ``Token`` authorization header::

    [nozomi]
    host      = https://nozomi.example.com
    api_token = <API token>
    auth_type = token

Some deployments also support HTTP Basic auth (username + password).

STIX Type Mapping
-----------------
+----------------+-------------------------------------------+
| STIX Type      | Nozomi Resource                           |
+================+===========================================+
| indicator      | alerts (security events & anomalies)      |
+----------------+-------------------------------------------+
| vulnerability  | vulnerabilities (CVE scan results)        |
+----------------+-------------------------------------------+
| infrastructure | nodes / assets (OT devices)               |
+----------------+-------------------------------------------+

Key Endpoints
-------------
* GET /api/open/query/do?query=alerts                   — List alerts
* GET /api/open/query/do?query=vulnerabilities          — List CVEs
* GET /api/open/query/do?query=nodes                    — Asset inventory
* GET /api/open/query/do?query=sessions                 — Network sessions
* GET /api/open/alerts/<id>                             — Single alert
* PATCH /api/open/alerts/<id>                           — Acknowledge alert

References
----------
https://community.nozominetworks.com/nozomi-networks-api-documentation
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d3e4f5a6-b7c8-9012-cdef-012345678901")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class NozomiClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Nozomi Networks Guardian / Vantage REST API.

    Parameters
    ----------
    host : str
        Base URL of the Nozomi instance (e.g. ``https://nozomi.example.com``).
    api_token : str
        Nozomi API token.
    username : str
        Optional username for Basic auth (used when ``api_token`` is empty).
    password : str
        Optional password for Basic auth.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "alerts",
        "vulnerability": "vulnerabilities",
        "infrastructure": "nodes",
    }

    def __init__(
        self,
        host: str = "https://localhost",
        api_token: str = "",
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_token = api_token
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject API token or Basic auth header."""
        if self._api_token:
            self._auth_headers["Authorization"] = f"Token {self._api_token}"
        elif self._username and self._password:
            import base64

            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the query endpoint for a single alert."""
        self.get("/api/open/query/do", params={"query": "alerts", "limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Nozomi object by STIX type and ID."""
        if stix_type == "indicator":
            resp = self.get(f"/api/open/alerts/{object_id}")
            return resp if isinstance(resp, dict) else {}

        if stix_type == "vulnerability":
            resp = self.get(
                "/api/open/query/do",
                params={
                    "query": f"vulnerabilities | where id=={object_id}",
                    "limit": 1,
                },
            )
            items = resp.get("result", []) if isinstance(resp, dict) else []
            return items[0] if items else {}

        if stix_type == "infrastructure":
            resp = self.get(
                "/api/open/query/do",
                params={
                    "query": f"nodes | where id=={object_id}",
                    "limit": 1,
                },
            )
            items = resp.get("result", []) if isinstance(resp, dict) else []
            return items[0] if items else {}

        raise GNATClientError(f"Unsupported STIX type for Nozomi: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Nozomi alerts, vulnerabilities, or nodes."""
        f = filters or {}
        resource = self.stix_type_map.get(stix_type, "alerts")
        query = resource
        if "status" in f:
            query += f" | where status=={f['status']}"
        if "severity" in f:
            query += f" | where risk=={f['severity']}"
        if "type_name" in f:
            query += f" | where type_name=={f['type_name']}"

        params: dict[str, Any] = {
            "query": query,
            "limit": page_size,
            "page": page - 1,
        }
        resp = self.get("/api/open/query/do", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("result", [])

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Acknowledge or update a Nozomi alert."""
        if stix_type == "indicator":
            alert_id = payload.get("id", "")
            body: dict[str, Any] = {}
            if "status" in payload:
                body["status"] = payload["status"]
            if "ack" in payload:
                body["ack"] = payload["ack"]
            resp = self.patch(f"/api/open/alerts/{alert_id}", json=body)
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(f"Nozomi: upsert not supported for STIX type '{stix_type}'")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Acknowledge a Nozomi alert (no hard delete via API)."""
        if stix_type == "indicator":
            self.patch(f"/api/open/alerts/{object_id}", json={"ack": True})
            return
        raise GNATClientError(f"Nozomi: delete not supported for STIX type '{stix_type}'")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_nodes(
        self,
        node_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return OT/IoT asset nodes from the Nozomi inventory."""
        query = "nodes"
        if node_type:
            query += f" | where type=={node_type}"
        resp = self.get("/api/open/query/do", params={"query": query, "limit": limit})
        return resp.get("result", []) if isinstance(resp, dict) else []

    def get_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve recent network sessions observed by Nozomi."""
        resp = self.get("/api/open/query/do", params={"query": "sessions", "limit": limit})
        return resp.get("result", []) if isinstance(resp, dict) else []

    def get_vulnerabilities(
        self,
        cve_id: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve CVE vulnerability data from Nozomi."""
        query = "vulnerabilities"
        if cve_id:
            query += f" | where cve_id=={cve_id}"
        if severity:
            query += f" | where severity=={severity}"
        resp = self.get("/api/open/query/do", params={"query": query, "limit": limit})
        return resp.get("result", []) if isinstance(resp, dict) else []

    def acknowledge_alert(self, alert_id: str) -> dict[str, Any]:
        """Acknowledge a specific Nozomi alert."""
        resp = self.patch(f"/api/open/alerts/{alert_id}", json={"ack": True})
        return resp if isinstance(resp, dict) else {}

    def get_network_protocols(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return observed OT/IT network protocols."""
        resp = self.get("/api/open/query/do", params={"query": "protocols", "limit": limit})
        return resp.get("result", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Nozomi object to STIX."""
        if "cve_id" in native or "cvss_score" in native:
            return self._vuln_to_stix(native)
        if "mac_address" in native or "vendor" in native or "firmware" in native:
            return self._node_to_stix(native)
        return self._alert_to_stix(native)

    def _alert_to_stix(self, alert: dict[str, Any]) -> dict[str, Any]:
        alert_id = str(alert.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"nozomi-alert-{alert_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        risk = str(alert.get("risk", alert.get("severity", "low"))).lower()
        ts = alert.get("time", alert.get("created_time", _now_ts()))
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

        # Build pattern from available network IOC fields
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")
        if src_ip:
            pattern = f"[ipv4-addr:value = '{src_ip}']"
        elif dst_ip:
            pattern = f"[ipv4-addr:value = '{dst_ip}']"
        else:
            pattern = f"[file:name = 'nozomi-alert-{alert_id[:32]}']"

        sectors = alert.get("x_target_sectors", [])
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": alert.get("name", alert.get("type_name", f"Nozomi Alert {alert_id}")),
            "description": alert.get("description", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": severity_map.get(risk, 25),
            "x_source_platform": "nozomi",
            "x_nozomi": {
                "alert_id": alert_id,
                "risk": risk,
                "status": alert.get("status", ""),
                "type_name": alert.get("type_name", ""),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": alert.get("protocol", ""),
                "ack": alert.get("ack", False),
            },
        }
        if isinstance(sectors, list) and sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def _vuln_to_stix(self, vuln: dict[str, Any]) -> dict[str, Any]:
        cve_id = vuln.get("cve_id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"nozomi-cve-{cve_id}"))
        ts = vuln.get("published_date", _now_ts())
        cvss = vuln.get("cvss_score", 0.0)
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": cve_id or f"Nozomi CVE {uid[:8]}",
            "description": vuln.get("description", "")[:500],
            "external_references": (
                [{"source_name": "cve", "external_id": cve_id}] if cve_id else []
            ),
            "created": ts,
            "modified": ts,
            "x_source_platform": "nozomi",
            "x_nozomi": {
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": vuln.get("severity", ""),
                "affected_device_ip": vuln.get("ip", ""),
                "affected_device_mac": vuln.get("mac_address", ""),
                "vendor": vuln.get("vendor", ""),
                "product": vuln.get("product", ""),
            },
        }

    def _node_to_stix(self, node: dict[str, Any]) -> dict[str, Any]:
        node_id = str(node.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"nozomi-node-{node_id}"))
        ts = _now_ts()
        ip = node.get("ip", "")
        return {
            "type": "infrastructure",
            "id": f"infrastructure--{uid}",
            "name": node.get("name", node_id),
            "description": f"OT/IoT device — {node.get('vendor', '')} {node.get('product_name', '')}",
            "infrastructure_types": ["ot"],
            "created": ts,
            "modified": ts,
            "x_source_platform": "nozomi",
            "x_nozomi": {
                "node_id": node_id,
                "ip": ip,
                "mac_address": node.get("mac_address", ""),
                "vendor": node.get("vendor", ""),
                "product_name": node.get("product_name", ""),
                "firmware_version": node.get("firmware_version", ""),
                "node_type": node.get("type", ""),
                "zone": node.get("zone", ""),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract Nozomi-compatible fields from a STIX dict."""
        return {
            "name": stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "stix_id": stix_dict.get("id", ""),
        }
