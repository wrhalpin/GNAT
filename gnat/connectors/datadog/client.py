"""
gnat.connectors.datadog.client
================================

Datadog Security / Cloud SIEM connector.

Datadog provides cloud-scale observability and security through its
SIEM (Security Monitoring), Cloud Security Management (CSM), Application
Security Management (ASM), and Cloud SIEM products.

Authentication
--------------
Dual API/Application key headers::

    [datadog]
    host    = https://api.datadoghq.com
    api_key = <your-datadog-api-key>
    app_key = <your-datadog-application-key>

Both keys are required. Generate them in the Datadog portal under
Organization Settings → API Keys / Application Keys.

For EU customers, use ``host = https://api.datadoghq.eu``.

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | Datadog Resource                             |
+================+==============================================+
| indicator      | Security signals (SIEM detections)           |
+----------------+----------------------------------------------+
| vulnerability  | CSM Findings / misconfigurations             |
+----------------+----------------------------------------------+
| report         | Incidents / dashboards                       |
+----------------+----------------------------------------------+

Key Endpoints
-------------
* GET  /api/v2/security_monitoring/signals   — Security signals
* GET  /api/v2/posture_management/findings   — CSM findings
* GET  /api/v2/incidents                     — Incidents
* POST /api/v2/security_monitoring/signals/search — Advanced search
* GET  /api/v1/events                        — Event stream

References
----------
https://docs.datadoghq.com/api/latest/
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a7b8c9d0-e1f2-3456-0123-567890123456")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _epoch_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


class DatadogClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Datadog Security / Cloud SIEM APIs.

    Parameters
    ----------
    host : str
        Base URL (default ``https://api.datadoghq.com``).
    api_key : str
        Datadog API key.
    app_key : str
        Datadog application key.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "security_monitoring/signals",
        "vulnerability": "posture_management/findings",
        "report": "incidents",
    }

    def __init__(
        self,
        host: str = "https://api.datadoghq.com",
        api_key: str = "",
        app_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._app_key = app_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject API and Application key headers."""
        self._auth_headers["DD-API-KEY"] = self._api_key
        self._auth_headers["DD-APPLICATION-KEY"] = self._app_key
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the security signals endpoint."""
        params: dict[str, Any] = {"page[limit]": 1}
        self.get("/api/v2/security_monitoring/signals", params=params)
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single Datadog object by STIX type and ID."""
        if stix_type == "indicator":
            resp = self.get(f"/api/v2/security_monitoring/signals/{object_id}")
            return resp.get("data", resp) if isinstance(resp, dict) else {}
        if stix_type == "vulnerability":
            resp = self.get(f"/api/v2/posture_management/findings/{object_id}")
            return resp.get("data", resp) if isinstance(resp, dict) else {}
        if stix_type == "report":
            resp = self.get(f"/api/v2/incidents/{object_id}")
            return resp.get("data", resp) if isinstance(resp, dict) else {}
        raise GNATClientError(f"Unsupported STIX type for Datadog: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Datadog security objects by STIX type."""
        f = filters or {}
        if stix_type == "indicator":
            params: dict[str, Any] = {"page[limit]": page_size}
            if "cursor" in f:
                params["page[cursor]"] = f["cursor"]
            resp = self.get("/api/v2/security_monitoring/signals", params=params)
            if not isinstance(resp, dict):
                return []
            return resp.get("data", [])

        if stix_type == "vulnerability":
            params_v: dict[str, Any] = {"page[limit]": page_size}
            if "cursor" in f:
                params_v["page[cursor]"] = f["cursor"]
            if "rule_id" in f:
                params_v["filter[rule_id]"] = f["rule_id"]
            resp = self.get("/api/v2/posture_management/findings", params=params_v)
            return resp.get("data", []) if isinstance(resp, dict) else []

        if stix_type == "report":
            params_r: dict[str, Any] = {
                "page[size]": page_size,
                "page[offset]": (page - 1) * page_size,
            }
            resp = self.get("/api/v2/incidents", params=params_r)
            return resp.get("data", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"Unsupported STIX type for Datadog: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a Datadog incident."""
        if stix_type == "report":
            body = {"data": {"type": "incidents", "attributes": payload}}
            resp = self.post("/api/v2/incidents", json=body)
            return resp.get("data", resp) if isinstance(resp, dict) else {}
        raise GNATClientError(f"Datadog: upsert not supported for STIX type '{stix_type}'")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Archive a Datadog incident."""
        if stix_type == "report":
            self.patch(
                f"/api/v2/incidents/{object_id}",
                json={
                    "data": {
                        "type": "incidents",
                        "id": object_id,
                        "attributes": {"archived": _now_ts()},
                    }
                },
            )
            return
        raise GNATClientError(f"Datadog: delete not supported for STIX type '{stix_type}'")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def search_signals(
        self,
        query: str = "",
        from_time: int | None = None,
        to_time: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search security signals using Datadog query syntax."""
        now = _epoch_ms()
        body = {
            "filter": {
                "query": query,
                "from": str(from_time or now - 86_400_000),  # 24h ago
                "to": str(to_time or now),
            },
            "page": {"limit": limit},
            "sort": "timestamp",
        }
        resp = self.post("/api/v2/security_monitoring/signals/search", json=body)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_csm_findings(
        self,
        rule_id: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch Cloud Security Management (CSM) findings."""
        params: dict[str, Any] = {"page[limit]": limit}
        if rule_id:
            params["filter[rule_id]"] = rule_id
        if severity:
            params["filter[severity]"] = severity
        resp = self.get("/api/v2/posture_management/findings", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_incidents(
        self,
        state: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch Datadog incidents."""
        params: dict[str, Any] = {"page[size]": limit}
        if state:
            params["filter[state]"] = state
        resp = self.get("/api/v2/incidents", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_security_rules(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch security monitoring detection rules."""
        params: dict[str, Any] = {"page[size]": limit}
        resp = self.get("/api/v2/security_monitoring/rules", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def create_security_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        """Create a new security monitoring detection rule."""
        resp = self.post("/api/v2/security_monitoring/rules", json=rule)
        return resp if isinstance(resp, dict) else {}

    def mute_signal(self, signal_id: str, reason: str = "maintenance") -> dict[str, Any]:
        """Mute a security signal."""
        body = {"data": {"attributes": {"action": "mute", "reason": reason}}}
        resp = self.patch(f"/api/v2/security_monitoring/signals/{signal_id}/state", json=body)
        return resp if isinstance(resp, dict) else {}

    def get_logs(
        self,
        query: str = "*",
        from_time: int | None = None,
        to_time: int | None = None,
        limit: int = 300,
    ) -> list[dict[str, Any]]:
        """Search Datadog logs."""
        now = _epoch_ms()
        body = {
            "filter": {
                "query": query,
                "from": str(from_time or now - 3_600_000),  # 1h ago
                "to": str(to_time or now),
            },
            "page": {"limit": limit},
        }
        resp = self.post("/api/v2/logs/events/search", json=body)
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Datadog security object to STIX."""
        native_type = native.get("type", "")
        attrs = native.get("attributes", native)

        if native_type == "security_signals" or "rule" in attrs:
            return self._signal_to_stix(native)
        if native_type == "posture_management_findings" or "rule_id" in attrs:
            return self._finding_to_stix(native)
        if native_type == "incidents" or "customer_impact_scope" in attrs:
            return self._incident_to_stix(native)
        # Default: signal
        return self._signal_to_stix(native)

    def _signal_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        signal_id = native.get("id", "")
        attrs = native.get("attributes", native)
        uid = str(_uuid.uuid5(_STIX_NS, f"datadog-signal-{signal_id}"))

        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}
        sev = str(attrs.get("severity", "info")).lower()
        confidence = severity_map.get(sev, 10)

        # Extract IP from network context if available; fall back to event name as file indicator
        network = attrs.get("network", {})
        remote_ip = network.get("client", {}).get("ip", "") if isinstance(network, dict) else ""
        if remote_ip:
            pattern = f"[ipv4-addr:value = '{remote_ip}']"
        else:
            # Non-network signal: represent as a named file artifact using the signal ID
            pattern = f"[file:name = 'datadog-signal-{signal_id[:36]}']"
        rule = attrs.get("rule", {}) if isinstance(attrs.get("rule"), dict) else {}
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": attrs.get("message", f"Datadog Signal {signal_id}"),
            "pattern": pattern,
            "pattern_type": "stix",
            "created": attrs.get("timestamp", _now_ts()),
            "modified": attrs.get("timestamp", _now_ts()),
            "indicator_types": ["malicious-activity"],
            "confidence": confidence,
            "x_source_platform": "datadog",
            "x_datadog": {
                "signal_id": signal_id,
                "severity": sev,
                "status": attrs.get("status", ""),
                "rule_id": rule.get("id", ""),
                "rule_name": rule.get("name", ""),
                "tags": attrs.get("tags", []),
            },
        }

    def _finding_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        finding_id = native.get("id", "")
        attrs = native.get("attributes", native)
        uid = str(_uuid.uuid5(_STIX_NS, f"datadog-finding-{finding_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}
        sev = str(attrs.get("severity", "info")).lower()
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": attrs.get("rule_name", finding_id),
            "description": attrs.get("message", "")[:500],
            "created": attrs.get("evaluation_changed_at", _now_ts()),
            "modified": attrs.get("evaluation_changed_at", _now_ts()),
            "x_source_platform": "datadog",
            "x_datadog": {
                "finding_id": finding_id,
                "rule_id": attrs.get("rule_id", ""),
                "status": attrs.get("status", ""),
                "severity": sev,
                "confidence": severity_map.get(sev, 10),
                "resource_type": attrs.get("resource_type", ""),
                "tags": attrs.get("tags", []),
            },
        }

    def _incident_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        incident_id = native.get("id", "")
        attrs = native.get("attributes", native)
        uid = str(_uuid.uuid5(_STIX_NS, f"datadog-incident-{incident_id}"))
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": attrs.get("title", f"Datadog Incident {incident_id}"),
            "description": attrs.get("customer_impact_scope", "")[:500],
            "created": attrs.get("created", _now_ts()),
            "modified": attrs.get("modified", _now_ts()),
            "published": attrs.get("created", _now_ts()),
            "object_refs": [],
            "x_source_platform": "datadog",
            "x_datadog": {
                "incident_id": incident_id,
                "status": attrs.get("status", ""),
                "severity": attrs.get("severity", ""),
                "detected": attrs.get("detected", ""),
                "resolved": attrs.get("resolved", ""),
                "customer_impact_start": attrs.get("customer_impact_start", ""),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX dict to a Datadog incident payload."""
        return {
            "title": stix_dict.get("name", ""),
            "customer_impact_scope": stix_dict.get("description", ""),
            "stix_id": stix_dict.get("id", ""),
        }
