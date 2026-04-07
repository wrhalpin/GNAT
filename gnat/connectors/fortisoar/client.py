# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortisoar.client
================================

FortiSOAR connector for module-based CRUD (alerts, incidents, indicators,
etc.) and playbook actions.

Authentication
--------------
JWT token via POST /auth/authenticate (preferred) or HTTP Basic Auth::

    [fortisoar]
    host     = https://<fortisoar-fqdn-or-ip>
    username = <username>
    password = <password>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | FortiSOAR Module                 |
+================+==================================+
| incident       | incidents                        |
+----------------+----------------------------------+
| observed-data  | alerts                           |
+----------------+----------------------------------+
| indicator      | indicators                       |
+----------------+----------------------------------+
| report         | assets                           |
+----------------+----------------------------------+

Key Endpoints (/api/3/)
-----------------------
* GET/POST /api/3/{module}              — List or bulk create records
* GET/PUT/DELETE /api/3/{module}/{uuid} — Single record CRUD
* POST /auth/authenticate               — JWT token exchange
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("aabbccdd-eeff-0011-2233-445566778899")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FortiSOARClient(BaseClient, ConnectorMixin):
    """
    HTTP client for FortiSOAR REST API v3 (module-based records + playbooks).

    Parameters
    ----------
    host : str
        FortiSOAR base URL, e.g. ``"https://fortisoar.example.com"``.
    username : str
        Username with appropriate permissions.
    password : str
        Password for authentication.
    """

    stix_type_map: dict[str, str] = {
        "incident": "incidents",
        "observed-data": "alerts",
        "indicator": "indicators",
        "report": "assets",
    }

    def __init__(self, host: str, username: str = "", password: str = "", **kwargs: Any) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._token: str | None = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Obtain JWT token via /auth/authenticate and set Bearer header."""
        if self._token:
            self._auth_headers["Authorization"] = f"Bearer {self._token}"
            return
        payload = {"username": self._username, "password": self._password}
        try:
            resp = self.post("/auth/authenticate", json=payload)
            self._token = resp.get("token") or resp.get("access_token")
            if self._token:
                self._auth_headers["Authorization"] = f"Bearer {self._token}"
            else:
                self._auth_headers["Authorization"] = self._basic_auth(
                    self._username, self._password
                )
        except Exception:
            self._auth_headers["Authorization"] = self._basic_auth(self._username, self._password)
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight check via model metadata endpoint."""
        self.get("/api/3/model_metadatas", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single FortiSOAR module record by UUID."""
        module = self.stix_type_map.get(stix_type, stix_type)
        resp = self.get(f"/api/3/{module}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List FortiSOAR module records with optional field filters."""
        module = self.stix_type_map.get(stix_type, stix_type)
        params: dict[str, Any] = {
            "$limit": page_size,
            "$offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get(f"/api/3/{module}", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("hydra:member", resp.get("data", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update a FortiSOAR module record."""
        module = self.stix_type_map.get(stix_type, stix_type)
        record_id = payload.get("@id", payload.get("id", ""))
        if record_id:
            resp = self.put(f"/api/3/{module}/{record_id}", json=payload)
        else:
            resp = self.post(f"/api/3/{module}", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a FortiSOAR module record by UUID."""
        module = self.stix_type_map.get(stix_type, stix_type)
        self.delete(f"/api/3/{module}/{object_id}")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def list_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return FortiSOAR alerts with optional status/severity filter."""
        params: dict[str, Any] = {"$limit": limit}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        resp = self.get("/api/3/alerts", params=params)
        return resp.get("hydra:member", []) if isinstance(resp, dict) else []

    def escalate_to_incident(self, alert_id: str, name: str) -> dict[str, Any]:
        """Create an incident linked to an existing alert."""
        resp = self.post(
            "/api/3/incidents",
            json={
                "name": name,
                "alerts": [f"/api/3/alerts/{alert_id}"],
            },
        )
        return resp if isinstance(resp, dict) else {}

    def trigger_playbook(self, playbook_iri: str, record_iri: str) -> dict[str, Any]:
        """Manually trigger a FortiSOAR playbook against a record."""
        resp = self.post(
            "/api/3/triggers/1/notifyTrigger",
            json={
                "playbookIRI": playbook_iri,
                "recordIRI": record_iri,
            },
        )
        return resp if isinstance(resp, dict) else {}

    def get_indicators(
        self,
        ioc_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve threat indicators from FortiSOAR."""
        params: dict[str, Any] = {"$limit": limit}
        if ioc_type:
            params["typeofindicator"] = ioc_type
        resp = self.get("/api/3/indicators", params=params)
        return resp.get("hydra:member", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a FortiSOAR record to STIX."""
        # Dispatch on module-specific fields
        if "indicatorValue" in native or "typeofindicator" in native:
            return self._indicator_to_stix(native)
        # Incidents explicitly have a linked 'alerts' list or a closing reason
        if "alerts" in native or "closingReason" in native:
            return self._incident_to_stix(native)
        return self._alert_to_stix(native)

    def _alert_to_stix(self, alert: dict[str, Any]) -> dict[str, Any]:
        alert_id = str(alert.get("id", alert.get("@id", "").split("/")[-1]))
        uid = str(_uuid.uuid5(_STIX_NS, f"fortisoar-alert-{alert_id}"))
        severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        sev = str(
            alert.get("severity", {}).get("itemValue", "low")
            if isinstance(alert.get("severity"), dict)
            else alert.get("severity", "low")
        ).lower()
        ts = alert.get("createDate", alert.get("modifyDate", _now_ts()))
        src_ip = alert.get("sourceIp", "")
        pattern = (
            f"[ipv4-addr:value = '{src_ip}']"
            if src_ip
            else f"[file:name = 'fortisoar-alert-{alert_id[:32]}']"
        )
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": alert.get("name", f"FortiSOAR Alert {alert_id}"),
            "description": alert.get("description", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": severity_map.get(sev, 25),
            "x_source_platform": "fortisoar",
            "x_fortisoar": {
                "record_id": alert_id,
                "module": "alerts",
                "severity": sev,
                "status": (
                    alert.get("status", {}).get("itemValue", "")
                    if isinstance(alert.get("status"), dict)
                    else alert.get("status", "")
                ),
                "source_ip": src_ip,
            },
        }

    def _incident_to_stix(self, incident: dict[str, Any]) -> dict[str, Any]:
        inc_id = str(incident.get("id", incident.get("@id", "").split("/")[-1]))
        uid = str(_uuid.uuid5(_STIX_NS, f"fortisoar-incident-{inc_id}"))
        ts = incident.get("createDate", _now_ts())
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": incident.get("name", f"FortiSOAR Incident {inc_id}"),
            "description": incident.get("description", "")[:500],
            "is_family": False,
            "created": ts,
            "modified": incident.get("modifyDate", ts),
            "x_source_platform": "fortisoar",
            "x_fortisoar": {
                "record_id": inc_id,
                "module": "incidents",
                "severity": (
                    incident.get("severity", {}).get("itemValue", "")
                    if isinstance(incident.get("severity"), dict)
                    else incident.get("severity", "")
                ),
                "status": (
                    incident.get("status", {}).get("itemValue", "")
                    if isinstance(incident.get("status"), dict)
                    else incident.get("status", "")
                ),
            },
        }

    def _indicator_to_stix(self, indicator: dict[str, Any]) -> dict[str, Any]:
        ioc_id = str(indicator.get("id", indicator.get("@id", "").split("/")[-1]))
        uid = str(_uuid.uuid5(_STIX_NS, f"fortisoar-ioc-{ioc_id}"))
        value = indicator.get("indicatorValue", "")
        ioc_type = str(
            indicator.get("typeofindicator", {}).get("itemValue", "")
            if isinstance(indicator.get("typeofindicator"), dict)
            else indicator.get("typeofindicator", "")
        ).lower()
        ts = indicator.get("createDate", _now_ts())
        if "ip" in ioc_type:
            pattern = f"[ipv4-addr:value = '{value}']"
        elif "domain" in ioc_type or "url" in ioc_type:
            pattern = f"[domain-name:value = '{value}']"
        elif "file" in ioc_type or "hash" in ioc_type:
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        else:
            pattern = f"[file:name = '{value}']"
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": value or f"FortiSOAR IOC {ioc_id}",
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "fortisoar",
            "x_fortisoar": {
                "record_id": ioc_id,
                "module": "indicators",
                "ioc_type": ioc_type,
                "reputation": (
                    indicator.get("reputation", {}).get("itemValue", "")
                    if isinstance(indicator.get("reputation"), dict)
                    else indicator.get("reputation", "")
                ),
                "confidence": indicator.get("confidence", 0),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract FortiSOAR-compatible fields from a STIX dict."""
        return {
            "name": stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
            "stix_id": stix_dict.get("id", ""),
        }
