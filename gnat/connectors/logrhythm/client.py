# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.logrhythm.client
====================================

LogRhythm NextGen SIEM connector.

LogRhythm NextGen SIEM provides log management, UEBA (User and Entity
Behavior Analytics), network monitoring (NDR), and security orchestration
(SOAR) capabilities. LogRhythm Axon is the cloud-native SaaS successor.

Authentication
--------------
Bearer token using an API token generated in the LogRhythm console::

    [logrhythm]
    host      = https://logrhythm.example.com:8501
    api_token = <Bearer token>
    auth_type = token

For LogRhythm Axon (cloud), the host is typically
``https://api.logrhythm.io`` and authentication uses OAuth2 client
credentials.

STIX Type Mapping
-----------------
+----------------+-----------------------------------------------+
| STIX Type      | LogRhythm Resource                            |
+================+===============================================+
| indicator      | alarms (security event alarms)                |
+----------------+-----------------------------------------------+
| malware        | cases (investigations)                        |
+----------------+-----------------------------------------------+
| observed-data  | log events / log messages                     |
+----------------+-----------------------------------------------+

Key Endpoints
-------------
* GET  /lr-alarm-api/alarms                  — List alarms
* GET  /lr-alarm-api/alarms/{alarmId}        — Get alarm details
* POST /lr-alarm-api/alarms/{alarmId}/status — Update alarm status
* GET  /lr-case-api/cases                    — List cases
* POST /lr-case-api/cases                    — Create case
* GET  /lr-case-api/cases/{caseId}           — Get case details
* PATCH /lr-case-api/cases/{caseId}          — Update case
* GET  /lr-search-api/actions/search         — Log search (async)
* GET  /lr-admin-api/lists                   — List management

References
----------
https://docs.logrhythm.com/lrsiem/7.x/rest-api-reference
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("f5a6b7c8-d9e0-1234-efab-234567890123")


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LogRhythmClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the LogRhythm NextGen SIEM REST API.

    Parameters
    ----------
    host : str
        LogRhythm REST API base URL (e.g. ``https://logrhythm.example.com:8501``).
    api_token : str
        Bearer token from the LogRhythm console.
    client_id : str
        OAuth2 client ID (LogRhythm Axon / cloud deployments only).
    client_secret : str
        OAuth2 client secret (LogRhythm Axon / cloud deployments only).
    """

    stix_type_map: dict[str, str] = {
        "indicator": "alarms",
        "malware": "cases",
        "observed-data": "events",
    }

    def __init__(
        self,
        host: str = "https://localhost:8501",
        api_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize LogRhythmClient."""
        super().__init__(host=host, **kwargs)
        self._api_token = api_token
        self._client_id = client_id
        self._client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token or obtain OAuth2 token for Axon deployments."""
        if self._api_token:
            self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
        elif self._client_id and self._client_secret:
            resp = self.post(
                "/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            token = resp.get("access_token") if isinstance(resp, dict) else None
            if not token:
                raise GNATClientError("LogRhythm: failed to obtain OAuth2 token")
            self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the alarms endpoint for a single result."""
        self.get("/lr-alarm-api/alarms", params={"count": 1, "offset": 0})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single alarm or case by ID."""
        if stix_type == "indicator":
            resp = self.get(f"/lr-alarm-api/alarms/{object_id}")
            return resp if isinstance(resp, dict) else {}

        if stix_type == "malware":
            resp = self.get(f"/lr-case-api/cases/{object_id}")
            return resp if isinstance(resp, dict) else {}

        if stix_type == "observed-data":
            # Log search is async; return a search stub
            resp = self.get(
                "/lr-search-api/actions/search",
                params={
                    "logCacheSize": 1,
                    "query": f"msgId:{object_id}",
                },
            )
            return resp if isinstance(resp, dict) else {}

        raise GNATClientError(f"Unsupported STIX type for LogRhythm: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List LogRhythm alarms, cases, or log events."""
        f = filters or {}
        offset = (page - 1) * page_size

        if stix_type == "indicator":
            params: dict[str, Any] = {"count": page_size, "offset": offset}
            if "status" in f:
                params["alarmStatus"] = f["status"]
            if "priority" in f:
                params["priority"] = f["priority"]
            resp = self.get("/lr-alarm-api/alarms", params=params)
            if not isinstance(resp, dict):
                return []
            return resp.get("alarmsSearchDetails", resp.get("data", []))

        if stix_type == "malware":
            params_c: dict[str, Any] = {"count": page_size, "offset": offset}
            if "status" in f:
                params_c["status"] = f["status"]
            resp = self.get("/lr-case-api/cases", params=params_c)
            if isinstance(resp, list):
                return resp
            if not isinstance(resp, dict):
                return []
            return resp.get("data", [])

        if stix_type == "observed-data":
            query = f.get("query", "*")
            resp = self.get(
                "/lr-search-api/actions/search",
                params={
                    "logCacheSize": page_size,
                    "query": query,
                },
            )
            return resp.get("items", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"Unsupported STIX type for LogRhythm: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update a LogRhythm case."""
        if stix_type == "malware":
            case_id = payload.get("id", "")
            if case_id:
                # Update existing case
                resp = self.patch(f"/lr-case-api/cases/{case_id}", json=payload)
                return resp if isinstance(resp, dict) else {}
            # Create new case
            resp = self.post("/lr-case-api/cases", json=payload)
            return resp if isinstance(resp, dict) else {}

        if stix_type == "indicator":
            alarm_id = payload.get("alarmId", payload.get("id", ""))
            status = payload.get("status", "Completed")
            resp = self.post(
                f"/lr-alarm-api/alarms/{alarm_id}/status",
                json={"status": status},
            )
            return resp if isinstance(resp, dict) else {}

        raise GNATClientError(f"LogRhythm: upsert not supported for STIX type '{stix_type}'")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Close/complete a LogRhythm alarm or case."""
        if stix_type == "indicator":
            self.post(f"/lr-alarm-api/alarms/{object_id}/status", json={"status": "Completed"})
            return
        if stix_type == "malware":
            self.patch(f"/lr-case-api/cases/{object_id}", json={"status": {"name": "Completed"}})
            return
        raise GNATClientError(f"LogRhythm: delete not supported for STIX type '{stix_type}'")

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_alarm_events(self, alarm_id: str) -> list[dict[str, Any]]:
        """Retrieve the raw log events associated with a LogRhythm alarm."""
        resp = self.get(f"/lr-alarm-api/alarms/{alarm_id}/events")
        return resp.get("logList", []) if isinstance(resp, dict) else []

    def get_case_evidence(self, case_id: str) -> list[dict[str, Any]]:
        """List evidence items attached to a case."""
        resp = self.get(f"/lr-case-api/cases/{case_id}/evidence")
        return resp if isinstance(resp, list) else []

    def add_case_note(self, case_id: str, note: str) -> dict[str, Any]:
        """Append a text note to a LogRhythm case."""
        resp = self.post(
            f"/lr-case-api/cases/{case_id}/evidence/note",
            json={"text": note},
        )
        return resp if isinstance(resp, dict) else {}

    def create_case_from_alarm(self, alarm_id: str, name: str, priority: int = 3) -> dict[str, Any]:
        """Create a new investigation case from an existing alarm."""
        resp = self.post(
            "/lr-case-api/cases",
            json={
                "name": name,
                "priority": priority,
                "externalId": str(alarm_id),
                "summary": f"Created from LogRhythm alarm {alarm_id} via GNAT",
            },
        )
        return resp if isinstance(resp, dict) else {}

    def search_logs(
        self,
        query: str = "*",
        max_results: int = 500,
    ) -> dict[str, Any]:
        """Submit an asynchronous log search and return the search handle."""
        resp = self.get(
            "/lr-search-api/actions/search",
            params={
                "logCacheSize": max_results,
                "query": query,
            },
        )
        return resp if isinstance(resp, dict) else {}

    def get_lists(self, list_type: str | None = None) -> list[dict[str, Any]]:
        """Retrieve LogRhythm list objects (threat lists, networks, etc.)."""
        params: dict[str, Any] = {}
        if list_type:
            params["listType"] = list_type
        resp = self.get("/lr-admin-api/lists", params=params)
        return resp if isinstance(resp, list) else []

    def update_list(self, list_id: int, items: list[str]) -> dict[str, Any]:
        """Append items to a LogRhythm list (e.g., blocklist IPs)."""
        resp = self.post(
            f"/lr-admin-api/lists/{list_id}/items",
            json={"items": [{"value": v, "isExpired": False} for v in items]},
        )
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a LogRhythm alarm, case, or event to STIX."""
        if "alarmId" in native or "alarmRuleID" in native:
            return self._alarm_to_stix(native)
        if "id" in native and "status" in native and "priority" in native:
            return self._case_to_stix(native)
        return self._event_to_stix(native)

    def _alarm_to_stix(self, alarm: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for alarm to stix."""
        alarm_id = str(alarm.get("alarmId", alarm.get("id", "")))
        uid = str(_uuid.uuid5(_STIX_NS, f"logrhythm-alarm-{alarm_id}"))
        priority_map = {1: 90, 2: 75, 3: 50, 4: 25, 5: 10}
        priority = int(alarm.get("alarmRiskScore", alarm.get("priority", 3)))
        # Map 0–100 risk score to 1–5 priority bucket for confidence
        if priority > 10:
            confidence = min(priority, 100)
        else:
            confidence = priority_map.get(priority, 50)

        ts = alarm.get("dateInserted", alarm.get("createdDate", _now_ts()))

        # Build pattern from impacted/origin host
        impacted_ip = alarm.get("impactedHostName", "")
        origin_ip = alarm.get("originHostName", "")
        alarm_ip = alarm.get("impactedIp", alarm.get("originIp", ""))
        if alarm_ip:
            pattern = f"[ipv4-addr:value = '{alarm_ip}']"
        elif impacted_ip:
            pattern = f"[domain-name:value = '{impacted_ip}']"
        else:
            pattern = f"[file:name = 'lr-alarm-{alarm_id[:32]}']"

        sectors = alarm.get("x_target_sectors", [])
        stix: dict[str, Any] = {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": alarm.get("alarmRuleName", f"LogRhythm Alarm {alarm_id}"),
            "description": alarm.get("briefDescription", "")[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": ts,
            "modified": ts,
            "indicator_types": ["malicious-activity"],
            "confidence": confidence,
            "x_source_platform": "logrhythm",
            "x_logrhythm": {
                "alarm_id": alarm_id,
                "alarm_rule_id": alarm.get("alarmRuleID", ""),
                "alarm_rule_name": alarm.get("alarmRuleName", ""),
                "status": alarm.get("alarmStatus", ""),
                "risk_score": alarm.get("alarmRiskScore", 0),
                "impacted_hostname": impacted_ip,
                "origin_hostname": origin_ip,
                "date_inserted": ts,
            },
        }
        if isinstance(sectors, list) and sectors:
            stix["x_target_sectors"] = sectors
        return stix

    def _case_to_stix(self, case: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for case to stix."""
        case_id = str(case.get("id", ""))
        uid = str(_uuid.uuid5(_STIX_NS, f"logrhythm-case-{case_id}"))
        ts = case.get("dateCreated", _now_ts())
        status = case.get("status", {})
        status_name = status.get("name", "") if isinstance(status, dict) else str(status)
        return {
            "type": "malware",
            "id": f"malware--{uid}",
            "name": case.get("name", f"LogRhythm Case {case_id}"),
            "description": case.get("summary", "")[:500],
            "is_family": False,
            "created": ts,
            "modified": case.get("dateUpdated", ts),
            "x_source_platform": "logrhythm",
            "x_logrhythm": {
                "case_id": case_id,
                "number": case.get("number", ""),
                "priority": case.get("priority", ""),
                "status": status_name,
                "owner": case.get("owner", {}).get("name", "")
                if isinstance(case.get("owner"), dict)
                else "",
                "due_date": case.get("dueDate", ""),
                "external_id": case.get("externalId", ""),
            },
        }

    def _event_to_stix(self, event: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for event to stix."""
        msg_id = str(event.get("logSourceMsgId", event.get("id", "")))
        uid = str(_uuid.uuid5(_STIX_NS, f"logrhythm-event-{msg_id}"))
        ts = event.get("logDate", _now_ts())
        src_ip = event.get("originIp", "")
        return {
            "type": "observed-data",
            "id": f"observed-data--{uid}",
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [],
            "created": ts,
            "modified": ts,
            "x_source_platform": "logrhythm",
            "x_logrhythm": {
                "msg_id": msg_id,
                "log_source": event.get("logSourceName", ""),
                "common_event": event.get("commonEventName", ""),
                "origin_ip": src_ip,
                "impacted_ip": event.get("impactedIp", ""),
                "severity": event.get("logSourceSeverity", ""),
                "raw_log": event.get("logMessage", "")[:1000],
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract LogRhythm-compatible fields from a STIX dict."""
        stix_type = stix_dict.get("type", "")
        if stix_type == "malware":
            return {
                "name": stix_dict.get("name", ""),
                "summary": stix_dict.get("description", ""),
                "priority": 3,
            }
        return {
            "alarmRuleName": stix_dict.get("name", ""),
            "stix_id": stix_dict.get("id", ""),
        }
