"""
gnat.connectors.security_onion.client
==========================================

Security Onion NSM platform connector.

Authentication
--------------
Username + password → Bearer token::

    [security_onion]
    host     = https://securityonion.corp.example.com
    username = analyst
    password = <password>

A ``POST /api/login`` returns a JWT that is cached until expiry.

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | Security Onion Resource          |
+====================+==================================+
| observed-data      | alerts                           |
+--------------------+----------------------------------+
| case               | cases                            |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``POST /api/login``              — obtain Bearer token
* ``POST /api/alerts/_search``     — ES DSL alert search
* ``GET  /api/alerts/{id}``        — single alert
* ``GET  /api/cases``              — case listing
* ``GET  /api/grid``               — sensor grid inventory

Notes
-----
* Underlying data store is Elasticsearch; queries use ES Query DSL
  passed through the ``so-api`` layer.
* Tokens expire (default 24 h) — re-authentication is automatic.
"""

from __future__ import annotations

import contextlib
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SecurityOnionClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Security Onion so-api REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://securityonion.corp.example.com"``.
    username : str
        Security Onion username.
    password : str
        Security Onion password.
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "alerts",
        "case":          "cases",
    }

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Obtain a Bearer token via POST /api/login and cache it.

        Token is stored in ``_auth_headers`` for all subsequent requests.
        """
        resp = self.post(
            "/api/login",
            json={"username": self._username, "password": self._password},
        )
        token = resp.get("token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError(
                "Security Onion login failed — no token in response."
            )
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the grid status endpoint."""
        self.get("/api/grid/status")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Security Onion alert or case by id.

        Parameters
        ----------
        object_id : str
            Alert or case id.
        """
        if stix_type == "case":
            return self.get(f"/api/cases/{object_id}")
        return self.get(f"/api/alerts/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Security Onion alerts or list cases.

        Parameters
        ----------
        filters : dict, optional
            For alerts:

            * ``query``      — ES Query DSL dict (default: match_all)
            * ``time_range`` — ``(start_iso, end_iso)`` tuple

            For cases:

            * ``status`` — case status string
        """
        filters = dict(filters or {})
        if stix_type == "case":
            params: dict[str, Any] = {}
            if "status" in filters:
                params["status"] = filters.pop("status")
            if page_size:
                params["limit"] = page_size
            resp = self.get("/api/cases", params=params)
            return resp if isinstance(resp, list) else resp.get("data", [])

        # Alerts via ES DSL search
        query      = filters.pop("query", None)
        time_range = filters.pop("time_range", None)
        from_      = (page - 1) * page_size

        must: list[Any] = []
        if time_range and len(time_range) == 2:
            must.append({
                "range": {"@timestamp": {"gte": time_range[0], "lte": time_range[1]}}
            })
        if query:
            must.append(query)

        body: dict[str, Any] = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": page_size,
            "from": from_,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        resp = self.post("/api/alerts/_search", json=body)
        if isinstance(resp, dict):
            hits = resp.get("hits", {})
            return [h.get("_source", {}) for h in hits.get("hits", [])]
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create a Security Onion case, or acknowledge an alert.

        Parameters
        ----------
        payload : dict
            For cases: ``title``, ``description``, ``severity``.
            For alerts: ``id`` + ``action`` (``"acknowledge"``).
        """
        if stix_type == "case":
            return self.post("/api/cases", json=payload)
        # Alert action
        alert_id = payload.get("id")
        if not alert_id:
            raise GNATClientError(
                "SecurityOnionClient.upsert_object: 'id' required for alert action."
            )
        action = payload.get("action", "acknowledge")
        return self.post(f"/api/alerts/{alert_id}/{action}")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError(
            "Security Onion does not support alert/case deletion via the API."
        )

    # ── Domain-specific operations ────────────────────────────────────────

    def search_alerts(
        self,
        query: dict[str, Any] | None = None,
        size: int = 100,
        from_: int = 0,
        time_range: tuple[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search alerts using ES Query DSL.

        Parameters
        ----------
        query : dict, optional
            ES Query DSL clause. Defaults to match_all.
        size : int
            Max results.
        from_ : int
            Pagination offset.
        time_range : tuple, optional
            ``(start_iso, end_iso)``.

        Returns
        -------
        list of dict
            Alert ``_source`` dicts.
        """
        must: list[Any] = []
        if time_range:
            must.append({
                "range": {"@timestamp": {"gte": time_range[0], "lte": time_range[1]}}
            })
        if query:
            must.append(query)
        body: dict[str, Any] = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": size,
            "from": from_,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        resp = self.post("/api/alerts/_search", json=body)
        if isinstance(resp, dict):
            hits = resp.get("hits", {})
            return [h.get("_source", {}) for h in hits.get("hits", [])]
        return []

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Retrieve a single alert by id."""
        return self.get(f"/api/alerts/{alert_id}")

    def acknowledge_alert(self, alert_id: str) -> dict[str, Any]:
        """Mark an alert as acknowledged."""
        return self.post(f"/api/alerts/{alert_id}/acknowledge")

    def escalate_alert(self, alert_id: str) -> dict[str, Any]:
        """Escalate an alert to a case."""
        return self.post(f"/api/alerts/{alert_id}/escalate")

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: int = 2,
        assignee: str | None = None,
    ) -> dict[str, Any]:
        """Create a new Security Onion case."""
        body: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
        }
        if assignee:
            body["assignee"] = assignee
        return self.post("/api/cases", json=body)

    def list_grid_nodes(self) -> list[dict[str, Any]]:
        """List sensor nodes in the Security Onion grid."""
        resp = self.get("/api/grid")
        return resp if isinstance(resp, list) else resp.get("nodes", [])

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Security Onion alert to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            Raw Security Onion alert dict.

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        alert = self._normalise(native)
        now   = _now_ts()
        ts    = alert.get("timestamp") or now

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append({
                        "type": "ipv4-addr",
                        "id":   ip_id,
                        "spec_version": "2.1",
                        "value": ip,
                    })
                refs.append(ip_id)

        src_ip   = alert.get("src_ip")
        dst_ip   = alert.get("dst_ip")
        src_port = alert.get("src_port")
        dst_port = alert.get("dst_port")
        if src_ip and dst_ip and (src_port or dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id":   nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_port:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_port"] = int(src_port)
                if dst_port:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_port"] = int(dst_port)
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        obs: dict[str, Any] = {
            "type":           "observed-data",
            "id":             obs_id,
            "spec_version":   "2.1",
            "created":        now,
            "modified":       now,
            "first_observed": ts,
            "last_observed":  ts,
            "number_observed": 1,
            "object_refs":    refs,
            "x_security_onion_alert": {
                "alert_id":  alert.get("id"),
                "rule_name": alert.get("rule_name"),
                "rule_id":   alert.get("rule_id"),
                "category":  alert.get("category"),
                "severity":  alert.get("severity"),
                "sensor":    alert.get("sensor"),
            },
        }
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX observed-data to a Security Onion alert action dict.

        Returns a payload suitable for ``upsert_object()``.
        """
        so = stix_dict.get("x_security_onion_alert", {})
        return {
            "id":      so.get("alert_id", ""),
            "action":  "acknowledge",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    @staticmethod
    def _normalise(alert: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw Security Onion alert dict."""
        rule = alert.get("rule", {})
        sev_map: dict[Any, int] = {"1": 4, "2": 3, "3": 2, "4": 1, 1: 4, 2: 3, 3: 2, 4: 1}
        sev_raw = alert.get("event", {}).get("severity", 3)
        return {
            "id":        alert.get("uid") or alert.get("_id"),
            "timestamp": alert.get("@timestamp"),
            "rule_name": rule.get("name"),
            "rule_id":   rule.get("uuid"),
            "category":  alert.get("event", {}).get("category"),
            "severity":  sev_map.get(sev_raw, 2),
            "src_ip":    alert.get("source", {}).get("ip"),
            "dst_ip":    alert.get("destination", {}).get("ip"),
            "src_port":  alert.get("source", {}).get("port"),
            "dst_port":  alert.get("destination", {}).get("port"),
            "proto":     alert.get("network", {}).get("transport"),
            "sensor":    alert.get("observer", {}).get("name"),
        }
