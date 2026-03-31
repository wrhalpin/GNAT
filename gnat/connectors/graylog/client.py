"""
gnat.connectors.graylog.client
===================================

Graylog SIEM connector.

Authentication
--------------
HTTP Basic auth (username + password)::

    [graylog]
    host     = https://graylog.corp.example.com:9000
    username = admin
    password = <password>

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | Graylog Resource                 |
+====================+==================================+
| observed-data      | search messages / alerts         |
+--------------------+----------------------------------+

Key Endpoints
-------------
* ``/api/search/universal/relative``  — relative time-range search
* ``/api/search/universal/absolute``  — absolute time-range search
* ``/api/streams``                    — stream listing
* ``/api/system``                     — health / system info

Notes
-----
* Graylog write operations (stream management, etc.) are supported
  via ``upsert_object`` when stix_type == ``"stream"``.
* All requests require ``X-Requested-By: GNAT`` on mutating calls.
"""

from __future__ import annotations

import base64
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


class GraylogClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Graylog REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://graylog.corp.example.com:9000"``.
    username : str
        Graylog username.
    password : str
        Graylog password.
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "search",
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
        """Inject HTTP Basic auth header."""
        creds = base64.b64encode(
            f"{self._username}:{self._password}".encode()
        ).decode()
        self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["X-Requested-By"] = "GNAT"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the Graylog system info endpoint."""
        self.get("/api/system")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a Graylog message by id.

        Parameters
        ----------
        object_id : str
            Graylog message id (index + message id, format ``index/id``).
        """
        parts = object_id.split("/", 1)
        if len(parts) == 2:
            return self.get(f"/api/messages/{parts[0]}/{parts[1]}")
        return self.get(f"/api/messages/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search Graylog messages using a relative time range.

        Parameters
        ----------
        filters : dict, optional
            Supported keys:

            * ``query``  — Lucene query string (default ``"*"``)
            * ``range``  — relative seconds window (default 3600)
            * ``fields`` — comma-separated field list
        """
        filters = dict(filters or {})
        query  = filters.pop("query", "*")
        rng    = filters.pop("range", 3600)
        fields = filters.pop("fields", None)

        params: dict[str, Any] = {
            "query": query,
            "range": rng,
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if fields:
            params["fields"] = fields

        resp = self.get("/api/search/universal/relative", params=params)
        if isinstance(resp, dict):
            return resp.get("messages", [])
        return []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a Graylog stream.

        Parameters
        ----------
        payload : dict
            Stream definition with ``title``, ``description``, etc.
        """
        stream_id = payload.pop("id", None)
        if stream_id:
            return self.put(f"/api/streams/{stream_id}", json=payload)
        return self.post("/api/streams", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a Graylog stream by id."""
        self.delete(f"/api/streams/{object_id}")

    # ── Domain-specific operations ────────────────────────────────────────

    def search_messages(
        self,
        query: str = "*",
        range_seconds: int = 3600,
        limit: int = 100,
        offset: int = 0,
        fields: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search messages using a relative time window.

        Parameters
        ----------
        query : str
            Lucene query string.
        range_seconds : int
            Relative window in seconds (e.g. 3600 = last hour).
        limit : int
            Max results per page.
        offset : int
            Pagination offset.
        fields : str, optional
            Comma-separated field list.

        Returns
        -------
        list of dict
        """
        params: dict[str, Any] = {
            "query": query,
            "range": range_seconds,
            "limit": limit,
            "offset": offset,
        }
        if fields:
            params["fields"] = fields
        resp = self.get("/api/search/universal/relative", params=params)
        return resp.get("messages", []) if isinstance(resp, dict) else []

    def list_streams(self) -> list[dict[str, Any]]:
        """Return all configured Graylog streams."""
        resp = self.get("/api/streams")
        return resp.get("streams", []) if isinstance(resp, dict) else []

    def get_cluster_health(self) -> dict[str, Any]:
        """Return Graylog cluster system info."""
        return self.get("/api/system")

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Graylog message to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            Raw Graylog message dict (``message`` key or flat dict).

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        msg = native.get("message", native)
        now = _now_ts()
        ts  = msg.get("timestamp") or now

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (msg.get("src_ip"), msg.get("dst_ip")):
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

        src_ip  = msg.get("src_ip")
        dst_ip  = msg.get("dst_ip")
        src_p   = msg.get("src_port")
        dst_p   = msg.get("dst_port")
        if src_ip and dst_ip and (src_p or dst_p):
            key = f"{src_ip}:{src_p}-{dst_ip}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id":   nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
                    "protocols": [str(msg.get("protocol", "tcp")).lower()],
                }
                if src_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_port"] = int(src_p)
                if dst_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_port"] = int(dst_p)
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
            "x_graylog_message": {
                "message_id": msg.get("_id"),
                "source":     msg.get("source"),
                "level":      msg.get("level"),
                "facility":   msg.get("facility"),
                "message":    msg.get("message"),
                "streams":    msg.get("streams", []),
            },
        }
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX observed-data object to a Graylog search query.

        Returns a query dict suitable for passing to ``search_messages()``.
        """
        stix_type = stix_dict.get("type", "")
        if stix_type != "observed-data":
            raise GNATClientError(
                f"GraylogClient.from_stix: expected 'observed-data', got '{stix_type}'"
            )
        graylog = stix_dict.get("x_graylog_message", {})
        query_parts = []
        if graylog.get("source"):
            query_parts.append(f"source:{graylog['source']}")
        if graylog.get("level") is not None:
            query_parts.append(f"level:{graylog['level']}")
        return {
            "query": " AND ".join(query_parts) if query_parts else "*",
            "stix_id": stix_dict.get("id", ""),
        }
