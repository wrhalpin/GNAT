# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Graylog Connector
===========================
Connector for Graylog SIEM / log management platform.

Auth: HTTP Basic (username:password base64)
  Authorization: Basic <base64(username:password)>
  Also requires: X-Requested-By: GNAT (on all write requests)

Base URL: https://<host>:<port>/api

Pagination: offset + limit query params
  Response: {"total": N, "count": N, "messages": [...]}

Key domains:
  Search      — full-text and field-filter search
  Streams     — log stream management
  Alerts      — alert definitions and event notifications
  Dashboards  — dashboard listing
  System      — cluster health, nodes, inputs

STIX: No native support. Mapper converts log messages → observed-data.

Dev access: Free Community Edition.
  https://graylog.org/downloads/

Configuration (gnat.ini):
  [graylog]
  url         = https://graylog.corp.example.com:9000
  username    =
  password    =
  verify_ssl  = true
  timeout     = 30
  max_results = 100
"""

import base64
import configparser
import json
import time
import urllib.parse
import uuid as _uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone

import urllib3

# ── Exceptions ────────────────────────────────────────────────────────────────


class GraylogError(Exception):
    """Raised when a graylog error error occurs."""
    pass


class GraylogConfigError(GraylogError):
    """Raised when a graylog config error error occurs."""
    pass


class GraylogAuthError(GraylogError):
    """Raised when a graylog auth error error occurs."""
    pass


class GraylogAPIError(GraylogError):
    """Raised when a graylog a p i error error occurs."""
    def __init__(self, message, status_code=None, endpoint=None):
        """Initialize GraylogAPIError."""
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class GraylogNotFoundError(GraylogAPIError):
    """Raised when a graylog not found error error occurs."""
    pass


class GraylogSTIXError(GraylogError):
    """Raised when a graylog s t i x error error occurs."""
    pass


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class GraylogConfig:
    """Configuration container for graylog."""
    url: str
    username: str
    password: str
    verify_ssl: bool = True
    timeout: int = 30
    max_results: int = 100
    base_url: str = field(init=False)
    auth_header: str = field(init=False)

    def __post_init__(self):
        """Post-init setup for GraylogConfig."""
        if not self.url:
            raise GraylogConfigError("'url' required in [graylog].")
        if not self.username:
            raise GraylogConfigError("'username' required.")
        if not self.password:
            raise GraylogConfigError("'password' required.")
        self.base_url = self.url.rstrip("/")
        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        self.auth_header = f"Basic {creds}"

    def endpoint(self, path: str) -> str:
        """Endpoint."""
        return f"{self.base_url}/api/{path.lstrip('/')}"

    @property
    def base_headers(self) -> dict:
        """Base headers."""
        return {
            "Authorization": self.auth_header,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @property
    def write_headers(self) -> dict:
        """Graylog requires X-Requested-By on all non-GET requests."""
        return {**self.base_headers, "X-Requested-By": "GNAT"}


def load_graylog_config(
    config: configparser.ConfigParser, section: str = "graylog"
) -> GraylogConfig:
    """Load graylog config from the configured source."""
    if not config.has_section(section):
        raise GraylogConfigError(f"Section '[{section}]' not found.")
    raw = {
        "url": "",
        "username": "",
        "password": "",
        "verify_ssl": "true",
        "timeout": "30",
        "max_results": "100",
    }
    raw.update(dict(config.items(section)))
    missing = [k for k in ("url", "username", "password") if not raw[k].strip()]
    if missing:
        raise GraylogConfigError(f"Missing required keys: {missing}")
    return GraylogConfig(
        url=raw["url"].strip(),
        username=raw["username"].strip(),
        password=raw["password"].strip(),
        verify_ssl=raw["verify_ssl"].strip().lower() in ("true", "1", "yes"),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
    )


# ── Client ────────────────────────────────────────────────────────────────────


class GraylogClient:
    """HTTP client for the Graylog REST API."""

    _RETRYABLE = {500, 502, 503, 504}

    def __init__(self, config: GraylogConfig):
        """Initialize GraylogClient."""
        self.config = config
        self._http = self._build_pool()

    def __enter__(self):
        """Enter the context manager."""
        return self

    def __exit__(self, *_):
        """Exit the context manager, handling any exceptions."""
        self.close()

    def close(self):
        """Release resources and close any open connections."""
        self._http.clear()

    def get(self, path: str, params: dict | None = None) -> dict | list:
        """Get."""
        url = self.config.endpoint(path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._request("GET", url, headers=self.config.base_headers)

    def post(self, path: str, body: dict | None = None) -> dict | list:
        """Post."""
        return self._request(
            "POST", self.config.endpoint(path), body=body, headers=self.config.write_headers
        )

    def put(self, path: str, body: dict | None = None) -> dict | list:
        """Put."""
        return self._request(
            "PUT", self.config.endpoint(path), body=body, headers=self.config.write_headers
        )

    def delete(self, path: str) -> dict:
        """Delete."""
        return self._request(
            "DELETE", self.config.endpoint(path), headers=self.config.write_headers
        )

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int | None = None,
        items_key: str = "messages",
    ) -> Iterator[dict]:
        """Generator using offset+limit Graylog pagination."""
        limit = page_size or self.config.max_results
        offset = 0
        base = dict(params or {})
        base["limit"] = limit
        total: int | None = None
        while True:
            base["offset"] = offset
            response = self.get(path, params=base)
            if total is None:
                total = response.get("total", 0) if isinstance(response, dict) else 0
            items = response.get(items_key, []) if isinstance(response, dict) else response
            if not items:
                break
            yield from items
            offset += len(items)
            if total is not None and offset >= total:
                break
            if len(items) < limit:
                break

    def _build_pool(self) -> urllib3.PoolManager:
        """Internal helper for build pool."""
        kw = {
            "num_pools": 4,
            "maxsize": 10,
            "timeout": urllib3.Timeout(connect=10.0, read=float(self.config.timeout)),
            "retries": urllib3.Retry(total=0, raise_on_status=False),
        }
        if not self.config.verify_ssl:
            kw["cert_reqs"] = "CERT_NONE"
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            kw["cert_reqs"] = "CERT_REQUIRED"
        return urllib3.PoolManager(**kw)

    def _request(
        self, method: str, url: str, body: dict | None = None, headers: dict | None = None
    ) -> dict | list:
        """Internal helper for request."""
        hdrs = headers or self.config.base_headers
        encoded = json.dumps(body).encode() if body else None
        delay = 1.0
        for attempt in range(4):
            try:
                resp = self._http.request(method, url, body=encoded, headers=hdrs)
            except urllib3.exceptions.HTTPError as e:
                if attempt < 3:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise GraylogAPIError(str(e), endpoint=url) from e
            if resp.status in (401, 403):
                raise GraylogAuthError(
                    f"Authentication failed (HTTP {resp.status}). Check credentials."
                )
            if resp.status == 404:
                raise GraylogNotFoundError(f"Not found: {url}", 404, url)
            if resp.status in self._RETRYABLE and attempt < 3:
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status not in (200, 201, 204):
                raise GraylogAPIError(f"HTTP {resp.status}", resp.status, url)
            if resp.status == 204 or not resp.data:
                return {}
            try:
                return json.loads(resp.data.decode("utf-8"))
            except Exception as e:
                raise GraylogAPIError(f"JSON parse error: {e}", endpoint=url) from e
        raise GraylogAPIError("Request failed.", endpoint=url)


# ── Search Commands ───────────────────────────────────────────────────────────


class GraylogSearchCommands:
    """Log message search operations."""

    def __init__(self, client: GraylogClient):
        """Initialize GraylogSearchCommands."""
        self._client = client

    def search(
        self,
        query: str = "*",
        time_range: int = 300,
        limit: int | None = None,
        offset: int = 0,
        filter_val: str | None = None,
        sort: str | None = None,
        fields: str | None = None,
    ) -> dict:
        """
        Universal search across all streams.

        Parameters
        ----------
        query : str
            Graylog query string (Lucene syntax).
        time_range : int
            Relative time range in seconds.
        limit : int | None
            Max messages.
        offset : int
            Pagination offset.
        filter_val : str | None
            Stream filter, e.g. 'streams:STREAM_ID'.
        sort : str | None
            Sort field:order, e.g. 'timestamp:desc'.
        fields : str | None
            Comma-separated field list.
        """
        params: dict = {
            "query": query,
            "range": time_range,
            "limit": limit or self._client.config.max_results,
            "offset": offset,
        }
        if filter_val:
            params["filter"] = filter_val
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields
        return self._client.get("search/universal/relative", params=params)

    def search_absolute(
        self,
        query: str,
        from_ts: str,
        to_ts: str,
        limit: int | None = None,
        offset: int = 0,
        fields: str | None = None,
    ) -> dict:
        """
        Search with absolute time range.

        Parameters
        ----------
        from_ts : str
            ISO 8601 start timestamp.
        to_ts : str
            ISO 8601 end timestamp.
        """
        params: dict = {
            "query": query,
            "from": from_ts,
            "to": to_ts,
            "limit": limit or self._client.config.max_results,
            "offset": offset,
        }
        if fields:
            params["fields"] = fields
        return self._client.get("search/universal/absolute", params=params)

    def get_messages(
        self,
        query: str = "*",
        time_range: int = 300,
        limit: int | None = None,
    ) -> list[dict]:
        """Return the message list from a relative search."""
        result = self.search(query=query, time_range=time_range, limit=limit)
        return result.get("messages", [])

    def iter_messages(
        self,
        query: str = "*",
        time_range: int = 3600,
        page_size: int | None = None,
    ) -> Iterator[dict]:
        """Generator yielding all messages from a paginated search."""
        limit = page_size or self._client.config.max_results
        offset = 0
        total: int | None = None
        while True:
            result = self.search(query=query, time_range=time_range, limit=limit, offset=offset)
            if total is None:
                total = result.get("total_results", 0)
            messages = result.get("messages", [])
            yield from messages
            offset += len(messages)
            if not messages or (total and offset >= total):
                break

    def field_histogram(
        self,
        query: str,
        field_name: str,
        interval: str = "hour",
        time_range: int = 86400,
    ) -> dict:
        """Get a histogram of a field's values over time."""
        return self._client.get(
            "search/universal/relative/histogram",
            params={"query": query, "field": field_name, "interval": interval, "range": time_range},
        )

    def field_terms(
        self,
        query: str,
        field_name: str,
        size: int = 10,
        time_range: int = 86400,
    ) -> dict:
        """Get top terms for a field."""
        return self._client.get(
            "search/universal/relative/terms",
            params={"query": query, "field": field_name, "size": size, "range": time_range},
        )

    @staticmethod
    def normalise_message(msg: dict) -> dict:
        """Flatten a Graylog message wrapper to GNAT normalised format."""
        fields = msg.get("message", {})
        return {
            "id": fields.get("_id"),
            "timestamp": fields.get("timestamp"),
            "source": fields.get("source"),
            "message": fields.get("message"),
            "level": fields.get("level"),
            "facility": fields.get("facility"),
            "src_ip": fields.get("src_ip") or fields.get("source_ip"),
            "dst_ip": fields.get("dst_ip") or fields.get("destination_ip"),
            "src_port": fields.get("src_port"),
            "dst_port": fields.get("dst_port"),
            "username": fields.get("user") or fields.get("username"),
            "stream_ids": msg.get("stream_ids", []),
            "_raw": fields,
        }


# ── Stream Commands ───────────────────────────────────────────────────────────


class GraylogStreamCommands:
    """Stream management operations."""

    def __init__(self, client: GraylogClient):
        """Initialize GraylogStreamCommands."""
        self._client = client

    def list_streams(self) -> list[dict]:
        """List all streams objects."""
        result = self._client.get("streams")
        return result.get("streams", [])

    def get_stream(self, stream_id: str) -> dict:
        """Retrieve stream."""
        return self._client.get(f"streams/{stream_id}")

    def pause_stream(self, stream_id: str) -> dict:
        """Pause stream."""
        return self._client.post(f"streams/{stream_id}/pause")

    def resume_stream(self, stream_id: str) -> dict:
        """Resume stream."""
        return self._client.post(f"streams/{stream_id}/resume")

    def get_stream_throughput(self, stream_id: str) -> dict:
        """Retrieve stream throughput."""
        return self._client.get(f"streams/{stream_id}/throughput")


# ── System Commands ───────────────────────────────────────────────────────────


class GraylogSystemCommands:
    """Cluster and system health operations."""

    def __init__(self, client: GraylogClient):
        """Initialize GraylogSystemCommands."""
        self._client = client

    def get_system_info(self) -> dict:
        """Retrieve system info."""
        return self._client.get("system")

    def get_cluster_nodes(self) -> list[dict]:
        """Retrieve cluster nodes."""
        result = self._client.get("system/cluster/nodes")
        return result.get("nodes", [])

    def get_inputs(self) -> list[dict]:
        """Retrieve inputs."""
        result = self._client.get("system/inputs")
        return result.get("inputs", [])

    def get_metrics(self, namespace: str = "") -> dict:
        """Retrieve metrics."""
        path = "system/metrics"
        if namespace:
            path += f"/namespace/{namespace}"
        return self._client.get(path)

    def get_throughput(self) -> dict:
        """Retrieve throughput."""
        return self._client.get("system/throughput")


# ── Alert Commands ────────────────────────────────────────────────────────────


class GraylogAlertCommands:
    """Alert and event notification operations."""

    def __init__(self, client: GraylogClient):
        """Initialize GraylogAlertCommands."""
        self._client = client

    def list_alerts(self, state: str | None = None, limit: int | None = None) -> list[dict]:
        """List all alerts objects."""
        params: dict = {"limit": limit or self._client.config.max_results}
        if state:
            params["state"] = state
        result = self._client.get("events/definitions", params=params)
        return result.get("event_definitions", [])

    def get_alert(self, alert_id: str) -> dict:
        """Retrieve alert."""
        return self._client.get(f"events/definitions/{alert_id}")

    def list_alert_events(self, limit: int | None = None) -> list[dict]:
        """List triggered alert events."""
        params = {"per_page": limit or self._client.config.max_results}
        result = self._client.get("events/search", params=params)
        return result.get("events", [])


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class GraylogSTIXMapper:
    """Maps Graylog log messages to STIX 2.1 observed-data bundles."""

    def message_to_stix_bundle(self, msg: dict) -> dict:
        """Convert a normalised Graylog message to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = msg.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (msg.get("src_ip"), msg.get("dst_ip")):
            if ip:
                obj = {
                    "type": "ipv4-addr",
                    "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}",
                    "spec_version": "2.1",
                    "value": ip,
                }
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        if user := msg.get("username"):
            uid = f"user-account--{_det_uuid('user-account', user)}"
            if uid not in seen:
                seen.add(uid)
                objects.append(
                    {"type": "user-account", "id": uid, "spec_version": "2.1", "user_id": user}
                )
            refs.append(uid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        objects.append(
            {
                "type": "observed-data",
                "id": obs_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_graylog_message": {
                    "message_id": msg.get("id"),
                    "source": msg.get("source"),
                    "message": msg.get("message"),
                    "level": msg.get("level"),
                    "facility": msg.get("facility"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def messages_to_stix_bundle(self, messages: list[dict]) -> dict:
        """Messages to stix bundle."""
        all_objects: list[dict] = []
        seen: set[str] = set()
        for m in messages:
            for obj in self.message_to_stix_bundle(m).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": all_objects,
        }


def _det_uuid(t: str, v: str) -> str:
    """Internal helper for det uuid."""
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
