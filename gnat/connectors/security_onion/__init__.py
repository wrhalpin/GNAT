# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Security Onion Connector
===================================
Connector for Security Onion Network Security Monitoring platform.

Security Onion exposes a REST API (so-api) on port 8080 that provides
access to alerts, cases, grid (asset) data, and PCAP retrieval.
The underlying data store is Elasticsearch, so search queries use
ES Query DSL passed through the so-api layer.

Auth: Bearer token
  POST /api/login  →  {"token": "<jwt>"}
  All requests: Authorization: Bearer <token>
  Tokens expire after a configurable period (default 24h).

Key domains:
  Alerts   — security alerts from detection engines (Suricata, Zeek, etc.)
  Cases    — incident management cases
  Grid     — sensor node inventory and health
  PCAP     — packet capture retrieval for alert pivot
  Hunt     — saved hunt queries (Sigma/EQL based)

STIX 2.1: No native support. Mapper converts alerts → observed-data bundles.

Dev access: Fully free, open source.
  ISO/Docker: https://docs.securityonion.net/en/2.4/installation.html

Configuration (gnat.ini):
  [security_onion]
  url           = https://securityonion.corp.example.com
  username      =
  password      =
  verify_ssl    = true
  timeout       = 30
  max_results   = 100
"""

import configparser
import json
import time
import urllib.parse
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import urllib3

# ── Exceptions ────────────────────────────────────────────────────────────────


class SecurityOnionError(Exception):
    """Base exception for Security Onion connector."""


class SecurityOnionConfigError(SecurityOnionError):
    """Raised when a security onion config error error occurs."""


class SecurityOnionAuthError(SecurityOnionError):
    """Raised when a security onion auth error error occurs."""


class SecurityOnionAPIError(SecurityOnionError):
    """Raised when a security onion a p i error error occurs."""
    def __init__(self, message, status_code=None, endpoint=None):
        """Initialize SecurityOnionAPIError."""
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class SecurityOnionNotFoundError(SecurityOnionAPIError):
    """Raised when a security onion not found error error occurs."""


class SecurityOnionSTIXError(SecurityOnionError):
    """Raised when a security onion s t i x error error occurs."""


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class SecurityOnionConfig:
    """Configuration container for security onion."""
    url: str
    username: str
    password: str
    verify_ssl: bool = True
    timeout: int = 30
    max_results: int = 100
    base_url: str = field(init=False)

    def __post_init__(self):
        """Post-init setup for SecurityOnionConfig."""
        if not self.url:
            raise SecurityOnionConfigError("'url' required in [security_onion].")
        if not self.username:
            raise SecurityOnionConfigError("'username' required.")
        if not self.password:
            raise SecurityOnionConfigError("'password' required.")
        self.base_url = self.url.rstrip("/")

    def endpoint(self, path: str) -> str:
        """Endpoint."""
        return f"{self.base_url}/api/{path.lstrip('/')}"

    @property
    def login_url(self) -> str:
        """Login url."""
        return f"{self.base_url}/api/login"


def load_security_onion_config(
    config: configparser.ConfigParser, section: str = "security_onion"
) -> SecurityOnionConfig:
    """Load security onion config from the configured source."""
    if not config.has_section(section):
        raise SecurityOnionConfigError(f"Section '[{section}]' not found.")
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
        raise SecurityOnionConfigError(f"Missing required keys: {missing}")
    return SecurityOnionConfig(
        url=raw["url"].strip(),
        username=raw["username"].strip(),
        password=raw["password"].strip(),
        verify_ssl=raw["verify_ssl"].strip().lower() in ("true", "1", "yes"),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
    )


# ── Auth Manager ──────────────────────────────────────────────────────────────


class SecurityOnionAuthManager:
    """JWT-based auth for Security Onion so-api."""

    _TOKEN_EXPIRY_SECS = 86400  # 24h default

    def __init__(self, config: SecurityOnionConfig, http: urllib3.PoolManager):
        """Initialize SecurityOnionAuthManager."""
        self._config = config
        self._http = http
        self._token: str | None = None
        self._acquired_at: float = 0.0

    def get_headers(self) -> dict:
        """Retrieve headers."""
        if not self._token_valid():
            self._login()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def invalidate(self):
        """Invalidate."""
        self._token = None

    def _token_valid(self) -> bool:
        """Internal helper for token valid."""
        if not self._token:
            return False
        return (time.time() - self._acquired_at) < (self._TOKEN_EXPIRY_SECS * 0.8)

    def _login(self):
        """Internal helper for login."""
        body = json.dumps(
            {
                "user": self._config.username,
                "password": self._config.password,
            }
        ).encode()
        try:
            resp = self._http.request(
                "POST",
                self._config.login_url,
                body=body,
                headers={"Content-Type": "application/json"},
                timeout=self._config.timeout,
            )
        except urllib3.exceptions.HTTPError as e:
            raise SecurityOnionAuthError(f"Login failed: {e}") from e
        if resp.status == 401:
            raise SecurityOnionAuthError("Invalid username or password.")
        if resp.status != 200:
            raise SecurityOnionAuthError(f"Login returned HTTP {resp.status}.")
        try:
            self._token = json.loads(resp.data.decode())["token"]
            self._acquired_at = time.time()
        except (KeyError, json.JSONDecodeError) as e:
            raise SecurityOnionAuthError(f"Could not parse login token: {e}") from e


# ── Client ────────────────────────────────────────────────────────────────────


class SecurityOnionClient:
    """HTTP client for the Security Onion so-api."""

    _RETRYABLE = {500, 502, 503, 504}

    def __init__(self, config: SecurityOnionConfig):
        """Initialize SecurityOnionClient."""
        self.config = config
        self._http = self._build_pool()
        self.auth = SecurityOnionAuthManager(config, self._http)

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
        return self._request("GET", url)

    def post(self, path: str, body: dict | None = None) -> dict | list:
        """Post."""
        return self._request("POST", self.config.endpoint(path), body=body)

    def delete(self, path: str) -> dict:
        """Delete."""
        return self._request("DELETE", self.config.endpoint(path))

    def paginate(self, path: str, params: dict | None = None, page_size: int | None = None):
        """Generator using offset+limit pagination."""
        limit = page_size or self.config.max_results
        offset = 0
        base = dict(params or {})
        base["limit"] = limit
        while True:
            base["offset"] = offset
            response = self.get(path, params=base)
            items = response if isinstance(response, list) else response.get("data", [])
            if not items:
                break
            yield from items
            offset += len(items)
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

    def _request(self, method: str, url: str, body: dict | None = None) -> dict | list:
        """Internal helper for request."""
        headers = self.auth.get_headers()
        encoded = json.dumps(body).encode() if body else None
        delay = 1.0
        for attempt in range(4):
            try:
                resp = self._http.request(method, url, body=encoded, headers=headers)
            except urllib3.exceptions.HTTPError as e:
                if attempt < 3:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise SecurityOnionAPIError(str(e), endpoint=url) from e
            if resp.status == 401 and attempt == 0:
                self.auth.invalidate()
                headers = self.auth.get_headers()
                continue
            if resp.status == 403:
                raise SecurityOnionAuthError("Insufficient permissions (HTTP 403).")
            if resp.status == 404:
                raise SecurityOnionNotFoundError(f"Not found: {url}", 404, url)
            if resp.status in self._RETRYABLE and attempt < 3:
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status not in (200, 201):
                raise SecurityOnionAPIError(f"Unexpected HTTP {resp.status}.", resp.status, url)
            try:
                return json.loads(resp.data.decode("utf-8"))
            except Exception as e:
                raise SecurityOnionAPIError(f"JSON parse error: {e}", endpoint=url) from e
        raise SecurityOnionAPIError("Request failed after retries.", endpoint=url)


# ── Alert Commands ────────────────────────────────────────────────────────────


class SecurityOnionAlertCommands:
    """Alert query and management operations."""

    def __init__(self, client: SecurityOnionClient):
        """Initialize SecurityOnionAlertCommands."""
        self._client = client

    def search_alerts(
        self,
        query: dict | None = None,
        size: int | None = None,
        from_: int = 0,
        sort: list | None = None,
        time_range: tuple[str, str] | None = None,
    ) -> dict:
        """
        Search alerts using ES Query DSL passed through so-api.

        Parameters
        ----------
        query : dict | None
            ES Query DSL query clause. Defaults to match_all.
        size : int | None
            Max results.
        from_ : int
            Pagination offset.
        sort : list | None
            ES sort spec.
        time_range : tuple[str, str] | None
            (start_iso, end_iso) for @timestamp filter.
        """
        must: list = []
        if time_range:
            must.append({"range": {"@timestamp": {"gte": time_range[0], "lte": time_range[1]}}})
        if query:
            must.append(query)
        body: dict = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": size or self._client.config.max_results,
            "from": from_,
        }
        if sort:
            body["sort"] = sort
        else:
            body["sort"] = [{"@timestamp": {"order": "desc"}}]
        return self._client.post("alerts/_search", body=body)

    def get_alert_hits(
        self,
        query: dict | None = None,
        size: int | None = None,
        time_range: tuple[str, str] | None = None,
    ) -> list[dict]:
        """Return _source dicts from alert search hits."""
        result = self.search_alerts(query=query, size=size, time_range=time_range)
        return [h.get("_source", {}) for h in result.get("hits", {}).get("hits", [])]

    def get_alert(self, alert_id: str) -> dict:
        """Retrieve a single alert by ID."""
        return self._client.get(f"alerts/{alert_id}")

    def acknowledge_alert(self, alert_id: str) -> dict:
        """Mark an alert as acknowledged."""
        return self._client.post(f"alerts/{alert_id}/acknowledge")

    def escalate_alert(self, alert_id: str) -> dict:
        """Escalate an alert to a case."""
        return self._client.post(f"alerts/{alert_id}/escalate")

    def get_alert_count(self, query: dict | None = None) -> int:
        """Count alerts matching a query."""
        body: dict = {"query": query or {"match_all": {}}}
        result = self._client.post("alerts/_count", body=body)
        return result.get("count", 0)

    @staticmethod
    def normalise_alert(alert: dict) -> dict:
        """Flatten a Security Onion alert to GNAT normalised format."""
        rule = alert.get("rule", {})
        sev_map = {"1": 4, "2": 3, "3": 2, "4": 1, 1: 4, 2: 3, 3: 2, 4: 1}
        sev_raw = alert.get("event", {}).get("severity", 3)
        return {
            "id": alert.get("uid") or alert.get("_id"),
            "timestamp": alert.get("@timestamp"),
            "rule_name": rule.get("name"),
            "rule_id": rule.get("uuid"),
            "category": alert.get("event", {}).get("category"),
            "severity": sev_map.get(sev_raw, 2),
            "src_ip": alert.get("source", {}).get("ip"),
            "dst_ip": alert.get("destination", {}).get("ip"),
            "src_port": alert.get("source", {}).get("port"),
            "dst_port": alert.get("destination", {}).get("port"),
            "proto": alert.get("network", {}).get("transport"),
            "sensor": alert.get("observer", {}).get("name"),
            "_raw": alert,
        }


# ── Case Commands ─────────────────────────────────────────────────────────────


class SecurityOnionCaseCommands:
    """Case management operations."""

    def __init__(self, client: SecurityOnionClient):
        """Initialize SecurityOnionCaseCommands."""
        self._client = client

    def list_cases(
        self,
        status: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """List all cases objects."""
        params: dict = {}
        if status:
            params["status"] = status
        if limit:
            params["limit"] = limit
        result = self._client.get("cases", params=params)
        return result if isinstance(result, list) else result.get("data", [])

    def get_case(self, case_id: str) -> dict:
        """Retrieve case."""
        return self._client.get(f"cases/{case_id}")

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: int = 2,
        assignee: str | None = None,
    ) -> dict:
        """Create a new case."""
        body: dict = {"title": title, "description": description, "severity": severity}
        if assignee:
            body["assignee"] = assignee
        return self._client.post("cases", body=body)

    def add_comment(self, case_id: str, comment: str) -> dict:
        """Create a new comment."""
        return self._client.post(f"cases/{case_id}/comments", body={"value": comment})

    def close_case(self, case_id: str) -> dict:
        """Close case."""
        return self._client.post(f"cases/{case_id}/close")


# ── Grid Commands ─────────────────────────────────────────────────────────────


class SecurityOnionGridCommands:
    """Sensor grid / node inventory operations."""

    def __init__(self, client: SecurityOnionClient):
        """Initialize SecurityOnionGridCommands."""
        self._client = client

    def list_nodes(self) -> list[dict]:
        """List all sensor nodes in the grid."""
        result = self._client.get("grid")
        return result if isinstance(result, list) else result.get("nodes", [])

    def get_node(self, node_id: str) -> dict:
        """Retrieve node."""
        return self._client.get(f"grid/{node_id}")

    def get_grid_status(self) -> dict:
        """Return overall grid health status."""
        return self._client.get("grid/status")


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class SecurityOnionSTIXMapper:
    """Maps Security Onion alerts to STIX 2.1 observed-data bundles."""

    def alert_to_stix_bundle(self, alert: dict) -> dict:
        """Convert a normalised Security Onion alert to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = alert.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
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

        src_port = alert.get("src_port")
        dst_port = alert.get("dst_port")
        if alert.get("src_ip") and alert.get("dst_ip") and (src_port or dst_port):
            key = f"{alert.get('src_ip')}:{src_port}-{alert.get('dst_ip')}:{dst_port}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['src_ip'])}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['dst_ip'])}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_port:
                    nt["src_port"] = int(src_port)
                if dst_port:
                    nt["dst_port"] = int(dst_port)
                objects.append(nt)
                refs.append(nid)

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
                "x_security_onion_alert": {
                    "alert_id": alert.get("id"),
                    "rule_name": alert.get("rule_name"),
                    "rule_id": alert.get("rule_id"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "sensor": alert.get("sensor"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def alerts_to_stix_bundle(self, alerts: list[dict]) -> dict:
        """Alerts to stix bundle."""
        all_objects: list[dict] = []
        seen: set[str] = set()
        for a in alerts:
            for obj in self.alert_to_stix_bundle(a).get("objects", []):
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
