# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT AlienVault OSSIM Connector
=====================================
Connector for AlienVault OSSIM (Open Source SIEM).

Note: AlienVault OSSIM open-source support ended in 2024. This
connector targets OSSIM 5.x which remains widely deployed.
For commercial USM Anywhere, the API surface is similar but
hosted at usm.alienvault.cloud with different auth.

Auth: API key via X-USM-API-KEY header
  Obtained from OSSIM UI: Configuration → Administration → Users → API

Base URL: https://<host>/api/1.0/  (OSSIM 5.x REST API)

Key domains:
  Alarms   — correlated security alarms (the primary security object)
  Events   — raw security events
  Assets   — host/asset inventory
  Sensors  — sensor node inventory
  Plugins  — installed detection plugins

STIX: No native support. Mapper converts alarms → observed-data bundles.

Dev access: Free, open source. OVA download at alienvault.com/products/ossim
  (Note: support ended 2024, community maintained)

Configuration (gnat.ini):
  [ossim]
  url        = https://ossim.corp.example.com
  api_key    =
  verify_ssl = false   ; OSSIM often uses self-signed certs
  timeout    = 30
  max_results = 50
"""

import configparser
import contextlib
import json
import time
import urllib.parse
import uuid as _uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone

import urllib3

# ── Exceptions ────────────────────────────────────────────────────────────────


class OSSIMError(Exception):
    """Raised when a o s s i m error error occurs."""
    pass


class OSSIMConfigError(OSSIMError):
    """Raised when a o s s i m config error error occurs."""
    pass


class OSSIMAuthError(OSSIMError):
    """Raised when a o s s i m auth error error occurs."""
    pass


class OSSIMAPIError(OSSIMError):
    """Raised when a o s s i m a p i error error occurs."""
    def __init__(self, message, status_code=None, endpoint=None):
        """Initialize OSSIMAPIError."""
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class OSSIMNotFoundError(OSSIMAPIError):
    """Raised when a o s s i m not found error error occurs."""
    pass


class OSSIMSTIXError(OSSIMError):
    """Raised when a o s s i m s t i x error error occurs."""
    pass


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class OSSIMConfig:
    """Configuration container for o s s i m."""
    url: str
    api_key: str
    verify_ssl: bool = False  # OSSIM commonly uses self-signed certs
    timeout: int = 30
    max_results: int = 50
    base_url: str = field(init=False)

    def __post_init__(self):
        """Post-init setup for OSSIMConfig."""
        if not self.url:
            raise OSSIMConfigError("'url' required in [ossim].")
        if not self.api_key:
            raise OSSIMConfigError("'api_key' required.")
        self.base_url = self.url.rstrip("/")

    def endpoint(self, path: str) -> str:
        """Endpoint."""
        return f"{self.base_url}/api/1.0/{path.lstrip('/')}"

    @property
    def base_headers(self) -> dict:
        """Base headers."""
        return {
            "X-USM-API-KEY": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


def load_ossim_config(config: configparser.ConfigParser, section: str = "ossim") -> OSSIMConfig:
    """Load ossim config from the configured source."""
    if not config.has_section(section):
        raise OSSIMConfigError(f"Section '[{section}]' not found.")
    raw = {"url": "", "api_key": "", "verify_ssl": "false", "timeout": "30", "max_results": "50"}
    raw.update(dict(config.items(section)))
    missing = [k for k in ("url", "api_key") if not raw[k].strip()]
    if missing:
        raise OSSIMConfigError(f"Missing required keys: {missing}")
    return OSSIMConfig(
        url=raw["url"].strip(),
        api_key=raw["api_key"].strip(),
        verify_ssl=raw["verify_ssl"].strip().lower() in ("true", "1", "yes"),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
    )


# ── Client ────────────────────────────────────────────────────────────────────


class OSSIMClient:
    """HTTP client for the OSSIM REST API."""

    _RETRYABLE = {500, 502, 503, 504}

    def __init__(self, config: OSSIMConfig):
        """Initialize OSSIMClient."""
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
        return self._request("GET", url)

    def post(self, path: str, body: dict | None = None) -> dict | list:
        """Post."""
        return self._request("POST", self.config.endpoint(path), body=body)

    def put(self, path: str, body: dict | None = None) -> dict | list:
        """Put."""
        return self._request("PUT", self.config.endpoint(path), body=body)

    def delete(self, path: str) -> dict:
        """Delete."""
        return self._request("DELETE", self.config.endpoint(path))

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int | None = None,
        items_key: str = "data",
    ) -> Iterator[dict]:
        """Generator using page+page_items OSSIM pagination."""
        limit = page_size or self.config.max_results
        page = 1
        total: int | None = None
        base = dict(params or {})
        base["page_items"] = limit
        while True:
            base["page"] = page
            response = self.get(path, params=base)
            if total is None:
                total = response.get("total", 0) if isinstance(response, dict) else 0
            items = response.get(items_key, []) if isinstance(response, dict) else response
            if not items:
                break
            yield from items
            page += 1
            if total and (page - 1) * limit >= total:
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

    def _request(self, method: str, url: str, body: dict | None = None) -> dict | list:
        """Internal helper for request."""
        headers = self.config.base_headers
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
                raise OSSIMAPIError(str(e), endpoint=url) from e
            if resp.status in (401, 403):
                raise OSSIMAuthError(f"Authentication failed (HTTP {resp.status}). Check api_key.")
            if resp.status == 404:
                raise OSSIMNotFoundError(f"Not found: {url}", 404, url)
            if resp.status in self._RETRYABLE and attempt < 3:
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status not in (200, 201, 204):
                raise OSSIMAPIError(f"HTTP {resp.status}", resp.status, url)
            if resp.status == 204 or not resp.data:
                return {}
            try:
                return json.loads(resp.data.decode("utf-8"))
            except Exception as e:
                raise OSSIMAPIError(f"JSON parse error: {e}", endpoint=url) from e
        raise OSSIMAPIError("Request failed.", endpoint=url)


# ── Alarm Commands ────────────────────────────────────────────────────────────


class OSSIMAlarmCommands:
    """Alarm management operations — OSSIM's primary security object."""

    def __init__(self, client: OSSIMClient):
        """Initialize OSSIMAlarmCommands."""
        self._client = client

    def list_alarms(
        self,
        status: str | None = None,
        priority: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List OSSIM alarms.

        Parameters
        ----------
        status : str | None
            'open', 'closed', 'unresolved'.
        priority : int | None
            Filter by priority (1–5).
        limit : int | None
            Max results.
        """
        params: dict = {"page_items": limit or self._client.config.max_results}
        if status:
            params["status"] = status
        if priority is not None:
            params["priority"] = priority
        result = self._client.get("alarms", params=params)
        return result.get("data", [])

    def iter_all_alarms(self, status: str | None = None) -> Iterator[dict]:
        """Generator yielding all alarms."""
        params: dict = {}
        if status:
            params["status"] = status
        yield from self._client.paginate("alarms", params=params)

    def get_alarm(self, alarm_id: str) -> dict:
        """Retrieve a single alarm by UUID."""
        return self._client.get(f"alarms/{alarm_id}")

    def get_alarm_events(self, alarm_id: str) -> list[dict]:
        """Get raw events associated with an alarm."""
        result = self._client.get(f"alarms/{alarm_id}/events")
        return result.get("data", [])

    def close_alarm(self, alarm_id: str) -> dict:
        """Close an alarm."""
        return self._client.put(f"alarms/{alarm_id}", body={"status": "closed"})

    def delete_alarm(self, alarm_id: str) -> dict:
        """Delete an alarm."""
        return self._client.delete(f"alarms/{alarm_id}")

    @staticmethod
    def normalise_alarm(alarm: dict) -> dict:
        """Flatten an OSSIM alarm to GNAT normalised format."""
        prio = int(alarm.get("priority", 1))
        sev_map = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4}
        return {
            "id": alarm.get("uuid") or alarm.get("id"),
            "timestamp": alarm.get("timestamp"),
            "name": alarm.get("rule_name") or alarm.get("name"),
            "priority": prio,
            "severity": sev_map.get(prio, 1),
            "status": alarm.get("status"),
            "src_ip": alarm.get("src_ip"),
            "dst_ip": alarm.get("dst_ip"),
            "src_port": alarm.get("src_port"),
            "dst_port": alarm.get("dst_port"),
            "protocol": alarm.get("protocol"),
            "sensor": alarm.get("sensor"),
            "event_count": alarm.get("event_count", 0),
            "_raw": alarm,
        }


# ── Event Commands ────────────────────────────────────────────────────────────


class OSSIMEventCommands:
    """Raw security event operations."""

    def __init__(self, client: OSSIMClient):
        """Initialize OSSIMEventCommands."""
        self._client = client

    def search_events(
        self,
        query: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Search for events matching the query."""
        params: dict = {"page_items": limit or self._client.config.max_results}
        if query:
            params["q"] = query
        if src_ip:
            params["src_ip"] = src_ip
        if dst_ip:
            params["dst_ip"] = dst_ip
        result = self._client.get("events", params=params)
        return result.get("data", [])


# ── Asset Commands ────────────────────────────────────────────────────────────


class OSSIMAssetCommands:
    """Asset / host inventory operations."""

    def __init__(self, client: OSSIMClient):
        """Initialize OSSIMAssetCommands."""
        self._client = client

    def list_assets(self, limit: int | None = None) -> list[dict]:
        """List all assets objects."""
        params = {"page_items": limit or self._client.config.max_results}
        result = self._client.get("assets", params=params)
        return result.get("data", [])

    def get_asset(self, asset_id: str) -> dict:
        """Retrieve asset."""
        return self._client.get(f"assets/{asset_id}")

    def search_by_ip(self, ip: str) -> list[dict]:
        """Search for by ip matching the query."""
        params = {"ip": ip, "page_items": 50}
        result = self._client.get("assets", params=params)
        return result.get("data", [])

    def iter_all_assets(self) -> Iterator[dict]:
        """Iter all assets."""
        yield from self._client.paginate("assets")


# ── Sensor Commands ───────────────────────────────────────────────────────────


class OSSIMSensorCommands:
    """Sensor node inventory."""

    def __init__(self, client: OSSIMClient):
        """Initialize OSSIMSensorCommands."""
        self._client = client

    def list_sensors(self) -> list[dict]:
        """List all sensors objects."""
        result = self._client.get("sensors")
        return result.get("data", [])

    def get_sensor(self, sensor_id: str) -> dict:
        """Retrieve sensor."""
        return self._client.get(f"sensors/{sensor_id}")


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class OSSIMSTIXMapper:
    """Maps OSSIM alarms to STIX 2.1 observed-data bundles."""

    def alarm_to_stix_bundle(self, alarm: dict) -> dict:
        """Convert a normalised OSSIM alarm to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = alarm.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (alarm.get("src_ip"), alarm.get("dst_ip")):
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

        src_p = alarm.get("src_port")
        dst_p = alarm.get("dst_port")
        if alarm.get("src_ip") and alarm.get("dst_ip") and (src_p or dst_p):
            key = f"{alarm['src_ip']}:{src_p}-{alarm['dst_ip']}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alarm['src_ip'])}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alarm['dst_ip'])}",
                    "protocols": [str(alarm.get("protocol", "tcp")).lower()],
                }
                if src_p:
                    with contextlib.suppress(ValueError, TypeError):
                        nt["src_port"] = int(src_p)
                if dst_p:
                    with contextlib.suppress(ValueError, TypeError):
                        nt["dst_port"] = int(dst_p)
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
                "number_observed": max(1, alarm.get("event_count", 1)),
                "object_refs": refs,
                "x_ossim_alarm": {
                    "alarm_id": alarm.get("id"),
                    "name": alarm.get("name"),
                    "priority": alarm.get("priority"),
                    "severity": alarm.get("severity"),
                    "status": alarm.get("status"),
                    "sensor": alarm.get("sensor"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def alarms_to_stix_bundle(self, alarms: list[dict]) -> dict:
        """Alarms to stix bundle."""
        all_objects: list[dict] = []
        seen: set[str] = set()
        for a in alarms:
            for obj in self.alarm_to_stix_bundle(a).get("objects", []):
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
