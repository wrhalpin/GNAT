# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT AlienVault OTX Connector
===================================
Connector for AlienVault Open Threat Exchange (OTX).

OTX is a free community-driven threat intelligence platform.
It provides IOC feeds (Pulses) contributed by security researchers
and organizations worldwide.

Auth: API key via X-OTX-API-KEY header
  Obtained at: https://otx.alienvault.com → My Profile → OTX Key

Base URL: https://otx.alienvault.com/api/v1

Key domains:
  Pulses      — threat intel collections (like MISP events)
  Indicators  — IOC values within pulses (IPs, domains, hashes, etc.)
  Subscriptions — pulses you're subscribed to
  Feed        — aggregated indicator feed for correlation

Pagination: page + limit query params
  Response: {"count": N, "next": "<url>", "previous": "<url>", "results": [...]}

STIX: No native STIX but maps naturally to STIX indicator SDOs.
      OTX pulses → STIX reports; indicators → STIX SCOs + indicators.

Dev access: Completely free. Register at https://otx.alienvault.com

Configuration (gnat.ini):
  [alienvault_otx]
  api_key      =
  verify_ssl   = true
  timeout      = 30
  max_results  = 50
"""

import configparser
import json
import time
import urllib.parse
import uuid as _uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

import urllib3

# ── Exceptions ────────────────────────────────────────────────────────────────


class OTXError(Exception):
    """Raised when a o t x error error occurs."""


class OTXConfigError(OTXError):
    """Raised when a o t x config error error occurs."""


class OTXAuthError(OTXError):
    """Raised when a o t x auth error error occurs."""


class OTXAPIError(OTXError):
    """Raised when a o t x a p i error error occurs."""
    def __init__(self, message, status_code=None, endpoint=None):
        """Initialize OTXAPIError."""
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class OTXNotFoundError(OTXAPIError):
    """Raised when a o t x not found error error occurs."""


class OTXRateLimitError(OTXAPIError):
    """Raised when a o t x rate limit error error occurs."""


class OTXSTIXError(OTXError):
    """Raised when a o t x s t i x error error occurs."""


# ── Config ────────────────────────────────────────────────────────────────────

_OTX_BASE = "https://otx.alienvault.com/api/v1"


@dataclass
class OTXConfig:
    """Configuration container for o t x."""
    api_key: str
    base_url: str = _OTX_BASE
    verify_ssl: bool = True
    timeout: int = 30
    max_results: int = 50

    def __post_init__(self):
        """Post-init setup for OTXConfig."""
        if not self.api_key:
            raise OTXConfigError("'api_key' required in [alienvault_otx].")
        self.base_url = self.base_url.rstrip("/")

    def endpoint(self, path: str) -> str:
        """Endpoint."""
        return f"{self.base_url}/{path.lstrip('/')}"

    @property
    def base_headers(self) -> dict:
        """Base headers."""
        return {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


def load_otx_config(
    config: configparser.ConfigParser, section: str = "alienvault_otx"
) -> OTXConfig:
    """Load otx config from the configured source."""
    if not config.has_section(section):
        raise OTXConfigError(f"Section '[{section}]' not found.")
    raw = {
        "api_key": "",
        "base_url": _OTX_BASE,
        "verify_ssl": "true",
        "timeout": "30",
        "max_results": "50",
    }
    raw.update(dict(config.items(section)))
    if not raw["api_key"].strip():
        raise OTXConfigError("'api_key' is required in [alienvault_otx].")
    return OTXConfig(
        api_key=raw["api_key"].strip(),
        base_url=raw["base_url"].strip(),
        verify_ssl=raw["verify_ssl"].strip().lower() in ("true", "1", "yes"),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
    )


# ── Client ────────────────────────────────────────────────────────────────────


class OTXClient:
    """HTTP client for the AlienVault OTX API."""

    _RETRYABLE = {500, 502, 503, 504}

    def __init__(self, config: OTXConfig):
        """Initialize OTXClient."""
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

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int | None = None,
    ) -> Iterator[dict]:
        """
        Generator using OTX's page+limit pagination.
        Follows 'next' URL from response until exhausted.
        """
        limit = page_size or self.config.max_results
        url = self.config.endpoint(path)
        base = dict(params or {})
        base["limit"] = limit
        url += "?" + urllib.parse.urlencode(base)

        while url:
            response = self._request("GET", url)
            if isinstance(response, dict):
                results = response.get("results", [])
            else:
                results = response
            yield from results
            # Follow next link directly (OTX provides full URL)
            next_url = response.get("next") if isinstance(response, dict) else None
            url = next_url

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
                raise OTXAPIError(str(e), endpoint=url) from e
            if resp.status == 401:
                raise OTXAuthError("OTX API key rejected (HTTP 401). Check api_key.")
            if resp.status == 403:
                raise OTXAuthError("OTX API key lacks required permissions (HTTP 403).")
            if resp.status == 404:
                raise OTXNotFoundError(f"Not found: {url}", 404, url)
            if resp.status == 429:
                if attempt < 3:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise OTXRateLimitError("OTX rate limit exceeded.", 429, url)
            if resp.status in self._RETRYABLE and attempt < 3:
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status not in (200, 201):
                raise OTXAPIError(f"HTTP {resp.status}", resp.status, url)
            try:
                return json.loads(resp.data.decode("utf-8"))
            except Exception as e:
                raise OTXAPIError(f"JSON parse error: {e}", endpoint=url) from e
        raise OTXAPIError("Request failed.", endpoint=url)


# ── Pulse Commands ────────────────────────────────────────────────────────────


class OTXPulseCommands:
    """
    OTX Pulse management operations.

    Pulses are the primary container in OTX — collections of related IOCs
    contributed by the community or your own organization.
    """

    def __init__(self, client: OTXClient):
        """Initialize OTXPulseCommands."""
        self._client = client

    def list_subscribed_pulses(
        self,
        modified_since: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List pulses you are subscribed to.

        Parameters
        ----------
        modified_since : str | None
            ISO 8601 timestamp — only pulses modified after this.
        limit : int | None
            Max results.
        """
        params: dict = {"limit": limit or self._client.config.max_results}
        if modified_since:
            params["modified_since"] = modified_since
        result = self._client.get("pulses/subscribed", params=params)
        return result.get("results", []) if isinstance(result, dict) else result

    def iter_subscribed_pulses(self, modified_since: str | None = None) -> Iterator[dict]:
        """Generator yielding all subscribed pulses."""
        params: dict = {}
        if modified_since:
            params["modified_since"] = modified_since
        yield from self._client.paginate("pulses/subscribed", params=params)

    def get_pulse(self, pulse_id: str) -> dict:
        """Retrieve a single pulse by ID."""
        return self._client.get(f"pulses/{pulse_id}")

    def get_pulse_indicators(self, pulse_id: str, limit: int | None = None) -> list[dict]:
        """Get all IOC indicators within a pulse."""
        params = {"limit": limit or self._client.config.max_results}
        result = self._client.get(f"pulses/{pulse_id}/indicators", params=params)
        return result.get("results", []) if isinstance(result, dict) else result

    def iter_pulse_indicators(self, pulse_id: str) -> Iterator[dict]:
        """Generator yielding all indicators in a pulse."""
        yield from self._client.paginate(f"pulses/{pulse_id}/indicators")

    def list_my_pulses(self, limit: int | None = None) -> list[dict]:
        """List pulses created by the authenticated user."""
        params = {"limit": limit or self._client.config.max_results}
        result = self._client.get("pulses/my", params=params)
        return result.get("results", []) if isinstance(result, dict) else result

    def create_pulse(
        self,
        name: str,
        description: str = "",
        tlp: str = "white",
        tags: list[str] | None = None,
        indicators: list[dict] | None = None,
        public: bool = True,
    ) -> dict:
        """
        Create a new OTX pulse.

        Parameters
        ----------
        name : str
        description : str
        tlp : str
            'white', 'green', 'amber', or 'red'.
        tags : list[str] | None
        indicators : list[dict] | None
            Each dict needs 'indicator' (value) and 'type' fields.
        public : bool
        """
        body: dict = {
            "name": name,
            "description": description,
            "TLP": tlp,
            "tags": tags or [],
            "indicators": indicators or [],
            "public": public,
        }
        return self._client.post("pulses/create", body=body)

    @staticmethod
    def normalise_pulse(pulse: dict) -> dict:
        """Flatten an OTX pulse to GNAT normalised format."""
        return {
            "id": pulse.get("id"),
            "name": pulse.get("name"),
            "description": pulse.get("description"),
            "author": pulse.get("author_name"),
            "tlp": pulse.get("TLP"),
            "tags": pulse.get("tags", []),
            "created": pulse.get("created"),
            "modified": pulse.get("modified"),
            "indicator_count": pulse.get("indicator_count", 0),
            "public": pulse.get("public", True),
            "adversary": pulse.get("adversary"),
            "targeted_countries": pulse.get("targeted_countries", []),
            "industries": pulse.get("industries", []),
            "malware_families": pulse.get("malware_families", []),
            "attack_ids": pulse.get("attack_ids", []),  # MITRE ATT&CK
            "_raw": pulse,
        }


# ── Indicator Commands ────────────────────────────────────────────────────────

# OTX indicator type → STIX SCO type
_OTX_TO_STIX: dict[str, str] = {
    "IPv4": "ipv4-addr",
    "IPv6": "ipv6-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "file",
    "FileHash-SHA1": "file",
    "FileHash-SHA256": "file",
    "FileHash-SHA512": "file",
    "email": "email-addr",
    "CVE": "vulnerability",
}


class OTXIndicatorCommands:
    """IOC indicator lookup and enrichment."""

    def __init__(self, client: OTXClient):
        """Initialize OTXIndicatorCommands."""
        self._client = client

    def get_ip_details(self, ip: str, section: str = "general") -> dict:
        """
        Get OTX threat context for an IP address.

        Parameters
        ----------
        ip : str
        section : str
            'general', 'reputation', 'geo', 'malware', 'url_list',
            'passive_dns', 'http_scans'.
        """
        return self._client.get(f"indicators/IPv4/{ip}/{section}")

    def get_domain_details(self, domain: str, section: str = "general") -> dict:
        """Get OTX threat context for a domain."""
        return self._client.get(f"indicators/domain/{domain}/{section}")

    def get_url_details(self, url: str, section: str = "general") -> dict:
        """Get OTX threat context for a URL."""
        encoded = urllib.parse.quote(url, safe="")
        return self._client.get(f"indicators/url/{encoded}/{section}")

    def get_file_details(self, hash_value: str, section: str = "general") -> dict:
        """Get OTX threat context for a file hash (MD5/SHA1/SHA256)."""
        return self._client.get(f"indicators/file/{hash_value}/{section}")

    def get_cve_details(self, cve_id: str) -> dict:
        """Get OTX threat context for a CVE."""
        return self._client.get(f"indicators/cve/{cve_id}/general")

    def search(
        self, query: str, indicator_type: str | None = None, limit: int | None = None
    ) -> dict:
        """
        Search OTX for pulses or indicators matching a query.

        Parameters
        ----------
        query : str
        indicator_type : str | None
            Filter by OTX indicator type (e.g. 'IPv4', 'domain').
        limit : int | None
        """
        params: dict = {"q": query, "limit": limit or self._client.config.max_results}
        if indicator_type:
            params["type"] = indicator_type
        return self._client.get("search/pulses", params=params)

    @staticmethod
    def normalise_indicator(ind: dict) -> dict:
        """Flatten an OTX indicator to GNAT normalised format."""
        return {
            "id": ind.get("id"),
            "type": ind.get("type"),
            "value": ind.get("indicator"),
            "created": ind.get("created"),
            "description": ind.get("description"),
            "title": ind.get("title"),
            "role": ind.get("role"),
            "is_active": ind.get("is_active", True),
            "stix_type": _OTX_TO_STIX.get(ind.get("type", ""), ""),
            "_raw": ind,
        }


# ── Feed Commands ─────────────────────────────────────────────────────────────


class OTXFeedCommands:
    """OTX feed / subscription operations."""

    def __init__(self, client: OTXClient):
        """Initialize OTXFeedCommands."""
        self._client = client

    def get_indicator_feed(
        self,
        indicator_type: str = "IPv4",
        modified_since: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        Get the aggregated indicator feed for a specific type.

        Parameters
        ----------
        indicator_type : str
            OTX indicator type: 'IPv4', 'domain', 'URL', 'FileHash-SHA256', etc.
        modified_since : str | None
            ISO 8601 timestamp filter.
        limit : int | None
        """
        params: dict = {"limit": limit or self._client.config.max_results}
        if modified_since:
            params["modified_since"] = modified_since
        result = self._client.get(f"indicators/export?type={indicator_type}", params=params)
        return result.get("results", []) if isinstance(result, dict) else result

    def iter_subscribed_indicators(self, modified_since: str | None = None) -> Iterator[dict]:
        """
        Generator yielding all indicators from all subscribed pulses.
        More efficient than fetching pulse-by-pulse.
        """
        for pulse in OTXPulseCommands(OTXClient(self._client.config)).iter_subscribed_pulses(
            modified_since=modified_since
        ):
            pulse_id = pulse.get("id")
            if pulse_id:
                yield from OTXPulseCommands(self._client).iter_pulse_indicators(pulse_id)


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class OTXSTIXMapper:
    """Maps OTX pulses and indicators to STIX 2.1 objects."""

    def pulse_to_stix_bundle(self, pulse: dict, indicators: list[dict] | None = None) -> dict:
        """
        Convert a normalised OTX pulse to a STIX 2.1 bundle.

        Produces a report SDO + SCOs/indicator SDOs for each indicator.

        Parameters
        ----------
        pulse : dict
            Normalised pulse from OTXPulseCommands.normalise_pulse().
        indicators : list[dict] | None
            Normalised indicators. If None, uses pulse._raw.indicators.
        """
        now = _now_ts()
        objects: list[dict] = []
        seen: set[str] = set()
        object_refs: list[str] = []

        raw_inds = indicators or [
            OTXIndicatorCommands.normalise_indicator(i)
            for i in pulse.get("_raw", {}).get("indicators", [])
        ]

        for ind in raw_inds:
            for obj in self.indicator_to_stix_objects(ind):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                object_refs.append(obj["id"])
        report_id = f"report--{_det_uuid('report', pulse.get('id', now))}"
        report: dict = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": pulse.get("created") or now,
            "modified": pulse.get("modified") or now,
            "name": pulse.get("name", "OTX Pulse"),
            "description": pulse.get("description", ""),
            "report_types": ["threat-report"],
            "published": pulse.get("created") or now,
            "object_refs": list(dict.fromkeys(object_refs)),
            "labels": pulse.get("tags", []),
            "x_otx_pulse": {
                "pulse_id": pulse.get("id"),
                "author": pulse.get("author"),
                "tlp": pulse.get("tlp"),
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "targeted_countries": pulse.get("targeted_countries", []),
            },
        }
        objects.append(report)
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def indicator_to_stix_objects(self, ind: dict) -> list[dict]:
        """Convert a normalised OTX indicator to STIX object(s)."""
        otx_type = ind.get("type", "")
        value = ind.get("value", "")
        if not value:
            return []
        stix_type = _OTX_TO_STIX.get(otx_type)
        if not stix_type:
            return []

        objects: list[dict] = []
        sco = self._build_sco(stix_type, otx_type, value)
        if not sco:
            return []
        objects.append(sco)

        # Also produce an indicator SDO
        pattern = self._build_pattern(stix_type, otx_type, value)
        if pattern:
            now = _now_ts()
            ind_id = f"indicator--{_det_uuid('indicator', pattern)}"
            objects.append(
                {
                    "type": "indicator",
                    "id": ind_id,
                    "spec_version": "2.1",
                    "created": ind.get("created") or now,
                    "modified": now,
                    "name": value,
                    "description": ind.get("description", ind.get("title", "")),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ind.get("created") or now,
                    "indicator_types": ["malicious-activity"],
                }
            )
        return objects

    def indicators_to_stix_bundle(self, indicators: list[dict]) -> dict:
        """Convert a flat list of normalised OTX indicators to a STIX bundle."""
        objects: list[dict] = []
        seen: set[str] = set()
        for ind in indicators:
            for obj in self.indicator_to_stix_objects(ind):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    @staticmethod
    def _build_sco(stix_type: str, otx_type: str, value: str) -> dict | None:
        """Internal helper for build sco."""
        if stix_type in ("ipv4-addr", "ipv6-addr"):
            return {
                "type": stix_type,
                "id": f"{stix_type}--{_det_uuid(stix_type, value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "domain-name":
            return {
                "type": "domain-name",
                "id": f"domain-name--{_det_uuid('domain-name', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "url":
            return {
                "type": "url",
                "id": f"url--{_det_uuid('url', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "email-addr":
            return {
                "type": "email-addr",
                "id": f"email-addr--{_det_uuid('email-addr', value)}",
                "spec_version": "2.1",
                "value": value,
            }
        if stix_type == "file":
            hash_map = {
                "FileHash-MD5": "MD5",
                "FileHash-SHA1": "SHA-1",
                "FileHash-SHA256": "SHA-256",
                "FileHash-SHA512": "SHA-512",
            }
            algo = hash_map.get(otx_type, "SHA-256")
            return {
                "type": "file",
                "id": f"file--{_det_uuid('file', value)}",
                "spec_version": "2.1",
                "hashes": {algo: value},
            }
        if stix_type == "vulnerability":
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{_det_uuid('vulnerability', value)}",
                "spec_version": "2.1",
                "created": _now_ts(),
                "modified": _now_ts(),
                "name": value,
                "external_references": [{"source_name": "cve", "external_id": value}],
            }
        return None

    @staticmethod
    def _build_pattern(stix_type: str, otx_type: str, value: str) -> str | None:
        """Internal helper for build pattern."""
        if stix_type in ("ipv4-addr", "ipv6-addr"):
            return f"[{stix_type}:value = '{value}']"
        if stix_type == "domain-name":
            return f"[domain-name:value = '{value}']"
        if stix_type == "url":
            return f"[url:value = '{value}']"
        if stix_type == "email-addr":
            return f"[email-addr:value = '{value}']"
        if stix_type == "file":
            hash_map = {
                "FileHash-MD5": "MD5",
                "FileHash-SHA1": "SHA-1",
                "FileHash-SHA256": "SHA-256",
            }
            algo = hash_map.get(otx_type, "SHA-256")
            return f"[file:hashes.'{algo}' = '{value}']"
        return None


def _det_uuid(t: str, v: str) -> str:
    """Internal helper for det uuid."""
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
