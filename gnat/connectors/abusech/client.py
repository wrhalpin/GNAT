# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abusech.client
==================================

Unified abuse.ch connector covering five free threat-intel feeds:

========================  ====================================================
Feed key                  Source URL
========================  ====================================================
``urlhaus``               https://urlhaus-api.abuse.ch/v1/
``malwarebazaar``         https://mb-api.abuse.ch/api/v1/
``threatfox``             https://threatfox-api.abuse.ch/api/v1/
``feodotracker``          https://feodotracker.abuse.ch/downloads/ipblocklist.json
``sslbl``                 https://sslbl.abuse.ch/blacklist/sslblacklist.json
========================  ====================================================

Authentication
--------------
abuse.ch feeds are free and anonymous, but registered users receive higher
rate limits.  Supply ``auth_key`` in the config to enable the ``Auth-Key``
header on all requests::

    [abusech]
    host      = https://abuse.ch
    auth_key  = OPTIONAL_ABUSE_CH_KEY
    default_feed = threatfox

STIX Type Mapping
-----------------
All five feeds emit STIX ``indicator`` objects with appropriate patterns;
MalwareBazaar and ThreatFox additionally emit ``malware`` objects for
family attribution.  Per-feed extension fields are prefixed with the feed
name (``x_urlhaus``, ``x_malwarebazaar``, etc.).

Notes
-----
* **Read-only** feeds. ``upsert_object`` and ``delete_object`` raise.
* Each feed has its own host, so this connector issues requests to full
  URLs via ``_fetch_feed()`` rather than relying on ``self.host``.
* URLhaus, MalwareBazaar, and ThreatFox are interactive query APIs.
* Feodo Tracker and SSLBL are static JSON blocklist downloads.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    utcnow,
    x509_fingerprint_pattern,
)

logger = logging.getLogger(__name__)

# Deterministic UUID-5 namespace for abuse.ch indicator ids. Using a fixed
# namespace means the same IOC always maps to the same STIX id across runs.
_NAMESPACE_ABUSECH = uuid.UUID("3f8c7e12-64a3-4c0f-9f7b-1a2d5b6e9c71")


def _stable_id(feed: str, key: str) -> str:
    """Return a STIX-compliant ``indicator--<uuid5>`` id for an abuse.ch IOC."""
    return f"indicator--{uuid.uuid5(_NAMESPACE_ABUSECH, f'{feed}|{key}')}"


# Per-feed endpoint hosts / URLs. Each entry is a dict describing how to
# hit the feed: either an interactive POST API ("post"/"base") or a static
# GET download ("get").
_FEED_ENDPOINTS: dict[str, dict[str, str]] = {
    "urlhaus": {
        "mode": "post",
        "base": "https://urlhaus-api.abuse.ch/v1",
    },
    "malwarebazaar": {
        "mode": "post-form",
        "base": "https://mb-api.abuse.ch/api/v1/",
    },
    "threatfox": {
        "mode": "post",
        "base": "https://threatfox-api.abuse.ch/api/v1/",
    },
    "feodotracker": {
        "mode": "get",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    },
    "sslbl": {
        "mode": "get",
        "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.json",
    },
}

VALID_FEEDS = frozenset(_FEED_ENDPOINTS.keys())


class AbuseChClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the abuse.ch threat-intel feed family.

    Parameters
    ----------
    host : str
        Nominal host (unused for actual requests — kept for config
        symmetry with other connectors).  Defaults to
        ``"https://abuse.ch"``.
    auth_key : str, optional
        Optional ``Auth-Key`` header for higher rate limits.
    default_feed : str, optional
        Which feed :meth:`list_objects` targets when ``filters`` does not
        specify one.  Defaults to ``"threatfox"``.
    """

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "feed-query",
        "malware": "malwarebazaar",
    }

    def __init__(
        self,
        host: str = "https://abuse.ch",
        auth_key: str = "",
        default_feed: str = "threatfox",
        **kwargs: Any,
    ) -> None:
        """Initialize AbuseChClient."""
        if default_feed not in VALID_FEEDS:
            raise GNATClientError(
                f"Invalid default_feed {default_feed!r}. "
                f"Valid values: {sorted(VALID_FEEDS)}"
            )
        super().__init__(host=host, **kwargs)
        self.auth_key = auth_key or ""
        self.default_feed = default_feed
        # Separate urllib3 pool manager so we can hit arbitrary hosts
        # without being bound to self.host.
        self._pool: urllib3.PoolManager | None = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set JSON accept header and optional abuse.ch Auth-Key header."""
        self._auth_headers["Accept"] = "application/json"
        if self.auth_key:
            self._auth_headers["Auth-Key"] = self.auth_key

    # ── Internal transport ────────────────────────────────────────────────

    def _get_pool(self) -> urllib3.PoolManager:
        """Lazily create a urllib3 pool manager for multi-host requests."""
        if self._pool is None:
            self._pool = urllib3.PoolManager(
                timeout=urllib3.Timeout(connect=self.timeout, read=self.timeout),
                cert_reqs="CERT_REQUIRED" if self.verify_ssl else "CERT_NONE",
            )
        return self._pool

    def _fetch_feed(
        self,
        feed: str,
        path: str = "",
        body: dict[str, Any] | None = None,
        form: dict[str, Any] | None = None,
    ) -> Any:
        """
        Issue a request to an abuse.ch feed and return the parsed JSON body.

        Raises
        ------
        GNATClientError
            On any HTTP error or unparseable response.
        """
        if not self._authenticated:
            self.authenticate()
            self._authenticated = True

        endpoint = _FEED_ENDPOINTS.get(feed)
        if endpoint is None:
            raise GNATClientError(f"Unknown abuse.ch feed {feed!r}")

        mode = endpoint["mode"]
        headers = {"Accept": "application/json"}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        pool = self._get_pool()
        try:
            if mode == "get":
                url = endpoint["url"]
                resp = pool.request("GET", url, headers=headers)
            elif mode == "post":
                base = endpoint["base"].rstrip("/")
                url = f"{base}/{path.lstrip('/')}" if path else base + "/"
                headers["Content-Type"] = "application/json"
                encoded = json.dumps(body or {}).encode()
                resp = pool.request("POST", url, body=encoded, headers=headers)
            elif mode == "post-form":
                url = endpoint["base"]
                resp = pool.request("POST", url, fields=form or {}, headers=headers)
            else:
                raise GNATClientError(f"Unknown feed mode {mode!r}")
        except urllib3.exceptions.HTTPError as exc:
            raise GNATClientError(f"abuse.ch {feed} request failed: {exc}") from exc

        if resp.status >= 400:
            raise GNATClientError(
                f"abuse.ch {feed} returned HTTP {resp.status}: {resp.data[:200]!r}"
            )
        try:
            return json.loads(resp.data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GNATClientError(
                f"abuse.ch {feed} returned non-JSON payload: {exc}"
            ) from exc

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping Feodo Tracker (smallest static blocklist) as a liveness probe."""
        try:
            data = self._fetch_feed("feodotracker")
            return isinstance(data, list)
        except GNATClientError:
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Look up a single IOC across the abuse.ch feeds.

        ``stix_type`` may be ``"indicator"`` or ``"malware"``.  ``object_id``
        should be a URL, domain, IP, or file hash.  The feed is chosen
        heuristically from the value shape, or via ``filters["feed"]`` in
        ``list_objects``.
        """
        if stix_type not in ("indicator", "malware"):
            raise GNATClientError(
                "abuse.ch get_object supports only indicator / malware"
            )
        target = object_id.strip()
        if not target:
            raise GNATClientError("abuse.ch get_object requires a non-empty id")

        # Heuristic: hashes go to MalwareBazaar, URLs to URLhaus, IPs to
        # Feodo Tracker, everything else to ThreatFox.
        if len(target) in (32, 40, 64) and all(
            c in "0123456789abcdefABCDEF" for c in target
        ):
            return self.query_mb_hash(target)
        if target.startswith(("http://", "https://")):
            return self.query_urlhaus_url(target)
        if _looks_like_ip(target):
            blocklist = self.get_feodo_blocklist()
            for entry in blocklist:
                if entry.get("ip_address") == target:
                    return entry
            raise GNATClientError(
                f"IP {target!r} not found in Feodo Tracker blocklist"
            )
        return self.query_threatfox_ioc(target)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List recent IOCs from a chosen abuse.ch feed.

        ``filters["feed"]`` selects the sub-feed (defaults to
        ``self.default_feed``).  Additional per-feed filter keys:

        * ``threatfox``: ``days`` (default 1)
        * ``urlhaus``: ``limit`` (default 1000)
        * ``malwarebazaar``: ``selector`` (``"time"`` default)
        """
        if stix_type not in ("indicator", "malware"):
            raise GNATClientError(
                "abuse.ch list_objects supports only indicator / malware"
            )
        filters = dict(filters or {})
        feed = filters.pop("feed", self.default_feed)
        if feed not in VALID_FEEDS:
            raise GNATClientError(f"Unknown abuse.ch feed {feed!r}")

        if feed == "threatfox":
            days = int(filters.get("days", 1))
            resp = self._fetch_feed(
                "threatfox", body={"query": "get_iocs", "days": days}
            )
            data = resp.get("data") if isinstance(resp, dict) else None
            items = data if isinstance(data, list) else []
        elif feed == "urlhaus":
            # URLhaus has a public "recent URLs" endpoint
            resp = self._fetch_feed("urlhaus", path="urls/recent/")
            data = resp.get("urls") if isinstance(resp, dict) else None
            items = data if isinstance(data, list) else []
        elif feed == "malwarebazaar":
            selector = filters.get("selector", "time")
            resp = self._fetch_feed(
                "malwarebazaar",
                form={"query": "get_recent", "selector": selector},
            )
            data = resp.get("data") if isinstance(resp, dict) else None
            items = data if isinstance(data, list) else []
        elif feed == "feodotracker":
            raw = self._fetch_feed("feodotracker")
            items = raw if isinstance(raw, list) else []
        else:  # sslbl
            raw = self._fetch_feed("sslbl")
            items = raw if isinstance(raw, list) else []

        # Inject a synthetic _feed marker so to_stix knows which mapper to use
        tagged = [dict(item, _feed=feed) for item in items if isinstance(item, dict)]
        start = max(0, (int(page) - 1) * int(page_size))
        return tagged[start : start + int(page_size)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """abuse.ch feeds are read-only."""
        raise GNATClientError(
            "abuse.ch connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """abuse.ch feeds are read-only."""
        raise GNATClientError(
            "abuse.ch connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def query_urlhaus_url(self, url: str) -> dict[str, Any]:
        """Look up a URL in URLhaus."""
        resp = self._fetch_feed("urlhaus", path="url/", body={"url": url})
        if isinstance(resp, dict):
            return dict(resp, _feed="urlhaus")
        return {"query_status": "error", "_feed": "urlhaus"}

    def query_urlhaus_host(self, host: str) -> dict[str, Any]:
        """Look up a host / domain in URLhaus."""
        resp = self._fetch_feed("urlhaus", path="host/", body={"host": host})
        if isinstance(resp, dict):
            return dict(resp, _feed="urlhaus")
        return {"query_status": "error", "_feed": "urlhaus"}

    def query_mb_hash(self, sha256: str) -> dict[str, Any]:
        """Look up a SHA-256 in MalwareBazaar."""
        resp = self._fetch_feed(
            "malwarebazaar",
            form={"query": "get_info", "hash": sha256},
        )
        if isinstance(resp, dict):
            data = resp.get("data")
            if isinstance(data, list) and data:
                return dict(data[0], _feed="malwarebazaar")
            return dict(resp, _feed="malwarebazaar")
        return {"query_status": "error", "_feed": "malwarebazaar"}

    def query_threatfox_ioc(self, ioc: str) -> dict[str, Any]:
        """Search ThreatFox for a specific IOC value."""
        resp = self._fetch_feed(
            "threatfox",
            body={"query": "search_ioc", "search_term": ioc},
        )
        if isinstance(resp, dict):
            data = resp.get("data")
            if isinstance(data, list) and data:
                return dict(data[0], _feed="threatfox")
            return dict(resp, _feed="threatfox")
        return {"query_status": "error", "_feed": "threatfox"}

    def get_feodo_blocklist(self) -> list[dict[str, Any]]:
        """Return the Feodo Tracker IP blocklist as a list of dicts."""
        raw = self._fetch_feed("feodotracker")
        if isinstance(raw, list):
            return [dict(item, _feed="feodotracker") for item in raw if isinstance(item, dict)]
        return []

    def get_sslbl_blocklist(self) -> list[dict[str, Any]]:
        """Return the SSL Blacklist as a list of dicts."""
        raw = self._fetch_feed("sslbl")
        if isinstance(raw, list):
            return [dict(item, _feed="sslbl") for item in raw if isinstance(item, dict)]
        return []

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert an abuse.ch feed record to a STIX 2.1 ``indicator``.

        The feed is identified by the ``_feed`` marker stamped by
        ``list_objects`` / ``query_*`` helpers, or inferred from the shape
        of the record.
        """
        if not isinstance(native, dict):
            raise GNATClientError("abuse.ch to_stix expects a dict input")

        feed = native.get("_feed") or _infer_feed(native)
        if feed == "urlhaus":
            return _map_urlhaus(native)
        if feed == "malwarebazaar":
            return _map_malwarebazaar(native)
        if feed == "threatfox":
            return _map_threatfox(native)
        if feed == "feodotracker":
            return _map_feodo(native)
        if feed == "sslbl":
            return _map_sslbl(native)
        raise GNATClientError(
            f"Cannot map abuse.ch record — unknown feed (marker={feed!r})"
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """abuse.ch is read-only; returns an informational stub."""
        return {
            "note": (
                "abuse.ch connector is read-only. Use query_* helpers or "
                "list_objects(filters={'feed': ...}) to search feeds."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


# ---------------------------------------------------------------------------
# Per-feed mapping helpers (module-private)
# ---------------------------------------------------------------------------


def _looks_like_ip(value: str) -> bool:
    """Return True if *value* looks like an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _infer_feed(record: dict[str, Any]) -> str:
    """Guess which abuse.ch feed produced a record from its shape."""
    if "url" in record and ("url_status" in record or "urlhaus_reference" in record):
        return "urlhaus"
    if "sha256_hash" in record and ("file_type" in record or "signature" in record):
        return "malwarebazaar"
    if "ioc" in record and "threat_type" in record:
        return "threatfox"
    if "ip_address" in record and ("malware" in record or "as_number" in record):
        return "feodotracker"
    if "SHA1" in record or "Listingreason" in record:
        return "sslbl"
    return "threatfox"


def _base_indicator(
    pattern: str, name: str, description: str, now: str
) -> dict[str, Any]:
    """Common base STIX indicator skeleton used by all feed mappers."""
    return {
        "type": "indicator",
        "spec_version": CURRENT_SPEC_VERSION,
        "created": now,
        "modified": now,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "name": name,
        "description": description,
        "labels": ["malicious-activity"],
    }


def _map_urlhaus(rec: dict[str, Any]) -> dict[str, Any]:
    """Map a URLhaus record to a STIX indicator."""
    now = utcnow()
    url_val = rec.get("url") or rec.get("url_id") or ""
    pattern = make_indicator_pattern("url", url_val) if url_val else "[url:value = '']"
    ind = _base_indicator(
        pattern=pattern,
        name=f"URLhaus: {url_val[:80]}",
        description=rec.get("threat") or "URLhaus malicious URL",
        now=now,
    )
    ind["id"] = _stable_id("urlhaus", url_val or "unknown")
    ind["x_urlhaus"] = {
        "url_status": rec.get("url_status"),
        "threat": rec.get("threat"),
        "tags": rec.get("tags", []),
        "date_added": rec.get("date_added"),
        "urlhaus_reference": rec.get("urlhaus_reference"),
    }
    return ind


def _map_malwarebazaar(rec: dict[str, Any]) -> dict[str, Any]:
    """Map a MalwareBazaar record to a STIX indicator (file hash)."""
    now = utcnow()
    sha256 = rec.get("sha256_hash") or ""
    pattern = (
        make_indicator_pattern("file:sha256", sha256)
        if sha256
        else "[file:hashes.'SHA-256' = '']"
    )
    ind = _base_indicator(
        pattern=pattern,
        name=f"MalwareBazaar: {rec.get('signature') or sha256[:16]}",
        description=rec.get("file_type_mime") or "MalwareBazaar sample",
        now=now,
    )
    ind["id"] = _stable_id("malwarebazaar", sha256 or "unknown")
    ind["x_malwarebazaar"] = {
        "sha256_hash": sha256,
        "sha1_hash": rec.get("sha1_hash"),
        "md5_hash": rec.get("md5_hash"),
        "file_type": rec.get("file_type"),
        "file_size": rec.get("file_size"),
        "signature": rec.get("signature"),
        "tags": rec.get("tags", []),
        "first_seen": rec.get("first_seen"),
    }
    return ind


def _map_threatfox(rec: dict[str, Any]) -> dict[str, Any]:
    """Map a ThreatFox record to a STIX indicator."""
    now = utcnow()
    ioc_type = (rec.get("ioc_type") or "").lower()
    ioc_val = rec.get("ioc") or ""
    if ioc_type in ("ip:port", "ip"):
        ip_only = ioc_val.split(":", 1)[0]
        pattern = make_indicator_pattern("ipv4-addr", ip_only)
    elif ioc_type == "domain":
        pattern = make_indicator_pattern("domain-name", ioc_val)
    elif ioc_type == "url":
        pattern = make_indicator_pattern("url", ioc_val)
    elif ioc_type in ("sha256_hash", "md5_hash", "sha1_hash"):
        algo = ioc_type.split("_", 1)[0]
        pattern = make_indicator_pattern(f"file:{algo}", ioc_val)
    else:
        pattern = f"[x-threatfox:value = '{ioc_val}']"

    ind = _base_indicator(
        pattern=pattern,
        name=f"ThreatFox: {rec.get('malware') or ioc_val[:32]}",
        description=rec.get("threat_type_desc") or "ThreatFox IOC",
        now=now,
    )
    ind["id"] = _stable_id("threatfox", ioc_val or "unknown")
    confidence = rec.get("confidence_level")
    if isinstance(confidence, int):
        ind["confidence"] = confidence
    ind["x_threatfox"] = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_val,
        "threat_type": rec.get("threat_type"),
        "malware": rec.get("malware"),
        "malware_printable": rec.get("malware_printable"),
        "first_seen": rec.get("first_seen"),
        "last_seen": rec.get("last_seen"),
        "reference": rec.get("reference"),
        "tags": rec.get("tags", []),
    }
    return ind


def _map_feodo(rec: dict[str, Any]) -> dict[str, Any]:
    """Map a Feodo Tracker record to a STIX indicator (IPv4)."""
    now = utcnow()
    ip = rec.get("ip_address") or ""
    pattern = make_indicator_pattern("ipv4-addr", ip) if ip else "[ipv4-addr:value = '']"
    ind = _base_indicator(
        pattern=pattern,
        name=f"Feodo Tracker: {rec.get('malware') or ip}",
        description=f"Feodo Tracker C2 IP ({rec.get('malware', 'unknown family')})",
        now=now,
    )
    ind["id"] = _stable_id("feodotracker", ip or "unknown")
    ind["x_feodotracker"] = {
        "ip_address": ip,
        "port": rec.get("port"),
        "status": rec.get("status"),
        "hostname": rec.get("hostname"),
        "as_number": rec.get("as_number"),
        "as_name": rec.get("as_name"),
        "country": rec.get("country"),
        "first_seen": rec.get("first_seen"),
        "last_online": rec.get("last_online"),
        "malware": rec.get("malware"),
    }
    return ind


def _map_sslbl(rec: dict[str, Any]) -> dict[str, Any]:
    """Map an SSLBL record to a STIX indicator (x509 fingerprint)."""
    now = utcnow()
    sha1 = rec.get("SHA1") or rec.get("sha1") or ""
    pattern = x509_fingerprint_pattern(sha1=sha1) if sha1 else "[x509-certificate:hashes.'SHA-1' = '']"
    ind = _base_indicator(
        pattern=pattern,
        name=f"SSLBL: {rec.get('Listingreason') or sha1[:16]}",
        description="Abuse.ch SSL Blacklist malicious certificate",
        now=now,
    )
    ind["id"] = _stable_id("sslbl", sha1 or "unknown")
    ind["x_sslbl"] = {
        "sha1": sha1,
        "listing_reason": rec.get("Listingreason") or rec.get("listing_reason"),
        "listing_date": rec.get("Listingdate") or rec.get("listing_date"),
    }
    return ind
