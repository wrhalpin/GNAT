# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.ip_api.client
==================================
IP geolocation connector for ip-api.com.

Tiers
-----
Free tier:
  - Host:       http://ip-api.com  (HTTP only — no HTTPS on free tier)
  - Auth:       None (no API key required)
  - Rate limit: 45 req/min (single), 15 batch req/min
  - Batch size: Up to 100 IPs per POST /batch request

Pro tier:
  - Host:       https://pro.ip-api.com
  - Auth:       API key via ``?key=YOUR_KEY`` query param
  - Rate limit: Higher limits (see ip-api.com/docs)

Endpoints
---------
Single lookup:  GET  /json/{ip}?fields=...
Batch lookup:   POST /batch?fields=...
                Body: [{"query": "1.2.3.4"}, ...]

Response shape (success)
------------------------
{
  "status":      "success",
  "country":     "United States",
  "countryCode": "US",
  "region":      "CA",
  "regionName":  "California",
  "city":        "Mountain View",
  "zip":         "94043",
  "lat":         37.4192,
  "lon":         -122.0574,
  "timezone":    "America/Los_Angeles",
  "isp":         "Google LLC",
  "org":         "Google Public DNS",
  "as":          "AS15169 Google LLC",
  "asname":      "GOOGLE",
  "proxy":       false,
  "hosting":     true,
  "query":       "8.8.8.8"
}

Response shape (failure)
------------------------
{
  "status":  "fail",
  "message": "private range",
  "query":   "192.168.1.1"
}
"""

import time
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

# Fields to request on every lookup — covers all investigation-useful fields
_FIELDS = (
    "status,message,country,countryCode,region,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query"
)

_BATCH_SIZE = 100


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IPAPIClient(BaseClient, ConnectorMixin):
    """
    IP geolocation connector for ip-api.com.

    Supports single IP lookups, batch lookups (up to 100 IPs), and
    large-scale lookups with automatic chunking and rate-limit throttling.

    Parameters
    ----------
    host : str
        API base URL. Defaults to ``"http://ip-api.com"`` (free tier).
        Set to ``"https://pro.ip-api.com"`` for pro tier.
    api_key : str, optional
        Pro tier API key. Injected as ``?key=`` query param when provided.
    timeout : float
        Request timeout in seconds.
    batch_delay : float
        Seconds to sleep between consecutive batch calls. Default ``4.0``
        keeps the free tier safely under 15 batch req/min.
    verify_ssl : bool
        TLS certificate verification. Has no effect on the free-tier HTTP
        endpoint; relevant for the pro HTTPS endpoint.
    """

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "geo",
    }

    def __init__(
        self,
        host: str = "http://ip-api.com",
        api_key: str = "",
        timeout: float = 30.0,
        batch_delay: float = 4.0,
        verify_ssl: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize IPAPIClient."""
        super().__init__(host=host, verify_ssl=verify_ssl, timeout=timeout, **kwargs)
        self._api_key = api_key.strip()
        self._batch_delay = float(batch_delay)

    # ── ConnectorMixin contract ────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Accept header. ip-api.com requires no token."""
        self._auth_headers["Accept"] = "application/json"
        self._authenticated = True

    def health_check(self) -> bool:
        """
        Verify connectivity by looking up Google's public DNS IP (8.8.8.8).

        Returns
        -------
        bool
            True if the API responds with status == 'success'.
        """
        try:
            result = self.lookup_ip("8.8.8.8")
            return result.get("status") == "success"
        except Exception:
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict:
        """
        Fetch geolocation data for a single IP address.

        Parameters
        ----------
        stix_type : str
            Must be ``"observed-data"``.
        object_id : str
            IP address to look up.

        Returns
        -------
        dict
            STIX observed-data object.
        """
        if stix_type != "observed-data":
            raise GNATClientError(
                f"ip-api.com only supports STIX type 'observed-data', got {stix_type!r}"
            )
        native = self.lookup_ip(object_id)
        return self.to_stix(native)

    def list_objects(
        self,
        stix_type: str,
        filters: dict | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict]:
        """
        Geolocate a list of IPs and return STIX observed-data objects.

        Parameters
        ----------
        stix_type : str
            Must be ``"observed-data"``.
        filters : dict, optional
            Accepted keys:

            ``ips`` : list[str]
                List of IP addresses to look up (preferred for bulk).
            ``ip`` : str
                Single IP address (alternative to ``ips``).
        page : int
            Ignored — ip-api.com does not paginate; all results are returned.
        page_size : int
            Ignored.

        Returns
        -------
        list[dict]
            List of STIX observed-data objects.
        """
        if stix_type != "observed-data":
            raise GNATClientError(
                f"ip-api.com only supports STIX type 'observed-data', got {stix_type!r}"
            )
        filters = filters or {}
        ips: list[str] = filters.get("ips") or []
        if not ips and filters.get("ip"):
            ips = [filters["ip"]]
        if not ips:
            return []
        native_results = self.lookup_many(ips)
        return [self.to_stix(r) for r in native_results]

    def upsert_object(self, stix_type: str, payload: dict) -> dict:
        """Raise — ip-api.com is a read-only data source."""
        raise GNATClientError("ip-api.com is read-only. upsert_object is not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Raise — ip-api.com is a read-only data source."""
        raise GNATClientError("ip-api.com is read-only. delete_object is not supported.")

    def to_stix(self, native: dict) -> dict:
        """
        Convert an ip-api.com response dict to a STIX 2.1 observed-data SDO.

        The IP address is embedded as an ``ipv4-addr`` SCO in ``objects``.
        All ip-api.com fields are preserved under ``x_ipapi_*`` extension keys.

        Parameters
        ----------
        native : dict
            Raw ip-api.com response dict with ``status == "success"``.

        Returns
        -------
        dict
            STIX 2.1 observed-data object.
        """
        ip = native.get("query", "")
        now = _now_iso()
        return {
            "type": "observed-data",
            "id": f"observed-data--ipapi-{ip}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "objects": {
                "0": {"type": "ipv4-addr", "value": ip},
            },
            "x_ipapi_country": native.get("country", ""),
            "x_ipapi_country_code": native.get("countryCode", ""),
            "x_ipapi_region": native.get("regionName", ""),
            "x_ipapi_city": native.get("city", ""),
            "x_ipapi_zip": native.get("zip", ""),
            "x_ipapi_lat": native.get("lat"),
            "x_ipapi_lon": native.get("lon"),
            "x_ipapi_timezone": native.get("timezone", ""),
            "x_ipapi_isp": native.get("isp", ""),
            "x_ipapi_org": native.get("org", ""),
            "x_ipapi_as": native.get("as", ""),
            "x_ipapi_asname": native.get("asname", ""),
            "x_ipapi_proxy": bool(native.get("proxy", False)),
            "x_ipapi_hosting": bool(native.get("hosting", False)),
            "x_ipapi_query": ip,
        }

    def from_stix(self, stix_dict: dict) -> dict:
        """
        Extract the IP address from a STIX object and return a lookup payload.

        Parameters
        ----------
        stix_dict : dict
            STIX observed-data object (typically created by :meth:`to_stix`).

        Returns
        -------
        dict
            ``{"query": "<ip_address>"}`` payload.
        """
        # Prefer the extension field set by to_stix()
        ip = stix_dict.get("x_ipapi_query", "")
        if not ip:
            # Fall back to the embedded SCO
            objects = stix_dict.get("objects", {})
            for obj in objects.values():
                if obj.get("type") == "ipv4-addr":
                    ip = obj.get("value", "")
                    break
        return {"query": ip}

    # ── ip-api.com API methods ────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict:
        """
        Look up geolocation data for a single IP address or hostname.

        Parameters
        ----------
        ip : str
            IPv4, IPv6 address, or domain name.

        Returns
        -------
        dict
            Raw ip-api.com response dict.

        Raises
        ------
        GNATClientError
            If the API returns ``status == "fail"``.
        """
        params: dict[str, Any] = {"fields": _FIELDS}
        if self._api_key:
            params["key"] = self._api_key
        result = self.get(f"/json/{ip}", params=params)
        if result.get("status") != "success":
            msg = result.get("message", "unknown error")
            raise GNATClientError(
                f"ip-api.com lookup failed for {ip!r}: {msg}",
                status=0,
            )
        return result

    def lookup_batch(self, ips: list[str]) -> list[dict]:
        """
        Look up geolocation data for up to 100 IPs in a single batch request.

        Failed lookups (RFC1918/reserved ranges, invalid IPs) are silently
        skipped — they are not raised as errors.

        Parameters
        ----------
        ips : list[str]
            Up to 100 IP addresses or hostnames.

        Returns
        -------
        list[dict]
            Successful ip-api.com response dicts (``status == "success"``).
        """
        if not ips:
            return []
        params: dict[str, Any] = {"fields": _FIELDS}
        if self._api_key:
            params["key"] = self._api_key
        body = [{"query": ip} for ip in ips]
        results = self.post("/batch", json=body, params=params)
        if not isinstance(results, list):
            return []
        return [r for r in results if r.get("status") == "success"]

    def lookup_many(self, ips: list[str]) -> list[dict]:
        """
        Look up geolocation data for an arbitrary number of IPs.

        Automatically splits into batches of up to 100 and sleeps
        :attr:`_batch_delay` seconds between calls to respect the free-tier
        rate limit of 15 batch requests/minute.

        Parameters
        ----------
        ips : list[str]
            Any number of IP addresses or hostnames.

        Returns
        -------
        list[dict]
            All successful ip-api.com response dicts across all batches.
        """
        results: list[dict] = []
        chunks = [ips[i : i + _BATCH_SIZE] for i in range(0, len(ips), _BATCH_SIZE)]
        for idx, chunk in enumerate(chunks):
            batch_results = self.lookup_batch(chunk)
            results.extend(batch_results)
            # Sleep between calls — skip delay after the last chunk
            if idx < len(chunks) - 1:
                time.sleep(self._batch_delay)
        return results
