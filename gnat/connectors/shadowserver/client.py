# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.shadowserver.client
========================================

Shadowserver Foundation API connector — network threat intelligence,
scan data, sinkholes, honeypot data, and malware reports.

Shadowserver provides daily reports covering:
- Compromised devices and botnets
- Open vulnerable services (RDP, SMB, Telnet etc.)
- Sinkholed domains and malware C2 infrastructure
- CVE-specific scan data

INI config::

    [shadowserver]
    host       = https://transform.shadowserver.org
    api_key    = <key>
    api_secret = <secret>
    auth_type  = token

Authentication
--------------
Shadowserver uses HMAC-SHA256 request signing.  Each request body is
signed with the API secret and the signature sent as the ``hmac`` field.

References
----------
https://transform.shadowserver.org/docs/
https://api.shadowserver.org/
"""

import hashlib
import hmac as _hmac
import json
from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class ShadowServerClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Shadowserver Foundation API.

    Read-only — Shadowserver provides intelligence feeds and reports;
    it does not accept threat intel submissions.

    Parameters
    ----------
    host : str
        API base URL.
    api_key : str
        Shadowserver API key.
    api_secret : str
        Shadowserver API secret for HMAC signing.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "ip",
        "vulnerability": "cve",
    }

    def __init__(
        self,
        host: str = "https://api.shadowserver.org",
        api_key: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ):
        """Initialize ShadowServerClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_secret = api_secret

    def authenticate(self) -> None:
        """Store credentials for per-request HMAC signing."""
        # No persistent auth header — Shadowserver uses request-level signing
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        resp = self._signed_post("/api/test/ping", {})
        return isinstance(resp, dict) and resp.get("pong") == 1

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Query Shadowserver for data on a specific IP or CVE.

        ``object_id`` is an IP address for ``indicator``, or a CVE ID
        for ``vulnerability``.
        """
        if stix_type == "vulnerability":
            resp = self._signed_post("/api/cve/query", {"cve": object_id})
        else:
            resp = self._signed_post("/api/ip/query", {"ip": object_id})
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Shadowserver report data.

        ``filters`` supports:
        - ``report`` (str): report type, e.g. ``"scan/rdp"``,
          ``"botnet_drone"``, ``"compromised_website"``
        - ``date`` (str): YYYY-MM-DD, defaults to latest available
        - ``asn`` (str): filter by Autonomous System Number
        - ``country`` (str): two-letter ISO country code

        Available report types:
        ``scan/rdp``, ``scan/smb``, ``scan/ssh``, ``scan/telnet``,
        ``botnet_drone``, ``sinkhole``, ``compromised_website``,
        ``malware_url``, ``darknet``
        """
        report = (filters or {}).get("report", "sinkhole")
        date = (filters or {}).get("date", "")
        asn = (filters or {}).get("asn", "")
        country = (filters or {}).get("country", "")

        payload: dict[str, Any] = {
            "report": report,
            "limit": page_size,
        }
        if date:
            payload["date"] = date
        if asn:
            payload["asn"] = asn
        if country:
            payload["country"] = country

        resp = self._signed_post("/api/report/query", payload)
        if not isinstance(resp, list):
            return resp.get("results", []) if isinstance(resp, dict) else []
        return resp

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Shadowserver API is read-only — upsert not supported.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Shadowserver API is read-only — delete not supported.")

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Shadowserver report record to a STIX Indicator.

        Shadowserver records vary by report type but consistently include:
        ``ip``, ``port``, ``protocol``, ``timestamp``, ``asn``, ``country``,
        ``sector`` (when available), ``tag`` (vulnerability/threat type).
        """
        ip = native.get("ip", "")
        timestamp = native.get("timestamp", "")
        sector = native.get("sector", "")
        tag = native.get("tag", "")
        asn = native.get("asn", "")
        country = native.get("country", "")
        port = native.get("port", "")

        name = ip
        if tag:
            name = f"{ip} ({tag})"

        indicator_types = ["malicious-activity"]
        if "scan" in str(native.get("report", "")).lower():
            indicator_types = ["anomalous-activity"]

        sectors = [sector] if sector else []

        return {
            "type": "indicator",
            "id": f"indicator--ss-{ip.replace('.', '-')}-{port}",
            "name": name,
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "created": timestamp,
            "modified": timestamp,
            "confidence": 75,  # Shadowserver data is high-quality
            "indicator_types": indicator_types,
            "x_source_platform": "shadowserver",
            "x_ss_port": port,
            "x_ss_protocol": native.get("protocol", ""),
            "x_ss_asn": asn,
            "x_ss_country": country,
            "x_ss_tag": tag,
            "x_ss_report": native.get("report", ""),
            "x_target_sectors": sectors,  # canonical sector field
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        return {"ip": m.group(1) if m else stix_dict.get("name", "")}

    # ── HMAC signing ───────────────────────────────────────────────────────

    def _signed_post(self, path: str, payload: dict[str, Any]) -> Any:
        """
        POST to the Shadowserver API with HMAC-SHA256 request signing.

        The signature is computed over the JSON-serialised request body
        using the API secret, then added as the ``hmac`` field.
        """
        body = dict(payload)
        body["apikey"] = self._api_key

        body_json = json.dumps(body, separators=(",", ":"), sort_keys=True)
        signature = _hmac.new(
            self._api_secret.encode(),
            body_json.encode(),
            hashlib.sha256,
        ).hexdigest()

        signed_body = dict(body)
        signed_body["hmac"] = signature

        return self.post(path, json=signed_body)
