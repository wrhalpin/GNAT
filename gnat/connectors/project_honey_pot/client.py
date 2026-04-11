# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.project_honey_pot.client
============================================

Project Honey Pot — community spam-trap and harvester intelligence.

Project Honey Pot has no REST API. Reputation lookups are performed via
the **http:BL** DNS-blocklist protocol::

    <api_key>.<reversed-ip>.dnsbl.httpbl.org

The DNS A record returned encodes the result as ``127.X.Y.Z`` where:

* ``X`` — days since the IP was last seen by a honey pot (0-255)
* ``Y`` — threat score (0-255; higher = more abusive)
* ``Z`` — visitor type bitfield
    * 0 — search engine
    * 1 — suspicious
    * 2 — harvester
    * 4 — comment spammer
    * combinations are bitwise OR

NXDOMAIN means the IP has not been observed by Project Honey Pot.

Configuration::

    [project_honey_pot]
    api_key = abcdefghijkl   # 12-char http:BL access key
"""

from __future__ import annotations

import socket
import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_PHP = uuid.UUID("4040b001-0001-4a1e-9b1e-4040b001c0fe")

_VISITOR_TYPES = {
    0: "search_engine",
    1: "suspicious",
    2: "harvester",
    4: "comment_spammer",
}


class ProjectHoneyPotClient(BaseClient, ConnectorMixin):
    """http:BL client for Project Honey Pot."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "httpbl"
    API_PREFIX: str = ""
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"indicator": "httpbl_lookup"}

    def __init__(
        self,
        host: str = "dnsbl.httpbl.org",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize ProjectHoneyPotClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        # Override the parsed host so DNS lookups use the bare zone
        self._dnsbl_zone = (host or "dnsbl.httpbl.org").replace(
            "https://", ""
        ).replace("http://", "").rstrip("/")

    def authenticate(self) -> None:
        """Validate that an http:BL access key is configured."""
        if not self.api_key:
            raise GNATClientError(
                "ProjectHoneyPot connector requires api_key in config "
                "(http:BL access key)."
            )
        if len(self.api_key) != 12:
            raise GNATClientError(
                "ProjectHoneyPot http:BL access keys are exactly 12 "
                f"lowercase letters; got {len(self.api_key)} characters."
            )

    def health_check(self) -> bool:
        """Resolve a known-clean IP (Google DNS) as a liveness probe."""
        try:
            self.authenticate()
            self._httpbl_query("8.8.8.8")
            return True
        except Exception:  # noqa: BLE001
            return False

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Look up a single IP via http:BL."""
        if stix_type != "indicator":
            raise GNATClientError(
                f"ProjectHoneyPot get_object does not support stix_type={stix_type!r}"
            )
        if not object_id:
            raise GNATClientError(
                "ProjectHoneyPot get_object requires a non-empty IP address"
            )
        return self._httpbl_query(object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Look up a batch of IPs via http:BL.

        ``filters['ips']`` must contain an iterable of IP addresses to
        check. Project Honey Pot has no native list endpoint.
        """
        if stix_type != "indicator":
            raise GNATClientError(
                f"ProjectHoneyPot list_objects does not support stix_type={stix_type!r}"
            )
        filters = dict(filters or {})
        ips = filters.get("ips") or []
        if not ips:
            raise GNATClientError(
                "ProjectHoneyPot list_objects requires an 'ips' filter "
                "(iterable of IP addresses to look up); the API has no "
                "native list endpoint."
            )
        results: list[dict[str, Any]] = []
        for ip in ips:
            if not isinstance(ip, str):
                continue
            try:
                results.append(self._httpbl_query(ip))
            except GNATClientError as exc:
                results.append({"_php_kind": "lookup", "ip": ip, "error": str(exc)})
        return results

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """ProjectHoneyPot connector is read-only."""
        raise GNATClientError(
            "ProjectHoneyPot connector is read-only — http:BL is a "
            "lookup-only protocol."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ProjectHoneyPot connector is read-only."""
        raise GNATClientError(
            "ProjectHoneyPot connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def check_ip(self, ip: str) -> dict[str, Any]:
        """Look up a single IP via http:BL."""
        return self.get_object("indicator", ip)

    def check_ips(self, ips: list[str]) -> list[dict[str, Any]]:
        """Look up a batch of IPs via http:BL."""
        return self.list_objects("indicator", filters={"ips": ips})

    # ── http:BL low-level helpers ──────────────────────────────────────────

    def _httpbl_query(self, ip: str) -> dict[str, Any]:
        """
        Issue a single http:BL DNS query and parse the response.

        Returns a dict with ``_php_kind="lookup"``, the queried IP, and
        the parsed reputation fields. If the IP is not listed, the
        ``listed`` flag is False and the score fields are zero.
        """
        if not self.api_key:
            self.authenticate()
        try:
            octets = ip.strip().split(".")
            if len(octets) != 4:
                raise GNATClientError(
                    f"ProjectHoneyPot expects an IPv4 address; got {ip!r}"
                )
            reversed_ip = ".".join(reversed(octets))
        except (AttributeError, ValueError) as exc:
            raise GNATClientError(
                f"ProjectHoneyPot could not parse IP {ip!r}: {exc}"
            ) from exc

        query_host = f"{self.api_key}.{reversed_ip}.{self._dnsbl_zone}"
        try:
            answer = socket.gethostbyname(query_host)
        except socket.gaierror:
            return {
                "_php_kind": "lookup",
                "ip": ip,
                "listed": False,
                "days_since_last_activity": 0,
                "threat_score": 0,
                "visitor_type_bits": 0,
                "visitor_types": [],
                "raw": None,
            }
        return _parse_httpbl_response(ip, answer)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Project Honey Pot lookup result to a STIX indicator."""
        if not isinstance(native, dict):
            raise GNATClientError("ProjectHoneyPot to_stix expects a dict input")

        ip = native.get("ip", "")
        pattern = make_indicator_pattern("ipv4-addr", ip) if ip else "[ipv4-addr:value = '']"
        stix_uuid = uuid.uuid5(_NAMESPACE_PHP, f"indicator|{ip}")
        threat_score = int(native.get("threat_score") or 0)
        listed = bool(native.get("listed"))
        labels = ["malicious-activity"] if listed and threat_score >= 25 else (
            ["anomalous-activity"] if listed else ["benign"]
        )
        types = native.get("visitor_types") or []

        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"Project Honey Pot: {ip}",
            "description": (
                f"http:BL reputation: threat_score={threat_score}, "
                f"types={','.join(types) or 'none'}"
            ),
            "labels": labels,
            "confidence": min(threat_score, 100) if listed else 0,
            "x_project_honey_pot": {
                "listed": listed,
                "threat_score": threat_score,
                "days_since_last_activity": int(
                    native.get("days_since_last_activity") or 0
                ),
                "visitor_type_bits": int(native.get("visitor_type_bits") or 0),
                "visitor_types": types,
                "raw": native.get("raw"),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """ProjectHoneyPot connector is read-only."""
        return {
            "note": (
                "ProjectHoneyPot connector is read-only. Use check_ip "
                "or check_ips to query http:BL."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _parse_httpbl_response(ip: str, answer: str) -> dict[str, Any]:
    """Parse a 4-octet http:BL DNS response into a structured dict."""
    parts = (answer or "").split(".")
    if len(parts) != 4 or parts[0] != "127":
        raise GNATClientError(
            f"ProjectHoneyPot returned unexpected http:BL response {answer!r}"
        )
    try:
        days = int(parts[1])
        score = int(parts[2])
        bits = int(parts[3])
    except ValueError as exc:
        raise GNATClientError(
            f"ProjectHoneyPot http:BL response not numeric: {answer!r}"
        ) from exc
    types: list[str] = []
    if bits == 0:
        types.append(_VISITOR_TYPES[0])
    else:
        for bit_value, name in _VISITOR_TYPES.items():
            if bit_value == 0:
                continue
            if bits & bit_value:
                types.append(name)
    return {
        "_php_kind": "lookup",
        "ip": ip,
        "listed": True,
        "days_since_last_activity": days,
        "threat_score": score,
        "visitor_type_bits": bits,
        "visitor_types": types,
        "raw": answer,
    }
