# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cisco_umbrella.client
======================================

Cisco Umbrella connector combining three Umbrella API surfaces:

* **Investigate API** — domain/IP threat intelligence and categorization
* **Enforcement API** — push custom block-list domains
* **Management API** — query and manage allow-list (trusted domain) entries

Authentication
--------------
All three APIs use different credentials.  Supply the ones your use-case
requires; any omitted API will raise :class:`~gnat.clients.base.GNATClientError`
when its methods are called.

* Investigate: ``investigate_api_key`` (Bearer token)
* Enforcement: ``enforcement_api_key``
* Management:  ``management_api_key``

Configuration::

    [cisco_umbrella]
    host                = https://investigate.api.umbrella.com
    investigate_api_key = YOUR_INVESTIGATE_KEY
    enforcement_api_key = YOUR_ENFORCEMENT_KEY
    management_api_key  = YOUR_MANAGEMENT_KEY
    # Optional: default TLP for produced indicators
    tlp_marking         = white

STIX Type Mapping
-----------------
+------------------+------------------------------------------+
| STIX Type        | Umbrella Resource                        |
+==================+==========================================+
| indicator        | Domain/IP classification (Investigate)   |
+------------------+------------------------------------------+
| course-of-action | Allow-list entry (trusted domain)        |
+------------------+------------------------------------------+

Notes
-----
* The Investigate API is **read-only** threat intelligence enrichment.
* The Enforcement API is **write-only** (push blocks, no reads).
* Umbrella's domain classification scheme uses numeric security categories;
  unknown/benign domains are considered **trusted** (whitelist), while
  domains tagged with security category codes are **blocked/suspicious**.
* ``list_objects("indicator")`` returns all indicators with security signals.
* ``list_objects("course-of-action")`` returns trusted (allow-listed) domains.
* The allow-list pattern here serves as the example of a feed connector that
  needs *special treatment* beyond simple STIX passthrough.
"""

from __future__ import annotations

import contextlib
import json as _json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import urllib3

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

logger = logging.getLogger(__name__)

_INVESTIGATE_HOST = "https://investigate.api.umbrella.com"
_ENFORCEMENT_HOST = "https://s-platform.api.opendns.com"
_MANAGEMENT_HOST = "https://management.api.umbrella.com"

# Umbrella security category codes considered malicious (non-exhaustive)
_MALICIOUS_CATEGORIES = frozenset(
    {
        "Botnet",
        "C2",
        "Command and Control",
        "Cryptomining",
        "Drive-by Downloads",
        "Dynamic DNS",
        "Malware",
        "Newly Seen Domains",
        "Phishing",
        "Potentially Harmful",
        "Spam",
        "Typosquatting",
    }
)


def _now_ts() -> str:
    """ISO 8601 timestamp for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stix_id(stix_type: str, seed: str) -> str:
    """Deterministic STIX ID from type + seed string."""
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


class CiscoUmbrellaClient(BaseClient, ConnectorMixin):
    """
    Connector for Cisco Umbrella threat intelligence and DNS enforcement.

    Combines the Investigate (threat intel), Enforcement (block-list push),
    and Management (allow-list query) APIs into one connector instance.

    Parameters
    ----------
    host : str
        Base URL for the Investigate API.
        Default: ``"https://investigate.api.umbrella.com"``.
    investigate_api_key : str
        API key / Bearer token for the Umbrella Investigate API.
    enforcement_api_key : str, optional
        API key for the Enforcement (block-list) API.
    management_api_key : str, optional
        API key for the Management (allow-list) API.
    tlp_marking : str
        Default TLP marking applied to produced STIX objects.
        Default: ``"white"``.
    """

    stix_type_map: dict[str, str] = {
        "indicator": "domain",
        "course-of-action": "allow_list",
    }

    def __init__(
        self,
        host: str = _INVESTIGATE_HOST,
        investigate_api_key: str = "",
        enforcement_api_key: str = "",
        management_api_key: str = "",
        tlp_marking: str = "white",
        **kwargs: Any,
    ):
        super().__init__(host=host or _INVESTIGATE_HOST, **kwargs)
        self._investigate_key = investigate_api_key
        self._enforcement_key = enforcement_api_key
        self._management_key = management_api_key
        self._tlp_marking = tlp_marking

        # Enforcement and management APIs live on different hosts;
        # share a single pool manager per host to reuse connections.
        self._enforcement_host = _ENFORCEMENT_HOST
        self._management_host = _MANAGEMENT_HOST
        self._enf_http = urllib3.PoolManager()
        self._mgmt_http = urllib3.PoolManager()

    # ── Authentication ─────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Populate auth headers for the Investigate API.

        The Enforcement and Management APIs use separate keys injected
        per-request in the domain-specific helper methods.
        """
        if not self._investigate_key:
            raise GNATClientError("CiscoUmbrellaClient requires 'investigate_api_key' in config.")
        self._auth_headers["Authorization"] = f"Bearer {self._investigate_key}"
        self._auth_headers["Accept"] = "application/json"
        self._authenticated = True

    # ── ConnectorMixin — health ─────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Probe the Investigate API by looking up a well-known benign domain.
        """
        self.get("/domains/categorization/cisco.com")
        return True

    # ── ConnectorMixin — CRUD ───────────────────────────────────────────

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single indicator or allow-list entry.

        For ``"indicator"`` the *object_id* is the domain name (or STIX ID
        ``indicator--<uuid>``; the domain is re-derived from the STIX id
        if it matches the ``_stix_id()`` seed convention).

        Parameters
        ----------
        stix_type : str
            ``"indicator"`` or ``"course-of-action"``.
        object_id : str
            Domain name or STIX ID.
        """
        domain = self._extract_domain(object_id)

        if stix_type == "indicator":
            raw = self._classify_domain(domain)
            return self.to_stix(raw)

        if stix_type == "course-of-action":
            entries = self.list_allow_list()
            for entry in entries:
                if entry.get("name", "").lower() == domain.lower():
                    return self.to_stix({"type": "course-of-action", **entry})
            raise GNATClientError(f"Domain {domain!r} not found in Umbrella allow-list.")

        raise GNATClientError(
            f"get_object unsupported for STIX type {stix_type!r}. "
            "Use 'indicator' or 'course-of-action'."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List indicators (domain threat intel) or allow-list entries.

        Parameters
        ----------
        stix_type : str
            ``"indicator"`` — returns recently-seen malicious domains.
            ``"course-of-action"`` — returns allow-listed (trusted) domains.
        filters : dict, optional
            For ``"indicator"``: provide ``{"domains": ["evil.com", ...]}``.
            For ``"course-of-action"``: no server-side filters supported.
        page, page_size : int
            Pagination.
        """
        filters = dict(filters or {})

        if stix_type == "indicator":
            domains: list[str] = filters.pop("domains", [])
            if not domains:
                # Without an explicit domain list return an empty set —
                # Umbrella Investigate has no bulk "list all bad domains" API;
                # callers should pass domains to classify.
                return []
            results = []
            for domain in domains:
                try:
                    raw = self._classify_domain(domain)
                    stix_obj = self.to_stix(raw)
                    if stix_obj:
                        results.append(stix_obj)
                except GNATClientError as exc:
                    logger.warning("Umbrella: skipping %r — %s", domain, exc)
            start = (page - 1) * page_size
            return results[start : start + page_size]

        if stix_type == "course-of-action":
            entries = self.list_allow_list()
            results_ca = [self.to_stix({"type": "course-of-action", **e}) for e in entries]
            start = (page - 1) * page_size
            return results_ca[start : start + page_size]

        raise GNATClientError(
            f"list_objects unsupported for STIX type {stix_type!r}. "
            "Use 'indicator' or 'course-of-action'."
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Push a domain to the Umbrella Enforcement (block-list) API.

        Parameters
        ----------
        stix_type : str
            Must be ``"indicator"``.
        payload : dict
            STIX indicator dict; the ``pattern`` field is parsed for the domain
            value, or ``name`` is used as a fallback.
        """
        if stix_type != "indicator":
            raise GNATClientError(
                "CiscoUmbrellaClient.upsert_object only supports 'indicator' "
                "(push to Enforcement block-list)."
            )
        domain = self._extract_domain_from_stix(payload)
        self.push_block_list([domain])
        return {"domain": domain, "action": "blocked", "status": "pushed"}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Remove a domain from the Umbrella Enforcement block-list.

        Parameters
        ----------
        stix_type : str
            Must be ``"indicator"``.
        object_id : str
            Domain name or STIX ID.
        """
        if stix_type != "indicator":
            raise GNATClientError(
                "delete_object only supported for 'indicator' in CiscoUmbrellaClient."
            )
        domain = self._extract_domain(object_id)
        self._delete_from_blocklist(domain)

    # ── STIX translation ────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert an Umbrella API response to a STIX 2.1 object.

        For domain classification results the output type is ``"indicator"``.
        For allow-list entries the output type is ``"course-of-action"``.
        Security categories determine the indicator confidence and labels.

        The ``x_umbrella`` extension carries full platform metadata.
        """
        obj_type = native.get("type", "indicator")
        now = _now_ts()

        if obj_type == "course-of-action":
            name = native.get("name", "")
            return {
                "type": "course-of-action",
                "id": _stix_id("course-of-action", f"umbrella:allow:{name}"),
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": f"Allow {name}",
                "description": native.get("comment", "Umbrella allow-list entry"),
                "x_umbrella": {
                    "domain": name,
                    "list_type": "allow",
                    "raw": native,
                },
            }

        # --- indicator (domain classification) ---
        domain = native.get("domain", "")
        categories = native.get("security_categories", [])
        status = native.get("status", "unknown")
        is_malicious = bool(
            categories and any(c in _MALICIOUS_CATEGORIES for c in categories)
        ) or status in ("blocked", "malicious")

        confidence = 85 if is_malicious else 10
        labels = ["malicious-activity"] if is_malicious else ["benign"]

        if not domain:
            return {}

        pattern = f"[domain-name:value = '{domain}']"
        return {
            "type": "indicator",
            "id": _stix_id("indicator", f"umbrella:domain:{domain}"),
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": domain,
            "description": (f"Umbrella classification: {', '.join(categories) or status}"),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": confidence,
            "labels": labels,
            "object_marking_refs": [f"marking-definition--{self._tlp_marking}"],
            "x_umbrella": {
                "domain": domain,
                "status": status,
                "security_categories": categories,
                "content_categories": native.get("content_categories", []),
                "is_malicious": is_malicious,
                "risk_score": native.get("risk_score"),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a STIX indicator to an Umbrella Enforcement API payload.

        Returns a dict ready to be passed to the Enforcement API ``POST``
        endpoint.
        """
        domain = self._extract_domain_from_stix(stix_dict)
        return {
            "alertTime": _now_ts(),
            "deviceId": "GNAT",
            "deviceVersion": "0.1.0",
            "dstDomain": domain,
            "dstUrl": f"http://{domain}/",
            "eventTime": _now_ts(),
            "protocolVersion": "1.0a",
            "providerName": "GNAT",
        }

    # ── Domain-specific helpers ─────────────────────────────────────────

    def classify_domain(self, domain: str) -> dict[str, Any]:
        """
        Classify a single domain via the Umbrella Investigate API.

        Returns the raw classification dict with ``status`` and
        ``security_categories`` keys.
        """
        return self._classify_domain(domain)

    def classify_domains(self, domains: list[str]) -> dict[str, Any]:
        """
        Bulk-classify up to 100 domains in a single Investigate API call.

        Parameters
        ----------
        domains : list of str
            Domain names to classify.

        Returns
        -------
        dict
            ``{domain: classification_dict}`` mapping.
        """
        if not domains:
            return {}
        resp = self.post(
            "/domains/categorization",
            json=domains,
        )
        return resp if isinstance(resp, dict) else {}

    def get_domain_security(self, domain: str) -> dict[str, Any]:
        """
        Return the security features for a domain (Investigate API).

        Includes passive DNS info, geolocation, and threat score details.
        """
        return self.get(f"/security/name/{domain}")

    def list_allow_list(self) -> list[dict[str, Any]]:
        """
        Return all allow-listed (trusted) domains from the Management API.

        Returns
        -------
        list of dict
            Each entry has at minimum ``name`` (domain) and ``comment``.
        """
        if not self._management_key:
            raise GNATClientError(
                "CiscoUmbrellaClient.list_allow_list requires 'management_api_key'."
            )
        url = f"{self._management_host}/v1/destinationlists"
        resp = self._mgmt_http.request(
            "GET",
            url,
            headers={
                "Authorization": f"Bearer {self._management_key}",
                "Accept": "application/json",
            },
        )
        if resp.status != 200:
            raise GNATClientError(
                f"Umbrella Management API error {resp.status}: {resp.data.decode()}"
            )
        body = _json.loads(resp.data.decode())
        return body.get("data", [])

    def add_to_allow_list(self, domains: list[str], comment: str = "") -> dict[str, Any]:
        """
        Add one or more domains to the Umbrella allow-list.

        Parameters
        ----------
        domains : list of str
            Domain names to allow.
        comment : str, optional
            Human-readable reason for allow-listing.

        Returns
        -------
        dict
            Management API response.
        """
        if not self._management_key:
            raise GNATClientError(
                "CiscoUmbrellaClient.add_to_allow_list requires 'management_api_key'."
            )
        payload = [{"type": "domain", "destination": d, "comment": comment} for d in domains]
        resp = self._mgmt_http.request(
            "POST",
            f"{self._management_host}/v1/destinationlists/allow/destinations",
            body=_json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self._management_key}",
                "Content-Type": "application/json",
            },
        )
        body = _json.loads(resp.data.decode())
        if resp.status not in (200, 201):
            raise GNATClientError(f"Umbrella Management API error {resp.status}: {body}")
        return body

    def push_block_list(self, domains: list[str]) -> dict[str, Any]:
        """
        Push domains to the Umbrella Enforcement (block-list) API.

        Parameters
        ----------
        domains : list of str
            Malicious domain names to block.

        Returns
        -------
        dict
            Enforcement API response.
        """
        if not self._enforcement_key:
            raise GNATClientError(
                "CiscoUmbrellaClient.push_block_list requires 'enforcement_api_key'."
            )
        now = _now_ts()
        events = [
            {
                "alertTime": now,
                "deviceId": "GNAT",
                "deviceVersion": "0.1.0",
                "dstDomain": d,
                "dstUrl": f"http://{d}/",
                "eventTime": now,
                "protocolVersion": "1.0a",
                "providerName": "GNAT",
            }
            for d in domains
        ]
        payload = {"format": "json", "data": events}
        url = f"{self._enforcement_host}/1.0/events?customerKey={self._enforcement_key}"
        resp = self._enf_http.request(
            "POST",
            url,
            body=_json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self._enforcement_key}",
                "Content-Type": "application/json",
            },
        )
        body = {}
        if resp.data:
            with contextlib.suppress(Exception):
                body = _json.loads(resp.data.decode())
        if resp.status not in (200, 202):
            raise GNATClientError(f"Umbrella Enforcement API error {resp.status}: {body}")
        return body

    # ── Internal helpers ────────────────────────────────────────────────

    def _classify_domain(self, domain: str) -> dict[str, Any]:
        """
        Call the Investigate categorization endpoint for a single domain.

        Returns a dict with ``domain``, ``status``, and
        ``security_categories`` keys.
        """
        resp = self.get(f"/domains/categorization/{domain}")
        if not isinstance(resp, dict):
            raise GNATClientError(f"Unexpected response from Umbrella Investigate for {domain!r}.")
        classification = resp.get(domain, resp)
        return {
            "domain": domain,
            "status": classification.get("status", "unknown"),
            "security_categories": classification.get("security_categories", []),
            "content_categories": classification.get("content_categories", []),
        }

    def _extract_domain(self, value: str) -> str:
        """
        Extract a domain name from a plain domain string or STIX ID.

        If *value* looks like a STIX ID (``indicator--<uuid>``) it is returned
        as-is for upstream callers to handle; plain strings pass through.
        """
        if "--" in value:
            # STIX ID format: cannot recover domain; caller must use plain name
            return value
        return value.strip()

    def _extract_domain_from_stix(self, stix_dict: dict[str, Any]) -> str:
        """
        Parse a domain name from a STIX indicator's ``pattern`` or ``name``.
        """
        pattern = stix_dict.get("pattern", "")
        if pattern:
            # e.g. "[domain-name:value = 'evil.com']"
            import re

            match = re.search(r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]", pattern)
            if match:
                return match.group(1)
        name = stix_dict.get("name", "")
        if name:
            return name
        raise GNATClientError(
            "Cannot determine domain from STIX object: "
            "provide 'pattern' with domain-name:value or 'name'."
        )

    def _delete_from_blocklist(self, domain: str) -> None:
        """Remove a domain from the Enforcement block-list."""
        if not self._enforcement_key:
            raise GNATClientError(
                "CiscoUmbrellaClient.delete_object requires 'enforcement_api_key'."
            )
        url = f"{self._enforcement_host}/1.0/domains?customerKey={self._enforcement_key}"
        resp = self._enf_http.request(
            "DELETE",
            url,
            body=_json.dumps([domain]).encode(),
            headers={
                "Authorization": f"Bearer {self._enforcement_key}",
                "Content-Type": "application/json",
            },
        )
        if resp.status not in (200, 204):
            raise GNATClientError(
                f"Umbrella Enforcement API delete error {resp.status}: {resp.data.decode()}"
            )
