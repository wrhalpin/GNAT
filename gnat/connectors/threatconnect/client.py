# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.threatconnect.client
======================================
ThreatConnect TC Exchange API v3 connector.

Supports two authentication modes:

* **TC-Token** (``auth_type = token``): static API token generated in the TC UI.
  Most common for service accounts and integrations.
* **HMAC** (``auth_type = hmac``): per-request HMAC-SHA256 signature using an
  Access ID + Secret Key pair.  Signature covers the request path and timestamp.

INI config (token mode)::

    [threatconnect]
    host      = https://app.threatconnect.com
    api_key   = YOUR_TC_API_TOKEN
    auth_type = token

INI config (HMAC mode)::

    [threatconnect]
    host       = https://app.threatconnect.com
    access_id  = YOUR_ACCESS_ID
    secret_key = YOUR_SECRET_KEY
    auth_type  = hmac
"""

import base64
import hashlib
import hmac as _hmac
import time
from typing import Any, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_API = "/api/v3"


class ThreatConnectClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the ThreatConnect TC Exchange API v3.

    Parameters
    ----------
    host : str
        API base URL, e.g. ``https://app.threatconnect.com``.
    api_key : str
        TC-Token (static API token).  Used when ``auth_type = token``.
    access_id : str
        HMAC Access ID.  Used when ``auth_type = hmac``.
    secret_key : str
        HMAC Secret Key.  Used when ``auth_type = hmac``.
    auth_type : str
        ``"token"`` (default) or ``"hmac"``.
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v3"
    API_PREFIX: str = "/api"

    stix_type_map: dict[str, str] = {
        "indicator": "indicators",
        "threat-actor": "groups",
        "malware": "groups",
        "campaign": "groups",
        "report": "groups",
    }

    def __init__(
        self,
        host: str = "https://app.threatconnect.com",
        api_key: str = "",
        access_id: str = "",
        secret_key: str = "",
        auth_type: str = "token",
        **kwargs: Any,
    ) -> None:
        """Initialize ThreatConnectClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._access_id = access_id
        self._secret_key = secret_key
        self._auth_type = auth_type.lower()

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Configure authentication headers.

        For ``token`` mode sets a static ``TC-Token`` header.
        For ``hmac`` mode the signature is computed per-request via
        :meth:`_hmac_headers`; this method marks the mode as active.
        """
        if self._auth_type == "token":
            self._auth_headers["Authorization"] = f"TC-Token {self._api_key}"
        # HMAC headers are generated per-request in _hmac_headers(); nothing
        # to store statically here.

    def health_check(self) -> bool:
        """Ping the whoami endpoint to verify credentials."""
        self.get(f"{_API}/whoami")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve one TC object by numeric ID."""
        resource = self.stix_type_map.get(stix_type, "indicators")
        resp = self._request_signed("GET", f"{_API}/{resource}/{object_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List TC objects.

        ``filters`` may contain:

        * ``tql`` (str): ThreatConnect Query Language expression,
          e.g. ``"typeName EQ 'Host'"``
        * ``fields`` (str): comma-separated extra fields to include
        """
        resource = self.stix_type_map.get(stix_type, "indicators")
        params: dict[str, Any] = {
            "resultStart": (page - 1) * page_size,
            "resultLimit": page_size,
        }
        if filters:
            if "tql" in filters:
                params["tql"] = filters["tql"]
            if "fields" in filters:
                params["fields"] = filters["fields"]

        resp = self._request_signed("GET", f"{_API}/{resource}", params=params)
        if not isinstance(resp, dict):
            return []
        data = resp.get("data", [])
        return data if isinstance(data, list) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update a TC indicator/group."""
        resource = self.stix_type_map.get(stix_type, "indicators")
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self._request_signed("PUT", f"{_API}/{resource}/{obj_id}", json=payload)
        else:
            resp = self._request_signed("POST", f"{_API}/{resource}", json=payload)
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete a TC object by numeric ID."""
        resource = self.stix_type_map.get(stix_type, "indicators")
        self._request_signed("DELETE", f"{_API}/{resource}/{object_id}")

    # ------------------------------------------------------------------
    # Domain-specific helpers
    # ------------------------------------------------------------------

    def search_indicators(
        self,
        query: str = "",
        confidence_gte: int | None = None,
        rating_gte: int | None = None,
        tag: str = "",
        owner: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search TC indicators with the v3 TQL filter language."""
        tql_parts: list[str] = []
        if query:
            tql_parts.append(f'summary LIKE "%{query}%"')
        if confidence_gte is not None:
            tql_parts.append(f"confidence >= {int(confidence_gte)}")
        if rating_gte is not None:
            tql_parts.append(f"rating >= {int(rating_gte)}")
        if tag:
            tql_parts.append(f'hasTag and tag.name = "{tag}"')
        if owner:
            tql_parts.append(f'ownerName = "{owner}"')
        params: dict[str, Any] = {"resultLimit": int(limit)}
        if tql_parts:
            params["tql"] = " AND ".join(tql_parts)
        resp = self._request_signed(
            "GET", f"{_API}/indicators", params=params
        )
        return _extract_tc_data(resp)

    def search_groups(
        self,
        group_type: str = "",
        name: str = "",
        tag: str = "",
        owner: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search TC groups (threat-actor, malware, campaign, report).

        ``group_type`` is one of ``"Threat"``, ``"Adversary"``,
        ``"Malware"``, ``"Campaign"``, ``"Report"``, ``"Incident"``.
        """
        tql_parts: list[str] = []
        if group_type:
            tql_parts.append(f'typeName = "{group_type}"')
        if name:
            tql_parts.append(f'name LIKE "%{name}%"')
        if tag:
            tql_parts.append(f'hasTag and tag.name = "{tag}"')
        if owner:
            tql_parts.append(f'ownerName = "{owner}"')
        params: dict[str, Any] = {"resultLimit": int(limit)}
        if tql_parts:
            params["tql"] = " AND ".join(tql_parts)
        resp = self._request_signed(
            "GET", f"{_API}/groups", params=params
        )
        return _extract_tc_data(resp)

    def list_owners(self) -> list[dict[str, Any]]:
        """Return all TC organizations / communities the caller can see."""
        resp = self._request_signed("GET", f"{_API}/security/owners")
        return _extract_tc_data(resp)

    def get_indicator(self, indicator_id: str) -> dict[str, Any]:
        """Fetch a single indicator by numeric id."""
        return self.get_object("indicator", indicator_id)

    def get_group(self, group_id: str) -> dict[str, Any]:
        """Fetch a single group by numeric id."""
        return self.get_object("threat-actor", group_id)

    def list_tags(self, name: str = "") -> list[dict[str, Any]]:
        """Return TC tags, optionally filtered by name substring."""
        params: dict[str, Any] = {"resultLimit": 1000}
        if name:
            params["tql"] = f'name LIKE "%{name}%"'
        resp = self._request_signed("GET", f"{_API}/tags", params=params)
        return _extract_tc_data(resp)

    def get_associations(
        self, object_type: str, object_id: str
    ) -> dict[str, Any]:
        """
        Return the association graph for an indicator or group.

        ``object_type`` is ``"indicators"`` or ``"groups"``.
        """
        resp = self._request_signed(
            "GET",
            f"{_API}/{object_type}/{object_id}",
            params={"fields": "associatedIndicators,associatedGroups,tags"},
        )
        return resp if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a TC indicator dict to a STIX Indicator SDO."""
        tc_type = native.get("type", "")
        value = native.get("summary", native.get("name", ""))
        pattern = self._make_pattern(tc_type, value)
        return {
            "type": "indicator",
            "id": f"indicator--tc-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("dateAdded", ""),
            "modified": native.get("lastModified", ""),
            "confidence": native.get("confidence", 0),
            "indicator_types": [native.get("type", "unknown").lower()],
            "x_source_platform": "threatconnect",
            "x_tc_id": native.get("id", ""),
            "x_tc_type": tc_type,
            "x_tc_owner": native.get("ownerName", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX Indicator to a TC indicator payload."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "summary": value,
            "type": self._stix_pattern_to_tc_type(pattern),
            "confidence": stix_dict.get("confidence", 0),
            "rating": min(5, stix_dict.get("confidence", 0) // 20),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _request_signed(
        self,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Dispatch an HTTP request with HMAC headers if needed."""
        if self._auth_type == "hmac":
            ts = str(int(time.time() * 1000))
            sig = self._compute_hmac(path, method, ts)
            extra = {
                "Authorization": f"TC {self._access_id}:{sig}",
                "Timestamp": ts,
            }
            # Temporarily merge HMAC headers
            saved = dict(self._auth_headers)
            self._auth_headers.update(extra)
            try:
                result = getattr(self, method.lower())(path, params=params, json=json)
            finally:
                self._auth_headers.clear()
                self._auth_headers.update(saved)
            return result
        return getattr(self, method.lower())(path, params=params, json=json)

    def _compute_hmac(self, path: str, method: str, timestamp: str) -> str:
        """Compute HMAC-SHA256 signature: HMAC(secret_key, path:method:timestamp)."""
        message = f"{path}:{method.upper()}:{timestamp}".encode()
        secret = self._secret_key.encode("utf-8")
        digest = _hmac.new(secret, message, hashlib.sha256).digest()
        return base64.b64encode(digest).decode("utf-8")

    @staticmethod
    def _make_pattern(tc_type: str, value: str) -> str:
        """Internal helper for make pattern."""
        t = tc_type.lower()
        if t in ("address", "host"):
            if "." in value and not value.startswith("http"):
                try:
                    parts = value.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        return f"[ipv4-addr:value = '{value}']"
                except Exception:
                    pass
            return f"[domain-name:value = '{value}']"
        if t in ("emailaddress", "email"):
            return f"[email-message:from_ref.value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("file", "hash"):
            if len(value) == 64:
                return f"[file:hashes.'SHA-256' = '{value}']"
            if len(value) == 40:
                return f"[file:hashes.'SHA-1' = '{value}']"
            return f"[file:hashes.'MD5' = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_pattern_to_tc_type(pattern: str) -> str:
        """Internal helper for stix pattern to tc type."""
        if "ipv4-addr" in pattern or "ipv6-addr" in pattern:
            return "Address"
        if "domain-name" in pattern:
            return "Host"
        if "url:" in pattern:
            return "URL"
        if "email" in pattern:
            return "EmailAddress"
        if "file:" in pattern:
            return "File"
        return "Host"


def _extract_tc_data(resp: Any) -> list[dict[str, Any]]:
    """Pull the list of records out of a ThreatConnect v3 response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    data = resp.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []
