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

import hashlib
import hmac as _hmac
import base64
import time
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, SAKClientError
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

    stix_type_map: Dict[str, str] = {
        "indicator":    "indicators",
        "threat-actor": "groups",
        "malware":      "groups",
        "campaign":     "groups",
        "report":       "groups",
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

    def get_object(
        self, stix_type: str, object_id: str
    ) -> Dict[str, Any]:
        """Retrieve one TC object by numeric ID."""
        resource = self.stix_type_map.get(stix_type, "indicators")
        resp = self._request_signed("GET", f"{_API}/{resource}/{object_id}")
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List TC objects.

        ``filters`` may contain:

        * ``tql`` (str): ThreatConnect Query Language expression,
          e.g. ``"typeName EQ 'Host'"``
        * ``fields`` (str): comma-separated extra fields to include
        """
        resource = self.stix_type_map.get(stix_type, "indicators")
        params: Dict[str, Any] = {
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

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
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
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a TC indicator dict to a STIX Indicator SDO."""
        tc_type = native.get("type", "")
        value   = native.get("summary", native.get("name", ""))
        pattern = self._make_pattern(tc_type, value)
        return {
            "type":             "indicator",
            "id":               f"indicator--tc-{native.get('id', '')}",
            "name":             value,
            "pattern":          pattern,
            "pattern_type":     "stix",
            "created":          native.get("dateAdded", ""),
            "modified":         native.get("lastModified", ""),
            "confidence":       native.get("confidence", 0),
            "indicator_types":  [native.get("type", "unknown").lower()],
            "x_source_platform": "threatconnect",
            "x_tc_id":          native.get("id", ""),
            "x_tc_type":        tc_type,
            "x_tc_owner":       native.get("ownerName", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a STIX Indicator to a TC indicator payload."""
        import re
        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "summary":    value,
            "type":       self._stix_pattern_to_tc_type(pattern),
            "confidence": stix_dict.get("confidence", 0),
            "rating":     min(5, stix_dict.get("confidence", 0) // 20),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _request_signed(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
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
        message = f"{path}:{method.upper()}:{timestamp}".encode("utf-8")
        secret  = self._secret_key.encode("utf-8")
        digest  = _hmac.new(secret, message, hashlib.sha256).digest()
        return base64.b64encode(digest).decode("utf-8")

    @staticmethod
    def _make_pattern(tc_type: str, value: str) -> str:
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
