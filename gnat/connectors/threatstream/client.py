"""
gnat.connectors.threatstream.client
======================================
Anomali ThreatStream OPTIC API v2 connector.

Authentication uses an API key combined with a username as HTTP query
parameters on every request (``api_key=`` and ``username=``).

INI config::

    [threatstream]
    host      = https://api.threatstream.com
    username  = your@email.com
    api_key   = YOUR_THREATSTREAM_API_KEY
    auth_type = api_key

References
----------
https://api.threatstream.com/optic/v2/
"""

from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_API = "/optic/v2"


class ThreatStreamClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Anomali ThreatStream OPTIC API v2.

    Parameters
    ----------
    host : str
        ThreatStream base URL.  Default ``https://api.threatstream.com``.
    username : str
        ThreatStream account email address.
    api_key : str
        ThreatStream API key.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":    "intelligence",
        "threat-actor": "actor",
        "malware":      "malware",
        "campaign":     "campaign",
        "vulnerability": "vulnerability",
    }

    def __init__(
        self,
        host: str = "https://api.threatstream.com",
        username: str = "",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._username = username
        self._api_key  = api_key

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        ThreatStream embeds credentials as query parameters on every request.

        This method stores the credential pair on the instance so
        :meth:`_auth_params` can inject them into every call.
        """
        # Credentials are injected as query params, not headers
        # Store them for use in _auth_params()
        self._ts_auth = {
            "username": self._username,
            "api_key":  self._api_key,
        }

    def health_check(self) -> bool:
        """Ping the intelligence feed with a minimal query."""
        resp = self.get(
            f"{_API}/intelligence/",
            params={**self._ts_auth, "limit": 1},
        )
        return isinstance(resp, dict) and "objects" in resp

    def get_object(
        self, stix_type: str, object_id: str
    ) -> Dict[str, Any]:
        """Retrieve a single ThreatStream object by numeric ID."""
        resource = self.stix_type_map.get(stix_type, "intelligence")
        resp = self.get(
            f"{_API}/{resource}/{object_id}/",
            params=self._ts_auth,
        )
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List ThreatStream intelligence objects.

        ``filters`` may include any OPTIC API filter parameter, e.g.:

        * ``type``: IOC type (``"ip"``, ``"domain"``, ``"md5"``, etc.)
        * ``status``: ``"active"`` | ``"inactive"``
        * ``confidence__gte``: minimum confidence score
        * ``modified_ts__gte``: ISO-8601 modified-after filter
        """
        resource = self.stix_type_map.get(stix_type, "intelligence")
        params: Dict[str, Any] = {
            **self._ts_auth,
            "limit":  min(page_size, 1000),
            "offset": (page - 1) * page_size,
            "format": "json",
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/{resource}/", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("objects", [])

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Import an indicator into ThreatStream.

        Uses ``POST /optic/v2/intelligence/`` for new objects and
        ``PATCH /optic/v2/intelligence/{id}/`` for updates.
        """
        resource = self.stix_type_map.get(stix_type, "intelligence")
        obj_id = payload.pop("id", None)
        if obj_id:
            resp = self.patch(
                f"{_API}/{resource}/{obj_id}/",
                params=self._ts_auth,
                json=payload,
            )
        else:
            resp = self.post(
                f"{_API}/{resource}/",
                params=self._ts_auth,
                json={"objects": [payload]},
            )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an intelligence object by ID."""
        resource = self.stix_type_map.get(stix_type, "intelligence")
        self.delete(
            f"{_API}/{resource}/{object_id}/",
            params=self._ts_auth,
        )

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ThreatStream intelligence object to a STIX Indicator SDO."""
        ts_type = native.get("type", "")
        value   = native.get("value", native.get("ip", native.get("domain", "")))
        pattern = self._make_pattern(ts_type, value)
        conf    = native.get("confidence", 0)
        return {
            "type":              "indicator",
            "id":                f"indicator--ts-{native.get('id', '')}",
            "name":              value,
            "pattern":           pattern,
            "pattern_type":      "stix",
            "created":           native.get("created_ts", ""),
            "modified":          native.get("modified_ts", ""),
            "confidence":        conf,
            "indicator_types":   ["malicious-activity"] if conf >= 50 else ["unknown"],
            "x_source_platform": "threatstream",
            "x_ts_id":           native.get("id", ""),
            "x_ts_type":         ts_type,
            "x_ts_status":       native.get("status", ""),
            "x_ts_feed_id":      native.get("feed_id", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Build a ThreatStream intelligence import payload from a STIX dict."""
        import re
        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {
            "value":      value,
            "type":       self._stix_to_ts_type(pattern),
            "confidence": stix_dict.get("confidence", 50),
            "status":     "active",
            "source":     "gnat",
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @property
    def _ts_auth(self) -> Dict[str, str]:
        return {"username": self._username, "api_key": self._api_key}

    @_ts_auth.setter
    def _ts_auth(self, value: Dict[str, str]) -> None:
        # Setter exists so authenticate() can assign; values already stored
        pass

    @staticmethod
    def _make_pattern(ts_type: str, value: str) -> str:
        t = (ts_type or "").lower()
        if t in ("ip", "ipv4", "srcip"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6",):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain", "hostname"):
            return f"[domain-name:value = '{value}']"
        if t in ("url",):
            return f"[url:value = '{value}']"
        if t in ("md5",):
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("sha1",):
            return f"[file:hashes.'SHA-1' = '{value}']"
        if t in ("sha256",):
            return f"[file:hashes.'SHA-256' = '{value}']"
        if t in ("email",):
            return f"[email-message:from_ref.value = '{value}']"
        return f"[domain-name:value = '{value}']"

    @staticmethod
    def _stix_to_ts_type(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ip"
        if "ipv6-addr" in pattern:
            return "ipv6"
        if "domain-name" in pattern:
            return "domain"
        if "url:" in pattern:
            return "url"
        if "MD5" in pattern:
            return "md5"
        if "SHA-1" in pattern:
            return "sha1"
        if "SHA-256" in pattern:
            return "sha256"
        if "email" in pattern:
            return "email"
        return "domain"
