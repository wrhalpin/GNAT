"""
gnat.connectors.mandiant.client
=================================
Mandiant Advantage API connector.

Uses OAuth2 ``client_credentials`` grant.  The API key acts as the OAuth
``client_id`` and the API secret as ``client_secret``; credentials are sent
as HTTP Basic auth to the token endpoint.

INI config::

    [mandiant]
    host       = https://api.intelligence.mandiant.com
    api_key    = YOUR_MANDIANT_API_KEY
    api_secret = YOUR_MANDIANT_API_SECRET
    auth_type  = oauth2
"""

import base64
from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_TOKEN_PATH = "/token"
_V4 = "/v4"

# Map STIX types → Mandiant collection names
_STIX_TO_ENDPOINT: dict[str, str] = {
    "indicator": "indicator",
    "threat-actor": "actor",
    "malware": "malware",
    "report": "report",
    "vulnerability": "vulnerability",
}


class MandiantClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Mandiant Advantage Threat Intelligence API v4.

    Parameters
    ----------
    host : str
        API base URL.  Default ``https://api.intelligence.mandiant.com``.
    api_key : str
        Mandiant API key (used as OAuth2 ``client_id``).
    api_secret : str
        Mandiant API secret (used as OAuth2 ``client_secret``).
    """

    stix_type_map: dict[str, str] = _STIX_TO_ENDPOINT

    def __init__(
        self,
        host: str = "https://api.intelligence.mandiant.com",
        api_key: str = "",
        api_secret: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._api_secret = api_secret

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 Bearer token via ``client_credentials`` grant.

        Credentials are sent as HTTP Basic auth
        (``Authorization: Basic base64(api_key:api_secret)``).
        """
        creds = base64.b64encode(f"{self._api_key}:{self._api_secret}".encode()).decode()
        # Temporarily set Basic auth header for the token request
        saved = dict(self._auth_headers)
        self._auth_headers["Authorization"] = f"Basic {creds}"
        self._auth_headers["X-App-Name"] = "gnat"
        try:
            resp = self.post(
                _TOKEN_PATH,
                data={"grant_type": "client_credentials"},
            )
        finally:
            self._auth_headers.clear()
            self._auth_headers.update(saved)

        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("Mandiant: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
        self._auth_headers["X-App-Name"] = "gnat"
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Check API reachability via a lightweight indicator query."""
        resp = self.get(f"{_V4}/indicator", params={"limit": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve a single Mandiant object by type and ID/value."""
        collection = _STIX_TO_ENDPOINT.get(stix_type, "indicator")
        resp = self.get(f"{_V4}/{collection}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Mandiant objects.

        ``filters`` may include:

        * ``start_epoch`` / ``end_epoch``: Unix epoch bounds
        * ``gte_mscore``: minimum Mandiant confidence score (0–100)
        * ``type``: indicator type filter (``"ipv4"``, ``"domain"``, etc.)
        """
        collection = _STIX_TO_ENDPOINT.get(stix_type, "indicator")
        params: dict[str, Any] = {
            "limit": min(page_size, 1000),
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update({k: v for k, v in filters.items() if v is not None})

        resp = self.get(f"{_V4}/{collection}", params=params)
        if not isinstance(resp, dict):
            return []
        # Mandiant wraps results in a key matching the collection name
        items = resp.get(collection, resp.get("indicators", resp.get("objects", [])))
        return items if isinstance(items, list) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Mandiant Advantage API is read-only for most tiers.

        Raises :class:`~gnat.clients.base.GNATClientError` — submit indicators
        via the Mandiant portal or SubmitSuspected API if licensed.
        """
        raise GNATClientError(
            "Mandiant Advantage API is read-only for standard subscriptions. "
            "Use the Mandiant portal to submit indicators."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Mandiant Advantage API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Mandiant API object to a STIX dict.

        Handles indicators, actors, malware families, and vulnerabilities.
        """
        obj_type = native.get("type", "")
        if obj_type in ("Actor", "threat-actor"):
            return self._actor_to_stix(native)
        if obj_type in ("Malware", "malware"):
            return self._malware_to_stix(native)
        if obj_type in ("Vulnerability", "vulnerability"):
            return self._vuln_to_stix(native)
        return self._indicator_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a Mandiant-compatible query dict derived from a STIX object."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {"value": value, "type": self._stix_to_mandiant_type(pattern)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _indicator_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        value = native.get("value", native.get("name", ""))
        mi_type = native.get("type", "")
        pattern = self._make_pattern(mi_type, value)
        mscore = native.get("mscore", 0)
        return {
            "type": "indicator",
            "id": f"indicator--mti-{native.get('id', '')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("first_seen", ""),
            "modified": native.get("last_seen", ""),
            "confidence": mscore,
            "indicator_types": ["malicious-activity"] if mscore >= 50 else ["unknown"],
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
            "x_mandiant_type": mi_type,
            "x_mandiant_mscore": mscore,
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "threat-actor",
            "id": f"threat-actor--mti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "aliases": [a.get("name", "") for a in native.get("aliases", [])],
            "created": native.get("last_updated", ""),
            "modified": native.get("last_updated", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
        }

    def _malware_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "malware",
            "id": f"malware--mti-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "is_family": True,
            "aliases": [a.get("name", "") for a in native.get("aliases", [])],
            "created": native.get("last_updated", ""),
            "modified": native.get("last_updated", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
        }

    def _vuln_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "vulnerability",
            "id": f"vulnerability--mti-{native.get('id', '')}",
            "name": native.get("cve_id", native.get("name", "")),
            "description": native.get("description", "")[:500],
            "created": native.get("publish_date", ""),
            "modified": native.get("last_update_date", ""),
            "x_source_platform": "mandiant",
            "x_mandiant_id": native.get("id", ""),
            "x_cvss_score": native.get("common_vulnerability_scores", {})
            .get("v3.1", {})
            .get("base_score", 0),
        }

    @staticmethod
    def _make_pattern(mi_type: str, value: str) -> str:
        t = (mi_type or "").lower()
        if t in ("ipv4", "ipv4-addr", "ip"):
            return f"[ipv4-addr:value = '{value}']"
        if t in ("ipv6", "ipv6-addr"):
            return f"[ipv6-addr:value = '{value}']"
        if t in ("domain", "fqdn"):
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
    def _stix_to_mandiant_type(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ipv4"
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
        return "domain"
