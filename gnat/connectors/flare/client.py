"""
gnat.connectors.flare.client
==============================
Flare Systems Threat Exposure Intelligence connector.

Flare monitors the dark web, paste sites, GitHub, and other sources for
leaked credentials, exposed assets, and threat actor activity.  The API
key is passed in the ``Authorization: Bearer`` header.

INI config::

    [flare]
    host    = https://api.flare.io
    api_key = YOUR_FLARE_API_KEY
    auth_type = token

References
----------
https://docs.flare.io/
"""

from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.base_connector import ConnectorMixin

_API_V2 = "/api/v2"
_LEAKS   = f"{_API_V2}/leaks"
_EVENTS  = f"{_API_V2}/events"
_SOURCES = f"{_API_V2}/sources"


class FlareClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Flare Systems Threat Exposure Intelligence API.

    Parameters
    ----------
    host : str
        Flare API base URL.  Default ``https://api.flare.io``.
    api_key : str
        Flare API key.
    tenant_id : str, optional
        Flare tenant ID for multi-tenant deployments.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":    "leaks",
        "observed-data": "events",
        "threat-actor": "actors",
        "malware":      "malware",
    }

    def __init__(
        self,
        host: str = "https://api.flare.io",
        api_key: str = "",
        tenant_id: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key  = api_key
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Set the Flare API Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"]  = "application/json"

    def health_check(self) -> bool:
        """Check API connectivity by requesting sources."""
        resp = self.get(_SOURCES, params={"size": 1})
        return isinstance(resp, dict)

    def get_object(
        self, stix_type: str, object_id: str
    ) -> Dict[str, Any]:
        """Retrieve a Flare leak/event by ID."""
        resource = self.stix_type_map.get(stix_type, "leaks")
        resp = self.get(f"{_API_V2}/{resource}/{object_id}")
        return resp if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List Flare exposure events or leaks.

        ``filters`` may include:

        * ``query``: keyword search across all indexed content
        * ``source``: data source filter (``"darkweb"``, ``"paste"``, ``"github"``)
        * ``type``: event type filter
        * ``from`` / ``to``: ISO-8601 date range
        * ``severity``: ``"low"``, ``"medium"``, ``"high"``, ``"critical"``
        """
        resource = self.stix_type_map.get(stix_type, "leaks")
        params: Dict[str, Any] = {
            "size": min(page_size, 500),
            "from": (page - 1) * page_size,
        }
        if self._tenant_id:
            params["tenant_id"] = self._tenant_id
        if filters:
            params.update(filters)

        resp = self.get(f"{_API_V2}/{resource}", params=params)
        if not isinstance(resp, dict):
            return []
        # Flare returns {"items": [...]} or {"hits": [...]}
        return resp.get("items", resp.get("hits", []))

    def upsert_object(
        self, stix_type: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Flare API is read-only — raises :class:`SAKClientError`."""
        raise SAKClientError(
            "Flare Systems API is read-only. Exposure data is sourced passively."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise SAKClientError("Flare Systems API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # Extra helpers
    # ------------------------------------------------------------------

    def search_leaks(
        self, query: str, source: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Full-text search across Flare's indexed exposure data.

        Parameters
        ----------
        query : str
            Search string (e.g. email address, domain, credential fragment).
        source : str, optional
            Restrict to a data source: ``"darkweb"``, ``"paste"``, ``"github"``.
        """
        params: Dict[str, Any] = {"query": query, "size": 100}
        if source:
            params["source"] = source
        if self._tenant_id:
            params["tenant_id"] = self._tenant_id
        resp = self.get(_LEAKS, params=params)
        return resp.get("items", []) if isinstance(resp, dict) else []

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Flare leak/event record to a STIX Indicator or ObservedData."""
        event_type = native.get("type", native.get("event_type", ""))
        if event_type in ("actor", "threat_actor"):
            return self._actor_to_stix(native)
        return self._leak_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Build a Flare search query dict from a STIX dict."""
        name = stix_dict.get("name", "")
        import re
        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else name
        return {"query": value, "source": "all"}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _leak_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        leak_type = native.get("type", "")
        value     = (
            native.get("email")
            or native.get("domain")
            or native.get("url")
            or native.get("hash")
            or native.get("title", "")
        )
        pattern   = self._make_pattern(leak_type, value)
        severity  = native.get("severity", "medium")
        conf = {"critical": 90, "high": 70, "medium": 50, "low": 25}.get(
            severity.lower() if isinstance(severity, str) else "medium", 50
        )
        return {
            "type":              "indicator",
            "id":                f"indicator--flare-{native.get('id', '')}",
            "name":              value or f"Flare event {native.get('id', '')}",
            "description":       native.get("description", native.get("title", ""))[:500],
            "pattern":           pattern,
            "pattern_type":      "stix",
            "created":           native.get("created_at", native.get("date", "")),
            "modified":          native.get("updated_at", ""),
            "confidence":        conf,
            "indicator_types":   ["malicious-activity"],
            "x_source_platform": "flare",
            "x_flare_id":        native.get("id", ""),
            "x_flare_type":      leak_type,
            "x_flare_source":    native.get("source", native.get("bucket", "")),
            "x_flare_severity":  severity,
        }

    def _actor_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type":              "threat-actor",
            "id":                f"threat-actor--flare-{native.get('id', '')}",
            "name":              native.get("name", native.get("alias", "")),
            "description":       native.get("description", "")[:500],
            "created":           native.get("created_at", ""),
            "modified":          native.get("updated_at", ""),
            "x_source_platform": "flare",
            "x_flare_id":        native.get("id", ""),
        }

    @staticmethod
    def _make_pattern(event_type: str, value: str) -> str:
        t = (event_type or "").lower()
        if t in ("email", "credential"):
            return f"[email-message:from_ref.value = '{value}']"
        if t in ("domain",):
            return f"[domain-name:value = '{value}']"
        if t in ("url", "paste"):
            return f"[url:value = '{value}']"
        if t in ("hash",):
            if len(value) == 64:
                return f"[file:hashes.'SHA-256' = '{value}']"
            return f"[file:hashes.'MD5' = '{value}']"
        if t in ("ip",):
            return f"[ipv4-addr:value = '{value}']"
        # Fallback: use name/description as a note-like pattern
        safe = value.replace("'", "\\'")
        return f"[domain-name:value = '{safe}']"
