"""
gnat.connectors.cloudsek.client
=================================
CloudSEK XVigil Attack Surface Management + Digital Risk connector.

Uses an API key passed in the ``Authorization: Bearer`` header.
XVigil monitors for leaked credentials, exposed assets, brand impersonation,
and dark-web mentions.

INI config::

    [cloudsek]
    host    = https://api.cloudsek.com
    api_key = YOUR_CLOUDSEK_API_KEY
    auth_type = token

References
----------
https://docs.cloudsek.com/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_API = "/xvigil/v1"


class CloudSEKClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the CloudSEK XVigil API.

    Parameters
    ----------
    host : str
        CloudSEK API base URL.  Default ``https://api.cloudsek.com``.
    api_key : str
        CloudSEK API key.
    org_id : str, optional
        CloudSEK organisation ID for multi-tenant deployments.
    """

    stix_type_map: dict[str, str] = {
        "indicator":    "indicators",
        "observed-data": "alerts",
        "threat-actor": "threat_actors",
        "malware":      "malware",
    }

    def __init__(
        self,
        host: str = "https://api.cloudsek.com",
        api_key: str = "",
        org_id: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._org_id  = org_id

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Set Bearer token and optional organisation header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"]  = "application/json"
        if self._org_id:
            self._auth_headers["X-Org-Id"] = self._org_id

    def health_check(self) -> bool:
        """Check API connectivity via a minimal alert query."""
        resp = self.get(f"{_API}/alerts", params={"limit": 1})
        return isinstance(resp, dict)

    def get_object(
        self, stix_type: str, object_id: str
    ) -> dict[str, Any]:
        """Retrieve a CloudSEK alert or indicator by ID."""
        resource = self.stix_type_map.get(stix_type, "alerts")
        resp = self.get(f"{_API}/{resource}/{object_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List CloudSEK XVigil alerts or indicators.

        ``filters`` may include:

        * ``category``: alert category (``"credential_leak"``, ``"brand_abuse"``, etc.)
        * ``severity``: ``"low"``, ``"medium"``, ``"high"``, ``"critical"``
        * ``status``: ``"open"``, ``"resolved"``, ``"false_positive"``
        * ``from_date`` / ``to_date``: ISO-8601 date strings
        * ``keyword``: search keyword
        """
        resource = self.stix_type_map.get(stix_type, "alerts")
        params: dict[str, Any] = {
            "limit":  min(page_size, 500),
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/{resource}", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("data", resp.get("results", []))

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """CloudSEK XVigil API is read-only — raises :class:`GNATClientError`."""
        raise GNATClientError(
            "CloudSEK XVigil API is read-only. "
            "Alerts are generated automatically from passive monitoring."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("CloudSEK XVigil API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # Extra helpers
    # ------------------------------------------------------------------

    def update_alert_status(
        self, alert_id: str, status: str, comment: str = ""
    ) -> dict[str, Any]:
        """
        Update the status of a CloudSEK alert (triage workflow).

        Parameters
        ----------
        alert_id : str
            Alert ID.
        status : str
            New status: ``"acknowledged"``, ``"resolved"``, ``"false_positive"``.
        comment : str, optional
            Analyst comment to attach to the status change.
        """
        payload: dict[str, Any] = {"status": status}
        if comment:
            payload["comment"] = comment
        resp = self.patch(f"{_API}/alerts/{alert_id}/status", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a CloudSEK alert or indicator dict to a STIX dict."""
        category = native.get("category", native.get("type", ""))
        if category in ("threat_actor",):
            return self._actor_to_stix(native)
        return self._alert_to_stix(native)

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a CloudSEK search query from a STIX dict."""
        import re
        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        value = m.group(1) if m else stix_dict.get("name", "")
        return {"keyword": value, "category": self._stix_to_cs_category(pattern)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _alert_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        category = native.get("category", "")
        value    = (
            native.get("email")
            or native.get("domain")
            or native.get("url")
            or native.get("keyword", native.get("title", ""))
        )
        pattern  = self._make_pattern(category, value)
        severity = native.get("severity", "medium")
        conf = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(
            severity.lower() if isinstance(severity, str) else "medium", 50
        )
        return {
            "type":              "indicator",
            "id":                f"indicator--cs-{native.get('id', '')}",
            "name":              value or native.get("title", ""),
            "description":       native.get("description", native.get("title", ""))[:500],
            "pattern":           pattern,
            "pattern_type":      "stix",
            "created":           native.get("created_at", native.get("date", "")),
            "modified":          native.get("updated_at", ""),
            "confidence":        conf,
            "indicator_types":   ["malicious-activity"],
            "x_source_platform": "cloudsek",
            "x_cs_id":           native.get("id", ""),
            "x_cs_category":     category,
            "x_cs_severity":     severity,
            "x_cs_status":       native.get("status", ""),
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        return {
            "type":              "threat-actor",
            "id":                f"threat-actor--cs-{native.get('id', '')}",
            "name":              native.get("name", ""),
            "description":       native.get("description", "")[:500],
            "created":           native.get("created_at", ""),
            "modified":          native.get("updated_at", ""),
            "x_source_platform": "cloudsek",
            "x_cs_id":           native.get("id", ""),
        }

    @staticmethod
    def _make_pattern(category: str, value: str) -> str:
        cat = (category or "").lower()
        if "credential" in cat or "email" in cat:
            return f"[email-message:from_ref.value = '{value}']"
        if "domain" in cat or "brand" in cat or "phishing" in cat:
            return f"[domain-name:value = '{value}']"
        if "url" in cat:
            return f"[url:value = '{value}']"
        if "ip" in cat:
            return f"[ipv4-addr:value = '{value}']"
        if "hash" in cat:
            return f"[file:hashes.'SHA-256' = '{value}']"
        safe = value.replace("'", "\\'") if value else "unknown"
        return f"[domain-name:value = '{safe}']"

    @staticmethod
    def _stix_to_cs_category(pattern: str) -> str:
        if "ipv4-addr" in pattern:
            return "ip_exposure"
        if "domain-name" in pattern:
            return "brand_abuse"
        if "url:" in pattern:
            return "phishing"
        if "email" in pattern:
            return "credential_leak"
        if "file:hashes" in pattern:
            return "malware"
        return "brand_abuse"
