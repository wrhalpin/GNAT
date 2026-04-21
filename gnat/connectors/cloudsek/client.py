# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/xvigil"

    stix_type_map: dict[str, str] = {
        "indicator": "indicators",
        "observed-data": "alerts",
        "threat-actor": "threat_actors",
        "malware": "malware",
    }

    def __init__(
        self,
        host: str = "https://api.cloudsek.com",
        api_key: str = "",
        org_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize CloudSEKClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._org_id = org_id

    # ------------------------------------------------------------------
    # ConnectorMixin interface
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Set Bearer token and optional organisation header."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"] = "application/json"
        if self._org_id:
            self._auth_headers["X-Org-Id"] = self._org_id

    def health_check(self) -> bool:
        """Check API connectivity via a minimal alert query."""
        resp = self.get(f"{_API}/alerts", params={"limit": 1})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
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
            "limit": min(page_size, 500),
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)

        resp = self.get(f"{_API}/{resource}", params=params)
        if not isinstance(resp, dict):
            return []
        return resp.get("data", resp.get("results", []))

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """CloudSEK XVigil API is read-only — raises :class:`GNATClientError`."""
        raise GNATClientError(
            "CloudSEK XVigil API is read-only. "
            "Alerts are generated automatically from passive monitoring."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("CloudSEK XVigil API is read-only — delete not supported.")

    # ------------------------------------------------------------------
    # Extra helpers
    # ------------------------------------------------------------------

    def update_alert_status(self, alert_id: str, status: str, comment: str = "") -> dict[str, Any]:
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
        """Internal helper for alert to stix."""
        category = native.get("category", "")
        value = (
            native.get("email")
            or native.get("domain")
            or native.get("url")
            or native.get("keyword", native.get("title", ""))
        )
        pattern = self._make_pattern(category, value)
        severity = native.get("severity", "medium")
        conf = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(
            severity.lower() if isinstance(severity, str) else "medium", 50
        )
        return {
            "type": "indicator",
            "id": f"indicator--cs-{native.get('id', '')}",
            "name": value or native.get("title", ""),
            "description": native.get("description", native.get("title", ""))[:500],
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("created_at", native.get("date", "")),
            "modified": native.get("updated_at", ""),
            "confidence": conf,
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "cloudsek",
            "x_cs_id": native.get("id", ""),
            "x_cs_category": category,
            "x_cs_severity": severity,
            "x_cs_status": native.get("status", ""),
        }

    def _actor_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Internal helper for actor to stix."""
        return {
            "type": "threat-actor",
            "id": f"threat-actor--cs-{native.get('id', '')}",
            "name": native.get("name", ""),
            "description": native.get("description", "")[:500],
            "created": native.get("created_at", ""),
            "modified": native.get("updated_at", ""),
            "x_source_platform": "cloudsek",
            "x_cs_id": native.get("id", ""),
        }

    @staticmethod
    def _make_pattern(category: str, value: str) -> str:
        """Internal helper for make pattern."""
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
        """Internal helper for stix to cs category."""
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

    # ── Alerts ────────────────────────────────────────────────────────────────

    def list_alerts(
        self,
        category: str = "",
        severity: str = "",
        status: str = "",
        from_date: str = "",
        to_date: str = "",
        keyword: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List XVigil alerts with optional filters.

        Parameters
        ----------
        category : str
            Alert category: ``"credential_leak"``, ``"brand_abuse"``,
            ``"phishing"``, ``"dark_web"``, ``"ip_exposure"``, etc.
        severity : str
            ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``.
        status : str
            ``"open"``, ``"acknowledged"``, ``"resolved"``, ``"false_positive"``.
        from_date / to_date : str
            ISO-8601 date range, e.g. ``"2024-01-01"``.
        keyword : str
            Free-text keyword search.
        """
        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "offset": offset,
        }
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if keyword:
            params["keyword"] = keyword

        resp = self.get(f"{_API}/alerts", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Retrieve a specific XVigil alert by ID."""
        resp = self.get(f"{_API}/alerts/{alert_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def add_alert_comment(self, alert_id: str, comment: str) -> dict[str, Any]:
        """Add an analyst comment to an alert."""
        resp = self.post(f"{_API}/alerts/{alert_id}/comments", json={"comment": comment})
        return resp if isinstance(resp, dict) else {}

    def list_credential_leaks(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List credential leak alerts (exposed usernames/passwords)."""
        return self.list_alerts(
            category="credential_leak",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    def list_brand_abuse(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List brand abuse / impersonation alerts."""
        return self.list_alerts(
            category="brand_abuse",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    def list_phishing_urls(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List phishing URL / site alerts."""
        return self.list_alerts(
            category="phishing",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    def list_dark_web_mentions(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List dark web mention alerts."""
        return self.list_alerts(
            category="dark_web",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    def list_exposed_assets(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List exposed asset / IP exposure alerts."""
        return self.list_alerts(
            category="ip_exposure",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    def list_code_leaks(
        self, limit: int = 100, from_date: str = "", to_date: str = ""
    ) -> list[dict[str, Any]]:
        """List source code leak alerts (GitHub, GitLab, Pastebin exposure)."""
        return self.list_alerts(
            category="code_leak",
            limit=limit,
            from_date=from_date,
            to_date=to_date,
        )

    # ── Indicators ────────────────────────────────────────────────────────────

    def search_indicators(
        self,
        keyword: str,
        ioc_type: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Search XVigil threat indicators.

        ``ioc_type`` options: ``"ip"``, ``"domain"``, ``"url"``, ``"email"``,
        ``"hash"``, ``"cve"``.
        """
        params: dict[str, Any] = {
            "keyword": keyword,
            "limit": min(limit, 500),
            "offset": offset,
        }
        if ioc_type:
            params["type"] = ioc_type
        resp = self.get(f"{_API}/indicators", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_domain_intelligence(self, domain: str) -> dict[str, Any]:
        """
        Get threat intelligence for a specific domain.

        Returns risk score, historical alerts, and associated threat actors.
        """
        resp = self.get(f"{_API}/intelligence/domain", params={"domain": domain})
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def get_ip_intelligence(self, ip: str) -> dict[str, Any]:
        """
        Get threat intelligence for a specific IP address.

        Returns geolocation, ASN, open ports, and associated threat data.
        """
        resp = self.get(f"{_API}/intelligence/ip", params={"ip": ip})
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def get_email_intelligence(self, email: str) -> dict[str, Any]:
        """
        Check an email address against CloudSEK breach databases.

        Returns breach records, credential leaks, and account exposure.
        """
        resp = self.get(f"{_API}/intelligence/email", params={"email": email})
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ── Threat actors ─────────────────────────────────────────────────────────

    def list_threat_actors(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """List tracked threat actor profiles."""
        resp = self.get(
            f"{_API}/threat_actors",
            params={"limit": min(limit, 500), "offset": offset},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_threat_actor(self, actor_id: str) -> dict[str, Any]:
        """Retrieve a specific threat actor profile."""
        resp = self.get(f"{_API}/threat_actors/{actor_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def get_actor_alerts(self, actor_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """List alerts attributed to a specific threat actor."""
        resp = self.get(
            f"{_API}/threat_actors/{actor_id}/alerts",
            params={"limit": limit},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Malware ───────────────────────────────────────────────────────────────

    def list_malware_families(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """List tracked malware family profiles."""
        resp = self.get(
            f"{_API}/malware",
            params={"limit": min(limit, 500), "offset": offset},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_malware_family(self, malware_id: str) -> dict[str, Any]:
        """Retrieve a specific malware family profile."""
        resp = self.get(f"{_API}/malware/{malware_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ── Watchlist (monitoring keywords) ──────────────────────────────────────

    def list_watchlist_keywords(self) -> list[dict[str, Any]]:
        """List currently monitored keywords/assets in the XVigil watchlist."""
        resp = self.get(f"{_API}/watchlist")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def add_watchlist_keyword(
        self,
        keyword: str,
        category: str = "brand_abuse",
        alert_on_match: bool = True,
    ) -> dict[str, Any]:
        """
        Add a keyword to the XVigil monitoring watchlist.

        ``category`` controls which detection module monitors the keyword.
        """
        payload: dict[str, Any] = {
            "keyword": keyword,
            "category": category,
            "alert_on_match": alert_on_match,
        }
        resp = self.post(f"{_API}/watchlist", json=payload)
        return resp if isinstance(resp, dict) else {}

    def remove_watchlist_keyword(self, keyword_id: str) -> dict[str, Any]:
        """Remove a keyword from the watchlist by ID."""
        resp = self.delete(f"{_API}/watchlist/{keyword_id}")
        return resp if isinstance(resp, dict) else {}

    # ── Dashboard & reporting ─────────────────────────────────────────────────

    def get_executive_summary(
        self,
        from_date: str = "",
        to_date: str = "",
    ) -> dict[str, Any]:
        """
        Retrieve the XVigil executive dashboard summary.

        Returns alert counts by category and severity, trend data,
        and top threat actors for the specified time window.
        """
        params: dict[str, Any] = {}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        resp = self.get(f"{_API}/dashboard/summary", params=params)
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def get_risk_score(self) -> dict[str, Any]:
        """
        Retrieve the organisation's current XVigil risk score.

        Returns an overall digital risk score with component breakdowns
        (brand exposure, credential leaks, dark web presence, etc.).
        """
        resp = self.get(f"{_API}/risk_score")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def export_alerts(
        self,
        export_format: str = "json",
        from_date: str = "",
        to_date: str = "",
        category: str = "",
    ) -> dict[str, Any]:
        """
        Export alerts in bulk.

        ``export_format`` options: ``"json"`` (default), ``"csv"``.
        Returns a dict containing download URL or inline data.
        """
        params: dict[str, Any] = {"format": export_format}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if category:
            params["category"] = category
        resp = self.get(f"{_API}/alerts/export", params=params)
        return resp if isinstance(resp, dict) else {}

    # ── Asset management ──────────────────────────────────────────────────────

    def list_monitored_assets(self) -> list[dict[str, Any]]:
        """List all assets currently monitored by CloudSEK XVigil."""
        resp = self.get(f"{_API}/assets")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def add_monitored_asset(
        self,
        asset_type: str,
        value: str,
        label: str = "",
    ) -> dict[str, Any]:
        """
        Register an asset for monitoring.

        ``asset_type`` options: ``"domain"``, ``"ip"``, ``"email_domain"``,
        ``"brand_keyword"``, ``"mobile_app"``.
        """
        payload: dict[str, Any] = {"type": asset_type, "value": value}
        if label:
            payload["label"] = label
        resp = self.post(f"{_API}/assets", json=payload)
        return resp if isinstance(resp, dict) else {}

    def remove_monitored_asset(self, asset_id: str) -> dict[str, Any]:
        """Remove an asset from monitoring."""
        resp = self.delete(f"{_API}/assets/{asset_id}")
        return resp if isinstance(resp, dict) else {}
