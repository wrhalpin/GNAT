"""
gnat.connectors.rapid7.client
==================================

Rapid7 connector — InsightVM (vulnerability management) and
Threat Command (threat intelligence).

Two product APIs are supported:

**InsightVM** (``product = insightvm``):
Vulnerability scan data, asset inventory, CVE findings, exploit
availability, and remediation status.  REST API v3.

**Threat Command** (``product = threat_command``):
External threat intelligence — IOCs, threat actor profiles, CVE
intelligence, dark web mentions.  Previously IntSights.

INI config::

    [rapid7]
    host     = https://us.api.insight.rapid7.com
    api_key  = <rapid7-platform-api-key>
    product  = insightvm          # or: threat_command
    auth_type = token

    # For Threat Command (separate endpoint):
    # host      = https://api.ti.insight.rapid7.com
    # account_id = <account-id>

References
----------
https://docs.rapid7.com/insight/api-overview/
https://docs.rapid7.com/insightvm/api/v3/
https://docs.rapid7.com/threat-command/
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class Rapid7Client(BaseClient, ConnectorMixin):
    """
    HTTP client for Rapid7 InsightVM and Threat Command APIs.

    Parameters
    ----------
    host : str
        API base URL.
    api_key : str
        Rapid7 Platform API key.
    product : str
        ``"insightvm"`` or ``"threat_command"``.
    account_id : str, optional
        Threat Command account id (required for Threat Command).
    """

    stix_type_map: dict[str, str] = {
        "vulnerability": "vulnerabilities",
        "indicator": "iocs",
        "threat-actor": "threat-actors",
        "asset": "assets",
    }

    def __init__(
        self,
        host: str,
        api_key: str = "",
        product: str = "insightvm",
        account_id: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._product = product.lower()
        self._account = account_id

    def authenticate(self) -> None:
        self._auth_headers["X-Api-Key"] = self._api_key
        if self._account:
            self._auth_headers["Account-Id"] = self._account

    def health_check(self) -> bool:
        if self._product == "insightvm":
            resp = self.get("/vm/v4/integration/vulnerabilities", params={"size": 1})
        else:
            resp = self.get("/public/v2/iocs/ioc-by-value", params={"iocValue": "google.com"})
        return isinstance(resp, dict)

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if self._product == "insightvm":
            return self._insightvm_get(stix_type, object_id)
        return self._tc_get(stix_type, object_id)

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        if self._product == "insightvm":
            return self._insightvm_list(stix_type, filters, page, page_size)
        return self._tc_list(stix_type, filters, page, page_size)

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._product == "insightvm":
            raise GNATClientError(
                "InsightVM is read-only via GNAT. "
                "Use the InsightVM console for remediation tracking."
            )
        # Threat Command supports IOC submissions
        if stix_type != "indicator":
            raise GNATClientError(
                f"Threat Command upsert only supports 'indicator', not {stix_type!r}"
            )
        return self.post("/public/v2/iocs", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        if self._product == "insightvm":
            raise GNATClientError("InsightVM is read-only — delete not supported.")
        self.delete(f"/public/v2/iocs/{object_id}")

    # ── InsightVM ──────────────────────────────────────────────────────────

    def _insightvm_get(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "vulnerability":
            resp = self.get(f"/vm/v4/integration/vulnerabilities/{object_id}")
            return resp if isinstance(resp, dict) else {}
        if stix_type == "asset":
            resp = self.get(f"/vm/v4/integration/assets/{object_id}")
            return resp if isinstance(resp, dict) else {}
        return {}

    def _insightvm_list(
        self, stix_type: str, filters: Optional[dict[str, Any]], page: int, page_size: int
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "page": page - 1,
            "size": page_size,
        }
        if stix_type == "vulnerability":
            if filters:
                params.update(filters)
            resp = self.get("/vm/v4/integration/vulnerabilities", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        if stix_type == "asset":
            resp = self.get("/vm/v4/integration/assets", params=params)
            return resp.get("data", []) if isinstance(resp, dict) else []
        return []

    # ── Threat Command ─────────────────────────────────────────────────────

    def _tc_get(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if stix_type == "indicator":
            resp = self.get("/public/v2/iocs/ioc-by-value", params={"iocValue": object_id})
            return resp if isinstance(resp, dict) else {}
        if stix_type == "threat-actor":
            resp = self.get(f"/public/v2/threat-actors/{object_id}")
            return resp if isinstance(resp, dict) else {}
        return {}

    def _tc_list(
        self, stix_type: str, filters: Optional[dict[str, Any]], page: int, page_size: int
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if stix_type == "indicator":
            if filters:
                params.update(filters)
            resp = self.get("/public/v2/iocs", params=params)
            return resp.get("content", []) if isinstance(resp, dict) else []
        if stix_type == "threat-actor":
            resp = self.get("/public/v2/threat-actors", params=params)
            return resp.get("content", []) if isinstance(resp, dict) else []
        return []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        if self._product == "insightvm":
            return self._vuln_to_stix(native)
        return self._ioc_to_stix(native)

    def _vuln_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """InsightVM vulnerability → STIX Vulnerability."""
        vuln_id = native.get("id", "")
        cves = native.get("cves", [])
        primary_cve = cves[0] if cves else ""
        severity = native.get("severity", "")
        cvss = native.get("cvss", {})
        score_v3 = (cvss.get("v3", {}) or {}).get("base_score")
        score_v2 = (cvss.get("v2", {}) or {}).get("base_score")
        cvss_score = score_v3 or score_v2

        exploits = native.get("exploits", [])
        exploited = len(exploits) > 0

        return {
            "type": "vulnerability",
            "id": f"vulnerability--r7-{vuln_id}",
            "name": primary_cve or vuln_id,
            "description": native.get("description", {}).get("text", "")[:500],
            "created": native.get("added", ""),
            "modified": native.get("modified", ""),
            "x_cve_id": primary_cve,
            "x_cvss_score": cvss_score,
            "x_severity": severity,
            "x_actively_exploited": exploited,
            "x_exploit_count": len(exploits),
            "x_source_platform": "rapid7_insightvm",
            "x_r7_vuln_id": vuln_id,
        }

    def _ioc_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Threat Command IOC → STIX Indicator."""
        ioc_type = native.get("type", "Domain").lower()
        value = native.get("value", "")
        severity = native.get("severity", "")
        tags = native.get("tags", [])

        pattern_map = {
            "ipaddresses": f"[ipv4-addr:value = '{value}']",
            "domains": f"[domain-name:value = '{value}']",
            "urls": f"[url:value = '{value}']",
            "hashes": f"[file:hashes.'SHA-256' = '{value}']",
            "emails": f"[email-addr:value = '{value}']",
        }
        pattern = pattern_map.get(ioc_type, f"[domain-name:value = '{value}']")

        confidence_map = {"critical": 90, "high": 75, "medium": 55, "low": 35}
        confidence = confidence_map.get(severity.lower(), 50)

        # Extract sector from tags
        sectors = [
            t for t in tags if t not in ("malware", "phishing", "botnet", "c2", "ransomware")
        ]

        return {
            "type": "indicator",
            "id": f"indicator--r7-{value[:40].replace('/', '_')}",
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("firstSeen", ""),
            "modified": native.get("lastSeen", ""),
            "confidence": confidence,
            "indicator_types": ["malicious-activity"],
            "x_source_platform": "rapid7_tc",
            "x_r7_severity": severity,
            "x_r7_ioc_type": ioc_type,
            "x_r7_tags": tags[:10],
            "x_target_sectors": sectors,  # canonical sector field
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
        return {"value": m.group(1) if m else stix_dict.get("name", "")}

    # ── InsightVM — Vulnerabilities ───────────────────────────────────────────

    def list_vulnerabilities(
        self,
        severity: str = "",
        cvss_min: float | None = None,
        exploitable: bool | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List InsightVM vulnerability definitions.

        Parameters
        ----------
        severity : str
            ``"Critical"``, ``"Severe"``, ``"Moderate"``.
        cvss_min : float
            Minimum CVSS v3 base score.
        exploitable : bool
            If True, only return vulnerabilities with known exploits.
        """
        params: dict[str, Any] = {"page": page - 1, "size": page_size}
        if severity:
            params["severity"] = severity
        if cvss_min is not None:
            params["cvssV3ScoreMin"] = cvss_min
        if exploitable is not None:
            params["exploitable"] = exploitable
        resp = self.get("/vm/v4/integration/vulnerabilities", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """Retrieve full details for a specific InsightVM vulnerability by ID."""
        resp = self.get(f"/vm/v4/integration/vulnerabilities/{vuln_id}")
        return resp if isinstance(resp, dict) else {}

    def get_vulnerability_solutions(self, vuln_id: str) -> list[dict[str, Any]]:
        """List remediation solutions for an InsightVM vulnerability."""
        resp = self.get(f"/vm/v4/integration/vulnerabilities/{vuln_id}/solutions")
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── InsightVM — Assets ────────────────────────────────────────────────────

    def list_assets(
        self, page: int = 1, page_size: int = 100
    ) -> list[dict[str, Any]]:
        """List discovered assets in InsightVM."""
        resp = self.get(
            "/vm/v4/integration/assets",
            params={"page": page - 1, "size": page_size},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        """Retrieve full details for a specific InsightVM asset."""
        resp = self.get(f"/vm/v4/integration/assets/{asset_id}")
        return resp if isinstance(resp, dict) else {}

    def get_asset_vulnerabilities(
        self, asset_id: str, page: int = 1, page_size: int = 100
    ) -> list[dict[str, Any]]:
        """List vulnerabilities found on a specific asset."""
        resp = self.get(
            f"/vm/v4/integration/assets/{asset_id}/vulnerabilities",
            params={"page": page - 1, "size": page_size},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_asset_services(self, asset_id: str) -> list[dict[str, Any]]:
        """List running services discovered on an asset."""
        resp = self.get(f"/vm/v4/integration/assets/{asset_id}/services")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def search_assets(
        self,
        query_filters: list[dict[str, Any]] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search assets using InsightVM filter criteria.

        ``query_filters`` example::

            [{"field": "ip-address", "operator": "in-range",
              "lower": "10.0.0.1", "upper": "10.0.0.254"}]
        """
        payload: dict[str, Any] = {
            "filters": query_filters or [],
            "match": "all",
        }
        resp = self.post(
            f"/vm/v4/integration/assets/search?page={page-1}&size={page_size}",
            json=payload,
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── InsightVM — Sites & Scans ─────────────────────────────────────────────

    def list_sites(self, page: int = 1, page_size: int = 100) -> list[dict[str, Any]]:
        """List scan sites configured in InsightVM."""
        resp = self.get(
            "/vm/v3/sites",
            params={"page": page - 1, "size": page_size},
        )
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_site(self, site_id: str) -> dict[str, Any]:
        """Retrieve full configuration for a specific scan site."""
        resp = self.get(f"/vm/v3/sites/{site_id}")
        return resp if isinstance(resp, dict) else {}

    def list_scans(
        self, site_id: str = "", page: int = 1, page_size: int = 25
    ) -> list[dict[str, Any]]:
        """List scan history, optionally scoped to a site."""
        if site_id:
            resp = self.get(
                f"/vm/v3/sites/{site_id}/scans",
                params={"page": page - 1, "size": page_size},
            )
        else:
            resp = self.get(
                "/vm/v3/scans",
                params={"page": page - 1, "size": page_size},
            )
        return resp.get("resources", []) if isinstance(resp, dict) else []

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        """Retrieve details and status for a specific scan."""
        resp = self.get(f"/vm/v3/scans/{scan_id}")
        return resp if isinstance(resp, dict) else {}

    def create_scan(self, site_id: str, hosts: list[str] | None = None) -> dict[str, Any]:
        """
        Trigger a new scan for a site.

        ``hosts`` — optional list of specific host IPs/names to scan within the site.
        """
        payload: dict[str, Any] = {}
        if hosts:
            payload["hosts"] = hosts
        resp = self.post(f"/vm/v3/sites/{site_id}/scans", json=payload)
        return resp if isinstance(resp, dict) else {}

    def get_remediation_report(
        self, asset_id: str, page: int = 1, page_size: int = 50
    ) -> list[dict[str, Any]]:
        """
        Retrieve prioritised remediation steps for an asset.

        Returns a list of solution objects ranked by risk reduction.
        """
        resp = self.get(
            f"/vm/v4/integration/assets/{asset_id}/vulnerabilities",
            params={"page": page - 1, "size": page_size, "sort": "riskScore,DESC"},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Threat Command — IOCs ─────────────────────────────────────────────────

    def lookup_ioc(self, value: str) -> dict[str, Any]:
        """
        Look up an IOC by value (IP, domain, URL, hash, email).

        Returns reputation, severity, and associated threat context.
        """
        resp = self.get("/public/v2/iocs/ioc-by-value", params={"iocValue": value})
        return resp if isinstance(resp, dict) else {}

    def list_iocs(
        self,
        ioc_type: str = "",
        severity: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List Threat Command IOCs with optional type/severity filters.

        ``ioc_type`` options: ``"IpAddresses"``, ``"Domains"``, ``"Urls"``,
        ``"Hashes"``, ``"Emails"``.
        ``severity`` options: ``"Critical"``, ``"High"``, ``"Medium"``, ``"Low"``.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if ioc_type:
            params["type"] = ioc_type
        if severity:
            params["severity"] = severity
        resp = self.get("/public/v2/iocs", params=params)
        return resp.get("content", []) if isinstance(resp, dict) else []

    def submit_ioc(
        self,
        value: str,
        ioc_type: str,
        severity: str = "Medium",
        tags: list[str] | None = None,
        comment: str = "",
    ) -> dict[str, Any]:
        """Submit a new IOC to Threat Command."""
        payload: dict[str, Any] = {
            "value": value,
            "type": ioc_type,
            "severity": severity,
        }
        if tags:
            payload["tags"] = tags
        if comment:
            payload["comment"] = comment
        return self.post("/public/v2/iocs", json=payload)

    # ── Threat Command — Threat actors ────────────────────────────────────────

    def list_threat_actors(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List Threat Command threat actor profiles."""
        resp = self.get(
            "/public/v2/threat-actors",
            params={"limit": limit, "offset": offset},
        )
        return resp.get("content", []) if isinstance(resp, dict) else []

    def get_threat_actor(self, actor_id: str) -> dict[str, Any]:
        """Retrieve a specific threat actor profile."""
        resp = self.get(f"/public/v2/threat-actors/{actor_id}")
        return resp if isinstance(resp, dict) else {}

    # ── Threat Command — CVE intelligence ────────────────────────────────────

    def list_cves(
        self,
        severity: str = "",
        exploitable: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List CVEs from Threat Command intelligence.

        ``severity`` options: ``"Critical"``, ``"High"``, ``"Medium"``, ``"Low"``.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if severity:
            params["severity"] = severity
        if exploitable is not None:
            params["inTheWild"] = exploitable
        resp = self.get("/public/v2/cves", params=params)
        return resp.get("content", []) if isinstance(resp, dict) else []

    def get_cve(self, cve_id: str) -> dict[str, Any]:
        """Retrieve Threat Command intelligence for a specific CVE."""
        resp = self.get(f"/public/v2/cves/{cve_id}")
        return resp if isinstance(resp, dict) else {}

    # ── Threat Command — Alerts (dark web / brand) ───────────────────────────

    def list_dark_web_alerts(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List dark web mention alerts from Threat Command."""
        resp = self.get(
            "/public/v2/data/alerts",
            params={"limit": limit, "offset": offset, "type": "darkWeb"},
        )
        return resp.get("content", []) if isinstance(resp, dict) else []

    def list_brand_alerts(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List brand protection alerts from Threat Command."""
        resp = self.get(
            "/public/v2/data/alerts",
            params={"limit": limit, "offset": offset, "type": "phishing"},
        )
        return resp.get("content", []) if isinstance(resp, dict) else []

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Retrieve a specific Threat Command alert by ID."""
        resp = self.get(f"/public/v2/data/alerts/{alert_id}")
        return resp if isinstance(resp, dict) else {}

    def update_alert_status(
        self, alert_id: str, status: str, comment: str = ""
    ) -> dict[str, Any]:
        """
        Update the status of a Threat Command alert.

        ``status`` options: ``"open"``, ``"closed"``, ``"accepted"``.
        """
        payload: dict[str, Any] = {"status": status}
        if comment:
            payload["comment"] = comment
        resp = self.patch(f"/public/v2/data/alerts/{alert_id}", json=payload)
        return resp if isinstance(resp, dict) else {}

    # ── Threat Command — Intelligence search ─────────────────────────────────

    def search_intelligence(
        self, query: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Free-text search across all Threat Command intelligence types."""
        resp = self.get(
            "/public/v2/search",
            params={"query": query, "limit": limit},
        )
        return resp.get("content", resp.get("results", [])) if isinstance(resp, dict) else []
