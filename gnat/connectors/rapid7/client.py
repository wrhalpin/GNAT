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
