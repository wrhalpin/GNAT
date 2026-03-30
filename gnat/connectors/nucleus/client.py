"""
gnat.connectors.nucleus.client
====================================

Nucleus Security connector — unified vulnerability intelligence and
risk management platform.

Nucleus aggregates scan data from multiple vulnerability scanners
(Tenable, Qualys, Rapid7, etc.) and enriches with threat intel context,
EPSS scores, KEV status, and business criticality.

INI config::

    [nucleus]
    host     = https://api.nucleussec.com
    api_key  = <nucleus-api-key>
    project  = <project-id>           # optional default project
    auth_type = token

Supported operations
--------------------
- ``list_objects(vulnerability)``  — vulnerabilities with risk context
- ``list_objects(asset)``          — asset inventory with vuln counts
- ``get_object(vulnerability, id)``— single vulnerability with full detail
- ``upsert_object(indicator)``     — push external threat intel into Nucleus

References
----------
https://docs.nucleussec.com/api/
"""

from typing import Any, Dict, List, Optional
from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class NucleusClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Nucleus Security API.

    Parameters
    ----------
    host : str
        Nucleus API base URL.
    api_key : str
        Nucleus API key.
    project : str, optional
        Default project id.  Can be overridden per request via ``filters``.
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "vulnerabilities",
        "indicator":     "threat-intel",
        "asset":         "assets",
    }

    def __init__(self, host: str = "https://api.nucleussec.com",
                 api_key: str = "", project: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._project = project

    def authenticate(self) -> None:
        self._auth_headers["x-apikey"] = self._api_key

    def health_check(self) -> bool:
        resp = self.get("/v2/projects")
        return isinstance(resp, (dict, list))

    def get_object(self, stix_type: str,
                   object_id: str) -> Dict[str, Any]:
        project = self._project
        if stix_type == "vulnerability":
            resp = self.get(
                f"/v2/projects/{project}/vulnerabilities/{object_id}"
            )
            return resp if isinstance(resp, dict) else {}
        if stix_type == "asset":
            resp = self.get(f"/v2/projects/{project}/assets/{object_id}")
            return resp if isinstance(resp, dict) else {}
        return {}

    def list_objects(self, stix_type: str,
                     filters: Optional[Dict[str, Any]] = None,
                     page: int = 1,
                     page_size: int = 100) -> List[Dict[str, Any]]:
        """
        List vulnerabilities or assets from Nucleus.

        ``filters`` supports:
        - ``project`` (str): override the default project id
        - ``severity`` (str): ``"critical"``, ``"high"``, ``"medium"``, ``"low"``
        - ``status`` (str): ``"open"``, ``"closed"``, ``"accepted"``
        - ``kev`` (bool): True = only CISA KEV vulnerabilities
        - ``epss_min`` (float): minimum EPSS probability score (0.0–1.0)
        - ``asset_id`` (str): filter vulns for a specific asset
        - ``cve`` (str): filter by CVE ID
        - ``industry`` (str): filter by asset industry classification
        """
        project  = (filters or {}).get("project", self._project)
        params: Dict[str, Any] = {
            "page":      page - 1,
            "page_size": page_size,
        }

        if stix_type == "vulnerability":
            for key in ("severity", "status", "asset_id", "cve"):
                if filters and filters.get(key):
                    params[key] = filters[key]
            if filters and filters.get("kev"):
                params["kev"] = True
            if filters and filters.get("epss_min") is not None:
                params["epss_min"] = filters["epss_min"]
            resp = self.get(
                f"/v2/projects/{project}/vulnerabilities",
                params=params,
            )
            data = resp.get("vulnerabilities", resp) if isinstance(resp, dict) else resp
            return data if isinstance(data, list) else []

        if stix_type == "asset":
            if filters and filters.get("industry"):
                params["industry"] = filters["industry"]
            resp = self.get(
                f"/v2/projects/{project}/assets",
                params=params,
            )
            data = resp.get("assets", resp) if isinstance(resp, dict) else resp
            return data if isinstance(data, list) else []

        return []

    def upsert_object(self, stix_type: str,
                      payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Push external threat intel into Nucleus (indicators only).

        Nucleus can ingest external IOCs to enrich vulnerability context —
        e.g. pushing a ThreatQ indicator that a CVE is being actively
        exploited by a known actor.
        """
        if stix_type != "indicator":
            raise GNATClientError(
                f"Nucleus upsert only supports 'indicator', not {stix_type!r}"
            )
        project = self._project
        resp = self.post(
            f"/v2/projects/{project}/threat-intel",
            json=self.from_stix(payload),
        )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        if stix_type == "indicator":
            project = self._project
            self.delete(f"/v2/projects/{project}/threat-intel/{object_id}")
        else:
            raise GNATClientError(
                f"Nucleus delete only supports 'indicator', not {stix_type!r}"
            )

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Nucleus vulnerability record to a STIX Vulnerability.

        Nucleus records include rich context: EPSS score, CISA KEV status,
        exploit availability, CVSS v3, affected assets count, and
        asset industry classifications.
        """
        vuln_id   = native.get("id", "")
        cve_id    = native.get("cve_id", "")
        severity  = native.get("severity", "")
        status    = native.get("status", "")

        cvss_v3   = native.get("cvss_v3_base_score")
        cvss_v2   = native.get("cvss_v2_base_score")
        cvss      = cvss_v3 or cvss_v2

        epss      = native.get("epss_score")         # 0.0–1.0
        kev       = native.get("cisa_kev", False)    # CISA Known Exploited
        has_exploit = native.get("exploit_available", False)
        exploited = kev or has_exploit

        # Industry/sector from asset tags
        industries = native.get("industries", []) or []
        asset_tags = native.get("asset_tags", []) or []
        sectors    = list(set(industries + [
            t for t in asset_tags
            if not t.startswith(("env:", "team:", "app:"))
        ]))

        # Confidence: KEV = 90, exploitable = 75, otherwise by severity
        if kev:
            confidence = 90
        elif has_exploit:
            confidence = 80
        else:
            confidence = {"critical": 75, "high": 65,
                          "medium": 50, "low": 35}.get(severity.lower(), 50)

        return {
            "type":              "vulnerability",
            "id":                f"vulnerability--ns-{vuln_id}",
            "name":              cve_id or vuln_id,
            "description":       native.get("description", "")[:500],
            "created":           native.get("first_found", ""),
            "modified":          native.get("last_updated", ""),
            "confidence":        confidence,
            "x_cve_id":          cve_id,
            "x_cvss_score":      cvss,
            "x_severity":        severity,
            "x_actively_exploited": exploited,
            "x_nucleus_kev":     kev,
            "x_nucleus_epss":    epss,
            "x_nucleus_status":  status,
            "x_nucleus_affected_assets": native.get("affected_assets_count", 0),
            "x_source_platform": "nucleus",
            "x_target_sectors":  sectors,  # canonical sector field
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a STIX Indicator to a Nucleus threat intel payload."""
        import re
        pattern   = stix_dict.get("pattern", "")
        m         = re.search(r"= '([^']+)'", pattern)
        ioc_value = m.group(1) if m else stix_dict.get("name", "")

        # Infer IOC type from pattern
        if "ipv4-addr" in pattern:
            ioc_type = "ip"
        elif "domain-name" in pattern:
            ioc_type = "domain"
        elif "url:" in pattern:
            ioc_type = "url"
        elif "SHA-256" in pattern:
            ioc_type = "hash"
        else:
            ioc_type = "domain"

        return {
            "value":      ioc_value,
            "type":       ioc_type,
            "confidence": stix_dict.get("confidence", 50),
            "source":     stix_dict.get("x_source_platform", "gnat"),
            "tags":       stix_dict.get("x_source_topic", ""),
        }
