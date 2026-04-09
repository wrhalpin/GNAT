# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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

from typing import Any, Optional

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

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "vulnerability": "vulnerabilities",
        "indicator": "threat-intel",
        "asset": "assets",
    }

    def __init__(
        self,
        host: str = "https://api.nucleussec.com",
        api_key: str = "",
        project: str = "",
        **kwargs: Any,
    ):
        """Initialize NucleusClient."""
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._project = project

    def authenticate(self) -> None:
        """Authenticate with the remote API and populate auth headers."""
        self._auth_headers["x-apikey"] = self._api_key

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        resp = self.get("/v2/projects")
        return isinstance(resp, (dict, list))

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        project = self._project
        if stix_type == "vulnerability":
            resp = self.get(f"/v2/projects/{project}/vulnerabilities/{object_id}")
            return resp if isinstance(resp, dict) else {}
        if stix_type == "asset":
            resp = self.get(f"/v2/projects/{project}/assets/{object_id}")
            return resp if isinstance(resp, dict) else {}
        return {}

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
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
        project = (filters or {}).get("project", self._project)
        params: dict[str, Any] = {
            "page": page - 1,
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

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Push external threat intel into Nucleus (indicators only).

        Nucleus can ingest external IOCs to enrich vulnerability context —
        e.g. pushing a ThreatQ indicator that a CVE is being actively
        exploited by a known actor.
        """
        if stix_type != "indicator":
            raise GNATClientError(f"Nucleus upsert only supports 'indicator', not {stix_type!r}")
        project = self._project
        resp = self.post(
            f"/v2/projects/{project}/threat-intel",
            json=self.from_stix(payload),
        )
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        if stix_type == "indicator":
            project = self._project
            self.delete(f"/v2/projects/{project}/threat-intel/{object_id}")
        else:
            raise GNATClientError(f"Nucleus delete only supports 'indicator', not {stix_type!r}")

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a Nucleus vulnerability record to a STIX Vulnerability.

        Nucleus records include rich context: EPSS score, CISA KEV status,
        exploit availability, CVSS v3, affected assets count, and
        asset industry classifications.
        """
        vuln_id = native.get("id", "")
        cve_id = native.get("cve_id", "")
        severity = native.get("severity", "")
        status = native.get("status", "")

        cvss_v3 = native.get("cvss_v3_base_score")
        cvss_v2 = native.get("cvss_v2_base_score")
        cvss = cvss_v3 or cvss_v2

        epss = native.get("epss_score")  # 0.0–1.0
        kev = native.get("cisa_kev", False)  # CISA Known Exploited
        has_exploit = native.get("exploit_available", False)
        exploited = kev or has_exploit

        # Industry/sector from asset tags
        industries = native.get("industries", []) or []
        asset_tags = native.get("asset_tags", []) or []
        sectors = list(
            set(industries + [t for t in asset_tags if not t.startswith(("env:", "team:", "app:"))])
        )

        # Confidence: KEV = 90, exploitable = 75, otherwise by severity
        if kev:
            confidence = 90
        elif has_exploit:
            confidence = 80
        else:
            confidence = {"critical": 75, "high": 65, "medium": 50, "low": 35}.get(
                severity.lower(), 50
            )

        return {
            "type": "vulnerability",
            "id": f"vulnerability--ns-{vuln_id}",
            "name": cve_id or vuln_id,
            "description": native.get("description", "")[:500],
            "created": native.get("first_found", ""),
            "modified": native.get("last_updated", ""),
            "confidence": confidence,
            "x_cve_id": cve_id,
            "x_cvss_score": cvss,
            "x_severity": severity,
            "x_actively_exploited": exploited,
            "x_nucleus_kev": kev,
            "x_nucleus_epss": epss,
            "x_nucleus_status": status,
            "x_nucleus_affected_assets": native.get("affected_assets_count", 0),
            "x_source_platform": "nucleus",
            "x_target_sectors": sectors,  # canonical sector field
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX Indicator to a Nucleus threat intel payload."""
        import re

        pattern = stix_dict.get("pattern", "")
        m = re.search(r"= '([^']+)'", pattern)
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
            "value": ioc_value,
            "type": ioc_type,
            "confidence": stix_dict.get("confidence", 50),
            "source": stix_dict.get("x_source_platform", "gnat"),
            "tags": stix_dict.get("x_source_topic", ""),
        }

    # ── Projects ──────────────────────────────────────────────────────────────

    def list_projects(self) -> list[dict[str, Any]]:
        """List all Nucleus projects accessible with the current API key."""
        resp = self.get("/v2/projects")
        return resp if isinstance(resp, list) else (resp.get("projects", []) if isinstance(resp, dict) else [])

    def get_project(self, project_id: str) -> dict[str, Any]:
        """Retrieve metadata for a specific Nucleus project."""
        resp = self.get(f"/v2/projects/{project_id}")
        return resp if isinstance(resp, dict) else {}

    # ── Vulnerabilities (typed) ───────────────────────────────────────────────

    def list_vulnerabilities(
        self,
        severity: str = "",
        status: str = "",
        cve_id: str = "",
        kev: bool = False,
        epss_min: float | None = None,
        asset_id: str = "",
        page: int = 1,
        page_size: int = 100,
        project: str = "",
    ) -> list[dict[str, Any]]:
        """
        List vulnerabilities with typed filters.

        Parameters
        ----------
        severity : str
            ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
        status : str
            ``"open"``, ``"closed"``, ``"accepted"``.
        kev : bool
            If True, return only CISA KEV vulnerabilities.
        epss_min : float
            Minimum EPSS probability score (0.0–1.0).
        asset_id : str
            Scope to a specific asset.
        """
        proj = project or self._project
        params: dict[str, Any] = {"page": page - 1, "page_size": page_size}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if cve_id:
            params["cve"] = cve_id
        if kev:
            params["kev"] = True
        if epss_min is not None:
            params["epss_min"] = epss_min
        if asset_id:
            params["asset_id"] = asset_id
        resp = self.get(f"/v2/projects/{proj}/vulnerabilities", params=params)
        data = resp.get("vulnerabilities", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    def get_vulnerability(
        self, vuln_id: str, project: str = ""
    ) -> dict[str, Any]:
        """Retrieve full details for a specific vulnerability finding."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/vulnerabilities/{vuln_id}")
        return resp if isinstance(resp, dict) else {}

    def get_vulnerability_assets(
        self, vuln_id: str, project: str = ""
    ) -> list[dict[str, Any]]:
        """List assets affected by a specific vulnerability."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/vulnerabilities/{vuln_id}/assets")
        data = resp.get("assets", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    def accept_risk(
        self,
        vuln_id: str,
        reason: str,
        expiry_date: str = "",
        project: str = "",
    ) -> dict[str, Any]:
        """
        Accept / waive a vulnerability finding.

        ``reason`` — justification for the risk acceptance.
        ``expiry_date`` — ISO 8601 date when the exception expires (optional).
        """
        proj = project or self._project
        payload: dict[str, Any] = {"status": "accepted", "reason": reason}
        if expiry_date:
            payload["expiry_date"] = expiry_date
        resp = self.patch(
            f"/v2/projects/{proj}/vulnerabilities/{vuln_id}",
            json=payload,
        )
        return resp if isinstance(resp, dict) else {}

    def reopen_vulnerability(
        self, vuln_id: str, project: str = ""
    ) -> dict[str, Any]:
        """Reopen a closed or accepted vulnerability."""
        proj = project or self._project
        resp = self.patch(
            f"/v2/projects/{proj}/vulnerabilities/{vuln_id}",
            json={"status": "open"},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Assets (typed) ────────────────────────────────────────────────────────

    def list_assets(
        self,
        industry: str = "",
        tag: str = "",
        page: int = 1,
        page_size: int = 100,
        project: str = "",
    ) -> list[dict[str, Any]]:
        """List assets in a Nucleus project with optional filters."""
        proj = project or self._project
        params: dict[str, Any] = {"page": page - 1, "page_size": page_size}
        if industry:
            params["industry"] = industry
        if tag:
            params["tag"] = tag
        resp = self.get(f"/v2/projects/{proj}/assets", params=params)
        data = resp.get("assets", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    def get_asset(self, asset_id: str, project: str = "") -> dict[str, Any]:
        """Retrieve full details for a specific asset."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/assets/{asset_id}")
        return resp if isinstance(resp, dict) else {}

    def list_asset_vulnerabilities(
        self,
        asset_id: str,
        severity: str = "",
        status: str = "",
        limit: int = 100,
        project: str = "",
    ) -> list[dict[str, Any]]:
        """List vulnerabilities for a specific asset."""
        proj = project or self._project
        params: dict[str, Any] = {"page_size": limit, "page": 0}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        resp = self.get(
            f"/v2/projects/{proj}/assets/{asset_id}/vulnerabilities",
            params=params,
        )
        data = resp.get("vulnerabilities", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    # ── Statistics & reporting ─────────────────────────────────────────────────

    def get_statistics(self, project: str = "") -> dict[str, Any]:
        """
        Retrieve vulnerability statistics dashboard for a project.

        Returns counts by severity, status, exploitability, KEV, and EPSS bands.
        """
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/statistics")
        return resp if isinstance(resp, dict) else {}

    def get_sla_violations(
        self, project: str = "", limit: int = 100
    ) -> list[dict[str, Any]]:
        """List vulnerabilities currently in breach of SLA remediation policies."""
        proj = project or self._project
        resp = self.get(
            f"/v2/projects/{proj}/vulnerabilities",
            params={"sla_violated": True, "page_size": limit, "page": 0},
        )
        data = resp.get("vulnerabilities", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    # ── Tags ──────────────────────────────────────────────────────────────────

    def list_tags(self, project: str = "") -> list[dict[str, Any]]:
        """List all asset tags defined in a Nucleus project."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/tags")
        data = resp.get("tags", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    def create_tag(
        self,
        tag_name: str,
        color: str = "#6366f1",
        project: str = "",
    ) -> dict[str, Any]:
        """Create a new asset classification tag."""
        proj = project or self._project
        resp = self.post(
            f"/v2/projects/{proj}/tags",
            json={"name": tag_name, "color": color},
        )
        return resp if isinstance(resp, dict) else {}

    def assign_tag_to_asset(
        self,
        asset_id: str,
        tag_id: str,
        project: str = "",
    ) -> dict[str, Any]:
        """Assign a tag to an asset."""
        proj = project or self._project
        resp = self.post(
            f"/v2/projects/{proj}/assets/{asset_id}/tags",
            json={"tag_id": tag_id},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Connectors / sources ──────────────────────────────────────────────────

    def list_connectors(self, project: str = "") -> list[dict[str, Any]]:
        """List scanner/source connectors configured for a project."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/connectors")
        data = resp.get("connectors", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []

    def get_connector_status(
        self, connector_id: str, project: str = ""
    ) -> dict[str, Any]:
        """Retrieve the last sync status for a specific connector."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/connectors/{connector_id}")
        return resp if isinstance(resp, dict) else {}

    def trigger_connector_sync(
        self, connector_id: str, project: str = ""
    ) -> dict[str, Any]:
        """Force an immediate re-import from a connector source."""
        proj = project or self._project
        resp = self.post(f"/v2/projects/{proj}/connectors/{connector_id}/sync")
        return resp if isinstance(resp, dict) else {}

    # ── SLA policies ──────────────────────────────────────────────────────────

    def list_sla_policies(self, project: str = "") -> list[dict[str, Any]]:
        """List SLA remediation policies defined for a project."""
        proj = project or self._project
        resp = self.get(f"/v2/projects/{proj}/sla-policies")
        data = resp.get("policies", resp) if isinstance(resp, dict) else resp
        return data if isinstance(data, list) else []
