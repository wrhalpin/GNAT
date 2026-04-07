# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.wazuh.vulnerabilities

Vulnerability detection commands for the Wazuh connector.

Wazuh's Vulnerability Detection module scans agents for packages
with known CVEs using the National Vulnerability Database (NVD)
and vendor advisories.

## Vulnerability fields of interest

cve, name (package), version, architecture, severity,
cvss2_score, cvss3_score, detection_time, package.condition,
references, title

## CVSS severity mapping -> GNAT

critical (9.0-10.0) -> 4
high     (7.0-8.9)  -> 3
medium   (4.0-6.9)  -> 2
low      (0.1-3.9)  -> 1
none     (0.0)      -> 0

These map to STIX 2.1 vulnerability SDOs.

## References

- https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Vulnerability
"""

from .client import WazuhClient

_CVSS_SEVERITY_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
    "unknown": 0,
}


class WazuhVulnerabilityCommands:
    """
    Vulnerability detection operations.

    Parameters
    ----------
    client : WazuhClient
        Authenticated HTTP client.
    """

    def __init__(self, client: WazuhClient) -> None:
        self._client = client

    def get_vulnerabilities(
        self,
        agent_id: str,
        severity: str | None = None,
        cve: str | None = None,
        package_name: str | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[dict]:
        """
        Query detected vulnerabilities for an agent.

        Parameters
        ----------
        agent_id : str
            Wazuh agent ID.
        severity : str | None
            Filter by CVSS severity: 'critical', 'high', 'medium', 'low', 'none'.
        cve : str | None
            Filter by CVE ID (e.g. 'CVE-2021-44228').
        package_name : str | None
            Filter by vulnerable package name.
        limit : int | None
            Max results.
        sort : str | None
            Sort expression, e.g. '-cvss3_score'.

        Returns
        -------
        list[dict]
            Vulnerability records.
        """
        params: dict = {"limit": min(limit or self._client.config.max_results, 500)}
        if severity:
            params["severity"] = severity
        if cve:
            params["cve"] = cve
        if package_name:
            params["name"] = package_name
        if sort:
            params["sort"] = sort

        response = self._client.get(f"vulnerability/{agent_id}", params=params)
        return self._client.extract_items(response)

    def iter_all_vulnerabilities(
        self,
        agent_id: str,
        severity: str | None = None,
    ):
        """
        Generator yielding all vulnerabilities for an agent.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        severity : str | None
            Optional severity filter.

        Yields
        ------
        dict
            Vulnerability record.
        """
        params: dict = {}
        if severity:
            params["severity"] = severity
        yield from self._client.paginate(f"vulnerability/{agent_id}", params=params)

    def get_vulnerability_summary(self, agent_id: str) -> dict:
        """
        Return vulnerability counts grouped by severity for an agent.

        Parameters
        ----------
        agent_id : str
            Agent ID.

        Returns
        -------
        dict
            Counts keyed by severity string.
        """
        params = {"limit": 500, "select": "severity"}
        response = self._client.get(f"vulnerability/{agent_id}", params=params)
        items = self._client.extract_items(response)
        summary: dict[str, int] = dict.fromkeys(_CVSS_SEVERITY_MAP, 0)
        for item in items:
            sev = (item.get("severity") or "unknown").lower()
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def run_vulnerability_scan(self, agent_id: str) -> dict:
        """
        Trigger a vulnerability scan on a specific agent.

        Parameters
        ----------
        agent_id : str
            Agent ID.

        Returns
        -------
        dict
            API response.
        """
        return self._client.put(f"vulnerability/{agent_id}/run_scan")

    @staticmethod
    def normalise_vulnerability(vuln: dict) -> dict:
        """Flatten a Wazuh vulnerability record for GNAT."""
        sev_str = (vuln.get("severity") or "unknown").lower()
        return {
            "cve": vuln.get("cve"),
            "package_name": vuln.get("name"),
            "package_version": vuln.get("version"),
            "architecture": vuln.get("architecture"),
            "severity": _CVSS_SEVERITY_MAP.get(sev_str, 0),
            "severity_label": sev_str,
            "cvss2_score": vuln.get("cvss2_score"),
            "cvss3_score": vuln.get("cvss3_score"),
            "title": vuln.get("title"),
            "detection_time": vuln.get("detection_time"),
            "references": vuln.get("references", []),
            "condition": vuln.get("package", {}).get("condition"),
            "_raw": vuln,
        }
