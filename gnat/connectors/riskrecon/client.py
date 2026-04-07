# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.riskrecon.client
=====================================

RiskRecon (Mastercard) Third-Party Risk Management connector.

Authentication
--------------
OAuth2 client-credentials flow::

    [riskrecon]
    host          = https://api.riskrecon.com
    client_id     = <client-id>
    client_secret = <client-secret>
    auth_type     = oauth2

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | RiskRecon Resource               |
+====================+==================================+
| threat-actor       | company (third party)            |
+--------------------+----------------------------------+
| vulnerability      | finding                          |
+--------------------+----------------------------------+
| observable         | asset (IP, domain, hostname)     |
+--------------------+----------------------------------+

Key Resources
-------------
* ``/companies``            — third-party companies monitored
* ``/companies/{id}/findings``  — security findings per company
* ``/companies/{id}/assets``    — discovered assets (IPs, domains)
* ``/companies/{id}/score``     — current risk score (0–10)
* ``/criteria``             — finding criteria definitions

The ``to_stix()`` method produces:

* A ``threat-actor`` for the company (third-party vendor)
* A ``vulnerability`` for each finding (severity, criterion, asset)

Severity mapping (RiskRecon → STIX ``x_severity``):
``critical``, ``high``, ``medium``, ``low``, ``info``
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class RiskReconClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the RiskRecon REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.riskrecon.com"``.
    client_id : str
        OAuth2 client ID.
    client_secret : str
        OAuth2 client secret.
    """

    stix_type_map: dict[str, str] = {
        "threat-actor": "companies",
        "vulnerability": "findings",
        "observable": "assets",
    }

    # RiskRecon severity → numeric confidence
    _SEVERITY_CONFIDENCE: dict[str, int] = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 40,
        "info": 20,
    }

    def __init__(
        self,
        host: str,
        client_id: str = "",
        client_secret: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Obtain an OAuth2 Bearer token via client-credentials flow.

        Raises
        ------
        GNATClientError
            If the token endpoint returns no ``access_token``.
        """
        resp = self.post(
            "/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise GNATClientError("RiskRecon: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping RiskRecon by listing one company."""
        self.get("/companies", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a RiskRecon object.

        For ``"threat-actor"`` returns the company profile.
        For ``"vulnerability"`` returns a specific finding.
        """
        rr_id = object_id.split("--", 1)[-1]
        if stix_type == "threat-actor":
            return self.get_company(rr_id)
        if stix_type == "vulnerability":
            # Findings are scoped to a company; return raw finding by id
            return self.get(f"/findings/{rr_id}")
        if stix_type == "observable":
            return self.get(f"/assets/{rr_id}")
        raise GNATClientError(f"RiskRecon: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List RiskRecon companies, findings, or assets.

        For findings and assets, pass ``{"company_id": "..."}`` in *filters*
        to scope results to a specific company.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            company_id = filters.pop("company_id", None)
            params.update(filters)
            if company_id:
                if stix_type == "vulnerability":
                    resp = self.get(f"/companies/{company_id}/findings", params=params)
                    return resp.get("findings", []) if isinstance(resp, dict) else []
                if stix_type == "observable":
                    resp = self.get(f"/companies/{company_id}/assets", params=params)
                    return resp.get("assets", []) if isinstance(resp, dict) else []

        if stix_type == "threat-actor":
            resp = self.get("/companies", params=params)
            return resp.get("companies", []) if isinstance(resp, dict) else []

        raise GNATClientError(
            f"RiskRecon: list_objects for '{stix_type}' requires filters={{'company_id': '...'}}"
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        RiskRecon is primarily a read / monitoring platform.

        Only company watchlist management (add/remove) is supported.
        """
        if stix_type == "threat-actor":
            domain = payload.get("domain", "")
            if not domain:
                raise GNATClientError(
                    "RiskRecon: 'domain' is required to add a company to monitoring."
                )
            return self.post("/companies", json={"domain": domain})
        raise GNATClientError(f"RiskRecon: create/update not supported for '{stix_type}'")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Remove a company from your RiskRecon monitoring list."""
        if stix_type == "threat-actor":
            self.delete(f"/companies/{object_id.split('--', 1)[-1]}")
            return
        raise GNATClientError(f"RiskRecon: delete not supported for '{stix_type}'")

    # ── Domain-specific operations ────────────────────────────────────────

    def get_company(self, company_id: str) -> dict[str, Any]:
        """
        Fetch a full company profile including current risk score.

        Returns
        -------
        dict
            Keys: ``id``, ``name``, ``domain``, ``score``,
            ``grade``, ``industries``, ``employee_count``.
        """
        return self.get(f"/companies/{company_id}")

    def get_score(self, company_id: str) -> dict[str, Any] | None:
        """
        Return the current risk score object for a company.

        Returns
        -------
        dict or None
            Keys: ``score`` (0–10), ``grade`` (A–F),
            ``score_date``, ``criteria_scores``.
        """
        resp = self.get(f"/companies/{company_id}/score")
        return resp if isinstance(resp, dict) else None

    def list_findings(
        self,
        company_id: str,
        severity: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List security findings for a company.

        Parameters
        ----------
        company_id : str
            RiskRecon company UUID.
        severity : str, optional
            Filter by severity: ``"critical"``, ``"high"``,
            ``"medium"``, ``"low"``, ``"info"``.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if severity:
            params["severity"] = severity
        resp = self.get(f"/companies/{company_id}/findings", params=params)
        return resp.get("findings", []) if isinstance(resp, dict) else []

    def list_assets(
        self,
        company_id: str,
        asset_type: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List discovered assets for a company.

        Parameters
        ----------
        company_id : str
            RiskRecon company UUID.
        asset_type : str, optional
            Filter by asset type: ``"ip"``, ``"domain"``, ``"hostname"``.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if asset_type:
            params["type"] = asset_type
        resp = self.get(f"/companies/{company_id}/assets", params=params)
        return resp.get("assets", []) if isinstance(resp, dict) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a RiskRecon object to STIX 2.1.

        Dispatches on the presence of ``score`` (company) vs ``criterion``
        (finding) vs ``ip`` / ``domain`` (asset).
        """
        data = native.get("data", native)

        # Company → threat-actor
        if "score" in data and "domain" in data:
            industries = data.get("industries", [])
            stix: dict[str, Any] = {
                "type": "threat-actor",
                "id": f"threat-actor--{data.get('id', '')}",
                "name": data.get("name", data.get("domain", "")),
                "description": f"Domain: {data.get('domain', '')}",
                "created": data.get("created_at", ""),
                "modified": data.get("updated_at", ""),
                "threat_actor_types": ["vendor"],
                "x_rr_score": data.get("score"),
                "x_rr_grade": data.get("grade", ""),
                "x_rr_domain": data.get("domain", ""),
                "x_rr_industries": industries,
            }
            if industries:
                stix["x_target_sectors"] = industries
            return stix

        # Finding → vulnerability
        if "criterion" in data or "finding_type" in data:
            severity = data.get("severity", "info")
            confidence = self._SEVERITY_CONFIDENCE.get(severity, 50)
            return {
                "type": "vulnerability",
                "id": f"vulnerability--{data.get('id', '')}",
                "name": data.get("criterion", data.get("finding_type", "")),
                "description": data.get("description", ""),
                "created": data.get("first_seen", ""),
                "modified": data.get("last_seen", ""),
                "confidence": confidence,
                "x_rr_severity": severity,
                "x_rr_asset": data.get("asset", ""),
                "x_rr_company_id": data.get("company_id", ""),
                "x_rr_criterion": data.get("criterion", ""),
                "x_rr_remediated": data.get("remediated", False),
            }

        # Asset → observable (fallback)
        asset_type = "ip" if data.get("ip") else "domain"
        value = data.get("ip", data.get("domain", data.get("hostname", "")))
        return {
            "type": "indicator" if value else "observed-data",
            "id": f"indicator--{data.get('id', '')}",
            "name": value,
            "pattern": (
                f"[ipv4-addr:value = '{value}']"
                if asset_type == "ip"
                else f"[domain-name:value = '{value}']"
            ),
            "pattern_type": "stix",
            "created": data.get("first_seen", ""),
            "modified": data.get("last_seen", ""),
            "x_rr_asset_type": asset_type,
            "x_rr_company_id": data.get("company_id", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Translate a STIX object to a RiskRecon company add payload."""
        return {
            "domain": stix_dict.get("x_rr_domain", stix_dict.get("name", "")),
        }

    # ── Company discovery & search ────────────────────────────────────────────

    def list_companies(
        self,
        name: str = "",
        domain: str = "",
        industry: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List monitored companies with optional filters.

        ``industry`` — sector filter, e.g. ``"Financial Services"``.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if name:
            params["name"] = name
        if domain:
            params["domain"] = domain
        if industry:
            params["industry"] = industry
        resp = self.get("/companies", params=params)
        return resp.get("companies", []) if isinstance(resp, dict) else []

    def search_companies(self, keyword: str, limit: int = 50) -> list[dict[str, Any]]:
        """Search for companies by name or domain keyword."""
        resp = self.get("/companies/search", params={"q": keyword, "limit": limit})
        return resp.get("companies", []) if isinstance(resp, dict) else []

    def get_company_by_domain(self, domain: str) -> dict[str, Any]:
        """Look up a company by primary domain name."""
        resp = self.get("/companies", params={"domain": domain, "limit": 1})
        companies = resp.get("companies", []) if isinstance(resp, dict) else []
        return companies[0] if companies else {}

    def add_company(self, domain: str, name: str = "") -> dict[str, Any]:
        """Add a company to your RiskRecon monitoring watchlist."""
        payload: dict[str, Any] = {"domain": domain}
        if name:
            payload["name"] = name
        return self.post("/companies", json=payload)

    def remove_company(self, company_id: str) -> None:
        """Remove a company from monitoring."""
        self.delete(f"/companies/{company_id}")

    # ── Scoring & trends ──────────────────────────────────────────────────────

    def get_score_history(
        self,
        company_id: str,
        days: int = 90,
    ) -> list[dict[str, Any]]:
        """
        Retrieve historical risk score data points for a company.

        ``days`` — look-back window (default 90 days).
        Returns a list of ``{"date": ..., "score": ..., "grade": ...}`` dicts.
        """
        resp = self.get(
            f"/companies/{company_id}/score/history",
            params={"days": days},
        )
        return resp.get("history", []) if isinstance(resp, dict) else []

    def get_portfolio_summary(self) -> dict[str, Any]:
        """
        Retrieve aggregate risk statistics across all monitored companies.

        Returns average score, grade distribution, and top finding criteria.
        """
        resp = self.get("/portfolio/summary")
        return resp if isinstance(resp, dict) else {}

    def list_industry_benchmarks(self) -> list[dict[str, Any]]:
        """List industry-level risk benchmark scores for comparison."""
        resp = self.get("/benchmarks/industries")
        return resp.get("benchmarks", []) if isinstance(resp, dict) else []

    # ── Findings (enhanced) ───────────────────────────────────────────────────

    def get_critical_findings(
        self, company_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Return only critical and high severity findings for a company."""
        results: list[dict[str, Any]] = []
        for sev in ("critical", "high"):
            results.extend(
                self.list_findings(company_id, severity=sev, page_size=limit)
            )
        return results

    def list_remediated_findings(
        self, company_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List findings that have been remediated / closed."""
        resp = self.get(
            f"/companies/{company_id}/findings",
            params={"status": "remediated", "limit": limit},
        )
        return resp.get("findings", []) if isinstance(resp, dict) else []

    def get_finding_detail(self, finding_id: str) -> dict[str, Any]:
        """Retrieve full detail for a specific finding including evidence."""
        resp = self.get(f"/findings/{finding_id}")
        return resp if isinstance(resp, dict) else {}

    def list_asset_findings(
        self, asset_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List all findings associated with a specific asset."""
        resp = self.get(
            f"/assets/{asset_id}/findings",
            params={"limit": limit},
        )
        return resp.get("findings", []) if isinstance(resp, dict) else []

    # ── Finding criteria ──────────────────────────────────────────────────────

    def list_criteria(self) -> list[dict[str, Any]]:
        """
        List all RiskRecon finding criteria definitions.

        Each criterion has an ``id``, ``name``, ``description``,
        ``category``, and ``severity`` range.
        """
        resp = self.get("/criteria")
        return resp.get("criteria", []) if isinstance(resp, dict) else []

    def get_criterion(self, criterion_id: str) -> dict[str, Any]:
        """Retrieve the definition and remediation guidance for a specific criterion."""
        resp = self.get(f"/criteria/{criterion_id}")
        return resp if isinstance(resp, dict) else {}

    # ── Assets (enhanced) ─────────────────────────────────────────────────────

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        """Retrieve full details for a specific discovered asset."""
        resp = self.get(f"/assets/{asset_id}")
        return resp if isinstance(resp, dict) else {}

    def list_open_ports(
        self, company_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List open ports detected across a company's internet-facing assets."""
        resp = self.get(
            f"/companies/{company_id}/assets",
            params={"has_open_ports": True, "limit": limit},
        )
        return resp.get("assets", []) if isinstance(resp, dict) else []

    # ── Action plans / remediation ────────────────────────────────────────────

    def list_action_plans(self, company_id: str) -> list[dict[str, Any]]:
        """List remediation action plans for a company."""
        resp = self.get(f"/companies/{company_id}/action-plans")
        return resp.get("action_plans", []) if isinstance(resp, dict) else []

    def create_action_plan(
        self,
        company_id: str,
        finding_ids: list[str],
        due_date: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        """
        Create a remediation action plan for a set of findings.

        ``due_date`` — ISO 8601 date for remediation deadline.
        """
        payload: dict[str, Any] = {"findings": finding_ids}
        if due_date:
            payload["due_date"] = due_date
        if notes:
            payload["notes"] = notes
        return self.post(f"/companies/{company_id}/action-plans", json=payload)

    def update_action_plan(
        self,
        company_id: str,
        plan_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an action plan (due date, status, notes)."""
        resp = self.patch(
            f"/companies/{company_id}/action-plans/{plan_id}",
            json=updates,
        )
        return resp if isinstance(resp, dict) else {}

    # ── Contacts ──────────────────────────────────────────────────────────────

    def list_company_contacts(self, company_id: str) -> list[dict[str, Any]]:
        """List security contacts on file for a monitored company."""
        resp = self.get(f"/companies/{company_id}/contacts")
        return resp.get("contacts", []) if isinstance(resp, dict) else []
