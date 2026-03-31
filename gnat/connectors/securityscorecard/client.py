"""
gnat.connectors.securityscorecard.client
=========================================

SecurityScorecard connector.

SecurityScorecard provides continuous security ratings for companies
based on externally observable risk factors across 10 security factors
including DNS health, IP reputation, web application security, network
security, patching cadence, endpoint security, cubit score, hacker
forums, leaked information, and social engineering.

Authentication
--------------
API token via ``Token`` header::

    [securityscorecard]
    host    = https://api.securityscorecard.io
    api_key = <your-ssc-api-key>

Generate the key in the SSC portal under Account Settings → API.

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | SSC Resource                                 |
+================+==============================================+
| report         | Company scores / scorecards                  |
+----------------+----------------------------------------------+
| vulnerability  | Findings / Issue details                     |
+----------------+----------------------------------------------+
| identity       | Company portfolio entries                    |
+----------------+----------------------------------------------+

Key Endpoints
-------------
* /companies/{domain}/score        — Current scorecard for a domain
* /companies/{domain}/factors      — Factor breakdown
* /companies/{domain}/issues       — Issue details (findings)
* /portfolios                      — Portfolio list
* /portfolios/{id}/companies       — Companies in a portfolio
* /industries/{industry}/score     — Industry benchmarks

References
----------
https://securityscorecard.readme.io/reference
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e5f6a7b8-c9d0-1234-ef01-345678901234")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SecurityScorecardClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the SecurityScorecard API.

    Parameters
    ----------
    host : str
        Base URL (default ``https://api.securityscorecard.io``).
    api_key : str
        SecurityScorecard API token.
    """

    stix_type_map: dict[str, str] = {
        "report":        "companies",
        "vulnerability": "issues",
        "identity":      "portfolios",
    }

    def __init__(
        self,
        host: str = "https://api.securityscorecard.io",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Token header."""
        self._auth_headers["Token"] = self._api_key
        self._auth_headers["Content-Type"] = "application/json"
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping the portfolios endpoint."""
        self.get("/portfolios")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single SSC object by type and identifier.

        For ``report`` and ``vulnerability``, *object_id* is a domain name.
        For ``identity``, *object_id* is a portfolio ID.
        """
        if stix_type == "report":
            return self.get(f"/companies/{object_id}/score")
        if stix_type == "vulnerability":
            resp = self.get(f"/companies/{object_id}/issues")
            return resp if isinstance(resp, dict) else {}
        if stix_type == "identity":
            return self.get(f"/portfolios/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for SecurityScorecard: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List SSC objects by STIX type."""
        f = filters or {}
        if stix_type == "identity":
            resp = self.get("/portfolios")
            if not isinstance(resp, dict):
                return []
            return resp.get("entries", [])

        if stix_type == "report":
            portfolio_id = f.get("portfolio_id", "")
            if not portfolio_id:
                raise GNATClientError(
                    "SSC list_objects for 'report' requires "
                    "filters={'portfolio_id': '<id>'}"
                )
            params: dict[str, Any] = {"page": page, "size": page_size}
            resp = self.get(f"/portfolios/{portfolio_id}/companies", params=params)
            return resp.get("entries", []) if isinstance(resp, dict) else []

        if stix_type == "vulnerability":
            domain = f.get("domain", "")
            if not domain:
                raise GNATClientError(
                    "SSC list_objects for 'vulnerability' requires "
                    "filters={'domain': '<domain>'}"
                )
            factor = f.get("factor", "")
            params_v: dict[str, Any] = {"page": page, "page_size": page_size}
            if factor:
                params_v["factor"] = factor
            resp = self.get(f"/companies/{domain}/issues", params=params_v)
            return resp.get("entries", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"Unsupported STIX type for SecurityScorecard: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError(
            "SecurityScorecard API is read-only — upsert not supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError(
            "SecurityScorecard API is read-only — delete not supported."
        )

    # ── Platform-specific helpers ──────────────────────────────────────────

    def get_company_score(self, domain: str) -> dict[str, Any]:
        """Fetch the current scorecard for a domain."""
        return self.get(f"/companies/{domain}/score")

    def get_company_factors(self, domain: str) -> list[dict[str, Any]]:
        """Fetch factor breakdown for a domain."""
        resp = self.get(f"/companies/{domain}/factors")
        return resp.get("entries", []) if isinstance(resp, dict) else []

    def get_company_issues(
        self, domain: str, factor: str | None = None, severity: str | None = None
    ) -> list[dict[str, Any]]:
        """Fetch issues/findings for a domain."""
        params: dict[str, Any] = {}
        if factor:
            params["factor"] = factor
        if severity:
            params["severity"] = severity
        resp = self.get(f"/companies/{domain}/issues", params=params)
        return resp.get("entries", []) if isinstance(resp, dict) else []

    def get_industry_average(self, industry: str) -> dict[str, Any]:
        """Fetch the average score for an industry vertical."""
        return self.get(f"/industries/{industry}/score")

    def get_portfolio_companies(
        self, portfolio_id: str, page: int = 1, page_size: int = 100
    ) -> list[dict[str, Any]]:
        """Fetch all companies in a portfolio."""
        params: dict[str, Any] = {"page": page, "size": page_size}
        resp = self.get(f"/portfolios/{portfolio_id}/companies", params=params)
        return resp.get("entries", []) if isinstance(resp, dict) else []

    def get_historical_scores(
        self, domain: str, date_from: str | None = None, date_to: str | None = None
    ) -> list[dict[str, Any]]:
        """Fetch historical score data for a domain."""
        params: dict[str, Any] = {}
        if date_from:
            params["from"] = date_from
        if date_to:
            params["to"] = date_to
        resp = self.get(f"/companies/{domain}/history/scores", params=params)
        return resp.get("entries", []) if isinstance(resp, dict) else []

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a SSC object to STIX."""
        if "domain" in native and "score" in native:
            return self._score_to_stix(native)
        if "type" in native and "severity" in native:
            return self._issue_to_stix(native)
        if "id" in native and "name" in native:
            return self._portfolio_to_stix(native)
        # Default to score report
        return self._score_to_stix(native)

    def _score_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        domain = native.get("domain", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"ssc-score-{domain}"))
        score = native.get("score", 0)
        return {
            "type": "report",
            "id": f"report--{uid}",
            "name": f"SecurityScorecard: {domain}",
            "description": f"Security score for {domain}: {score}/100",
            "created": native.get("last_scorecard_change", _now_ts()),
            "modified": native.get("last_scorecard_change", _now_ts()),
            "published": native.get("last_scorecard_change", _now_ts()),
            "object_refs": [],
            "x_source_platform": "securityscorecard",
            "x_securityscorecard": {
                "domain": domain,
                "score": score,
                "grade": native.get("grade", ""),
                "grade_url": native.get("grade_url", ""),
                "industry": native.get("industry", ""),
                "size": native.get("size", ""),
            },
            # Canonical GNAT sector field — populated from SSC industry tag
            "x_target_sectors": [native.get("industry", "")] if native.get("industry") else [],
        }

    def _issue_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        issue_id = native.get("id", "")
        issue_type = native.get("type", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"ssc-issue-{issue_id or issue_type}"))
        severity_map = {"high": 80, "medium": 50, "low": 25, "info": 10}
        sev = native.get("severity", "info").lower()
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": issue_type,
            "description": native.get("detail", "")[:500],
            "created": native.get("first_seen_time", _now_ts()),
            "modified": native.get("last_seen_time", _now_ts()),
            "x_source_platform": "securityscorecard",
            "x_securityscorecard": {
                "issue_type": issue_type,
                "factor": native.get("factor", ""),
                "severity": sev,
                "confidence": severity_map.get(sev, 10),
                "count": native.get("count", 1),
            },
        }

    def _portfolio_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        portfolio_id = native.get("id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"ssc-portfolio-{portfolio_id}"))
        return {
            "type": "identity",
            "id": f"identity--{uid}",
            "name": native.get("name", portfolio_id),
            "identity_class": "organization",
            "created": native.get("created_at", _now_ts()),
            "modified": native.get("updated_at", _now_ts()),
            "x_source_platform": "securityscorecard",
            "x_securityscorecard": {
                "portfolio_id": portfolio_id,
                "companies_count": native.get("total", 0),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Extract SSC query parameters from a STIX dict."""
        return {
            "stix_id": stix_dict.get("id", ""),
            "domain": stix_dict.get("name", ""),
        }
