"""
gnat.connectors.defectdojo.client
=================================

DefectDojo (Open Source Vulnerability Management & Orchestration) connector — full client.

Authentication
--------------
API Token via ``Authorization: Token`` header::

    [defectdojo]
    host  = https://your-defectdojo-instance.com
    token = <your-defectdojo-api-token>

Generate token in DefectDojo UI (API v2 section) or via admin.

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | DefectDojo Resource              |
+================+==================================+
| vulnerability  | Findings                         |
+----------------+----------------------------------+
| report         | Engagements / Tests              |
+----------------+----------------------------------+

Key Endpoints (API v2)
----------------------
* /api/v2/findings/          — List/create findings (core vuln data)
* /api/v2/engagements/       — Engagements (projects/tests)
* /api/v2/tests/             — Individual tests/scans
* /api/v2/products/          — Products (high-level grouping)

Notes
-----
* DefectDojo is writable (supports import/upsert of findings).
* Strong support for severity, CVSS, CWE, MITRE ATT&CK, endpoints, and tags.
* OpenAPI/Swagger available at /api/v2/oa3/swagger-ui/ on your instance.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c7d8e9f0-a1b2-3c4d-5e6f-7a8b9c0d1e2f")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class DefectDojoClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for DefectDojo API v2.

    Parameters
    ----------
    host : str
        Base URL of your DefectDojo instance.
    token : str
        DefectDojo API token.
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "findings",
        "report":        "engagements",
    }

    def __init__(self, host: str, token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Token auth header."""
        self._auth_headers["Authorization"] = f"Token {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin —