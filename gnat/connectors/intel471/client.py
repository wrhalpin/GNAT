"""
gnat.connectors.intel471.client
===============================

Intel 471 (Cybercrime-Focused Threat Intelligence) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [intel471]
    host  = https://api.intel471.com
    token = <your-intel471-api-token>

Generate the token in the Intel 471 portal (Settings → API Access).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Intel 471 Resource               |
+================+==================================+
| indicator      | IOCs from cybercrime sources     |
+----------------+----------------------------------+
| report         | Actor profiles, malware campaigns, ransomware intel |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/actors                     — Threat actor profiles and activity
* /v1/malware                    — Malware samples and campaigns
* /v1/ransomware                 — Ransomware group intel and leaks
* /v1/iocs                       — Extracted IOCs from underground sources
* /v1/alerts                     — Real-time alerts on cybercrime activity
* /v1/search                     — Unified search across collections

Notes
-----
* Deep focus on actor attribution, malware, and ransomware operations.
* Strong on underground forum and marketplace monitoring.
* Excellent complement to Flashpoint and Hudson Rock for cybercrime depth.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("c9d0e1f2-a3b4-5c6d-7e8f-9a0b1c2d3e4f")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Intel471Client(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Intel 471 Cybercrime Intelligence API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.intel471.com").
    token : str
        Intel 471 API token.
    """

    stix_type_map: Dict[str, str] = {
        "indicator": "iocs",
        "report":    "actors",
    }

    def __init__(self, host: str = "https://api.intel471.com", token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._token = token

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject Bearer token header."""
        self._auth_headers["Authorization"] = f"Bearer {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content"]