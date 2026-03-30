"""
gnat.connectors.flashpoint.client
=================================

Flashpoint (Underground / Dark Web CTI) connector — full client.

Authentication
--------------
API Token via ``Authorization: Bearer`` header::

    [flashpoint]
    host  = https://api.flashpoint.io
    token = <your-flashpoint-api-token>

Generate the token in the Flashpoint portal (Settings → API Access).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Flashpoint Resource              |
+================+==================================+
| indicator      | IOCs from underground sources    |
+----------------+----------------------------------+
| report         | Alerts / Threat Actor intel / Forum posts |
+----------------+----------------------------------+

Key Endpoints (2026 API)
------------------------
* /v1/alerts                     — Real-time alerts from underground sources
* /v1/iocs                       — IOCs extracted from dark web / forums
* /v1/threat-actors              — Threat actor profiles and activity
* /v1/forums                     — Forum posts and marketplace listings
* /v1/ransomware                 — Ransomware-specific intelligence
* /v1/search                     — Unified search across all collections

Notes
-----
* Deep underground visibility (forums, dark web markets, Telegram, etc.).
* Strong on early ransomware and cybercrime signals.
* Read-only for most use cases; excellent for enrichment.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a9b8c7d6-e5f4-3a2b-1c0d-9e8f7a6b5c4d")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%-%dT%H:%M:%S.%f")[:-3] + "Z"


class FlashpointClient(BaseClient, ConnectorMixin):
    """
    Full HTTP client for Flashpoint Underground CTI API.

    Parameters
    ----------
    host : str
        Base URL (usually "https://api.flashpoint.io").
    token : str
        Flashpoint API token.
    """

    stix_type_map: Dict[str, str] = {
        "indicator":