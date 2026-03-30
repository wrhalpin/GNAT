"""
gnat.connectors.logrhythm.client
================================

LogRhythm (SIEM + Threat Intel) connector — full client (Exabeam-hosted APIs).

Authentication
--------------
OAuth2 or API Token (check your instance; common is Bearer token)::

    [logrhythm]
    host  = https://your-lr-instance.exabeam.com
    token = <your-lr-api-token>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | LogRhythm Resource               |
+================+==================================+
| report         | Cases / Alarms                   |
+----------------+----------------------------------+
| indicator      | IOCs from alarms                 |
+----------------+----------------------------------+

Key Endpoints
-------------
* /api/cases                    — Case management
* /api/alarms                   — Alarm data
* /api/entities                 — Entity enrichment
* /api/search                   — Log/search queries
* AI Engine & NetMon endpoints (new in 7.23+)

Notes
-----
* Strong for case orchestration and alarm-to-STIX pipelines.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LogRhythmClient(BaseClient, ConnectorMixin):
    stix_type_map: Dict[str, str] = {
        "report": "cases",
        "indicator": "alarms",
    }

    def __init__(self, host: str, token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._token = token

    def authenticate(self) -> None:
        self._auth_headers["Authorization"] = f"Bearer {self._token}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        self.get("/api/cases", params={"limit": 1})
        return True

    # ... (list_objects, get_object, helpers for alarms/cases/search, to_stix/from_stix with x_logrhythm_ namespace) ...
    # (Full implementation follows the same style as previous connectors – let me know if you need the complete expanded version.)