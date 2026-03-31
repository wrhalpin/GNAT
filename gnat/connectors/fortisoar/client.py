"""
gnat.connectors.fortisoar.client
================================

FortiSOAR connector for module-based CRUD (alerts, incidents, indicators, etc.) and playbook actions.

Authentication
--------------
JWT token via POST /auth/authenticate (preferred) or HTTP Basic Auth::

    [fortisoar]
    host     = https://<fortisoar-fqdn-or-ip>
    username = <username>
    password = <password>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | FortiSOAR Module                 |
+================+==================================+
| incident       | incidents                        |
+----------------+----------------------------------+
| observed-data  | alerts                           |
+----------------+----------------------------------+
| indicator      | indicators                       |
+----------------+----------------------------------+
| report         | other modules (assets, warrooms) |
+----------------+----------------------------------+

Key Endpoints (/api/3/)
-----------------------
* ``GET/POST /api/3/{module}``          -- List or bulk create (e.g., /api/3/alerts, /api/3/incidents)
* ``GET/PUT/DELETE /api/3/{module}/{uuid}`` -- Single record CRUD
* ``POST /auth/authenticate``           -- JWT token exchange
* Playbook triggering via custom endpoints or module actions

Notes
-----
* Full CRUD support on standard modules (alerts, incidents, indicators).
* `list_objects()` and `upsert_object()` dispatch by STIX type → module name.
* Domain helpers for common operations (list_alerts, escalate_to_incident, trigger_playbook).
* `to_stix()` maps records to appropriate STIX types with rich `x_fortisoar` extension.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision for STIX."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FortiSOARClient(BaseClient, ConnectorMixin):
    """
    HTTP client for FortiSOAR REST API v3 (module-based records + playbooks).

    Parameters
    ----------
    host : str
        FortiSOAR base URL, e.g. ``"https://fortisoar.example.com"``.
    username : str
        Username with appropriate permissions.
    password : str
        Password for authentication.
    """

    stix_type_map: Dict[str, str] = {
        "incident": "incidents",
        "observed-data": "alerts",
        "indicator": "indicators",
        "report": "assets",  # or other modules
    }

    def __init__(self, host: str, username: str = "", password: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._username = username
        self._password = password
        self._token: Optional[str] = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Obtain JWT token via /auth/authenticate and set Bearer header."""
        if self._token:
            self._auth_headers["Authorization"] = f"Bearer {self._token}"
            return

        # First-time JWT exchange
        payload = {"username": self._username, "password": self._password}
        try:
            resp = self.post("/auth/authenticate", json=payload)
            self._token = resp.get("token") or resp.get("access_token")
            if self._token:
                self._auth_headers["Authorization"] = f"Bearer {self._token}"
            else:
                # Fallback to Basic if JWT fails
                self._auth_headers["Authorization"] = self._basic_auth(self._username, self._password)
        except Exception:
            # Fallback to Basic Auth
            self._auth_headers["Authorization"] = self._basic_auth(self._username, self._password)

        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin -- CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Lightweight check via modules list or application status."""
        self.get("/api/3/model_metadatas", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch single record by UUID."""
        module = self.stix_type_map.get(stix