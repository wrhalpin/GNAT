# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.netskope.client
====================================

Netskope REST API v2 connector.

INI config::

    [netskope]
    host      = https://<tenant>.goskope.com
    api_token = <token>
    auth_type = token
"""

from typing import Any, Optional

from gnat.clients.base import BaseClient
from gnat.connectors.base_connector import ConnectorMixin


class NetskopeClient(BaseClient, ConnectorMixin):
    """HTTP client for the Netskope REST API v2."""

    stix_type_map: dict[str, str] = {
        "indicator": "urllist",
        "malware": "malware",
    }

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        """Initialize NetskopeClient."""
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    def authenticate(self) -> None:
        """Inject Netskope API token header."""
        self._auth_headers["Netskope-Api-Token"] = self._api_token

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check against the remote API."""
        self.get("/api/v2/policy/urllist", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        return self.get(f"/api/v2/policy/urllist/{object_id}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List all objects objects."""
        params: dict[str, Any] = {"limit": page_size, "skip": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = self.get("/api/v2/policy/urllist", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        list_id = payload.pop("id", None)
        if list_id:
            return self.patch(f"/api/v2/policy/urllist/{list_id}", json=payload)
        return self.post("/api/v2/policy/urllist", json=payload)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        self.delete(f"/api/v2/policy/urllist/{object_id}")

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert this object to STIX format."""
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("name", ""),
            "created": native.get("modify_by", ""),
            "modified": native.get("modify_by", ""),
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Create an instance from STIX data."""
        return {"name": stix_dict.get("name", ""), "type": "exact", "data": {"urls": []}}

    # ── URL list extended operations ──────────────────────────────────────

    def deploy_urllist(self, list_id: str) -> dict[str, Any]:
        """
        Apply a pending URL list to Netskope policy (deploy to enforcement).

        Calls ``POST /api/v2/policy/urllist/{list_id}/deploy``.

        Parameters
        ----------
        list_id : str
            URL list ID to deploy.
        """
        resp = self.post(f"/api/v2/policy/urllist/{list_id}/deploy", json={})
        return resp if isinstance(resp, dict) else {}

    def add_urls_to_list(
        self,
        list_id: str,
        urls: list[str],
        list_type: str = "exact",
    ) -> dict[str, Any]:
        """
        Append URLs to an existing Netskope URL list.

        Calls ``PATCH /api/v2/policy/urllist/{list_id}``.

        Parameters
        ----------
        list_id : str
            URL list ID to modify.
        urls : list of str
            URL values to add.
        list_type : str
            Match type for added URLs: ``"exact"``, ``"regex"``.
            Default ``"exact"``.
        """
        resp = self.patch(
            f"/api/v2/policy/urllist/{list_id}",
            json={"data": {"urls": urls}, "type": list_type},
        )
        return resp if isinstance(resp, dict) else {}

    def replace_urllist_urls(
        self,
        list_id: str,
        urls: list[str],
        list_type: str = "exact",
    ) -> dict[str, Any]:
        """
        Replace the full URL set in a Netskope URL list.

        Calls ``PUT /api/v2/policy/urllist/{list_id}``.

        Parameters
        ----------
        list_id : str
            URL list ID.
        urls : list of str
            Complete new URL set.
        list_type : str
            Match type: ``"exact"`` or ``"regex"``.  Default ``"exact"``.
        """
        resp = self.put(
            f"/api/v2/policy/urllist/{list_id}",
            json={"data": {"urls": urls}, "type": list_type},
        )
        return resp if isinstance(resp, dict) else {}

    # ── Alerts ────────────────────────────────────────────────────────────

    def list_alerts(
        self,
        alert_type: str = "",
        limit: int = 100,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope alerts with optional filters.

        Calls ``GET /api/v2/alerts/``.

        Parameters
        ----------
        alert_type : str, optional
            Filter by alert type (e.g. ``"Malware"``, ``"DLP"``,
            ``"watchlist"``, ``"policy"``).
        limit : int
            Maximum alerts to return.  Default ``100``.
        skip : int
            Pagination offset.  Default ``0``.
        start_time : int, optional
            Unix timestamp; return only alerts after this time.
        end_time : int, optional
            Unix timestamp; return only alerts before this time.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if alert_type:
            params["type"] = alert_type
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get("/api/v2/alerts/", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Retrieve a single Netskope alert by ID.

        Calls ``GET /api/v2/alerts/{alert_id}``.

        Parameters
        ----------
        alert_id : str
            Netskope alert ID.
        """
        resp = self.get(f"/api/v2/alerts/{alert_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def acknowledge_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Acknowledge a Netskope alert, marking it as reviewed.

        Calls ``PATCH /api/v2/alerts/{alert_id}`` with
        ``{"acked": True}``.

        Parameters
        ----------
        alert_id : str
            Netskope alert ID to acknowledge.
        """
        resp = self.patch(f"/api/v2/alerts/{alert_id}", json={"acked": True})
        return resp if isinstance(resp, dict) else {}

    # ── Event data export ─────────────────────────────────────────────────

    def get_application_events(
        self,
        filter_expr: str = "",
        limit: int = 1000,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope application events (page traffic, app usage).

        Calls ``GET /api/v2/events/dataexport/events/application``.

        Parameters
        ----------
        filter_expr : str, optional
            NQL filter expression (e.g. ``"app eq 'Dropbox'"``).
        limit : int
            Records per page.  Default ``1000``.
        skip : int
            Pagination offset.
        start_time : int, optional
            Unix timestamp for start of window.
        end_time : int, optional
            Unix timestamp for end of window.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if filter_expr:
            params["query"] = filter_expr
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get(
            "/api/v2/events/dataexport/events/application", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_page_events(
        self,
        filter_expr: str = "",
        limit: int = 1000,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope page events (web browsing / URL visits).

        Calls ``GET /api/v2/events/dataexport/events/page``.

        Parameters
        ----------
        filter_expr : str, optional
            NQL filter expression.
        limit : int
            Records per page.  Default ``1000``.
        skip : int
            Pagination offset.
        start_time : int, optional
            Unix timestamp for start of window.
        end_time : int, optional
            Unix timestamp for end of window.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if filter_expr:
            params["query"] = filter_expr
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get(
            "/api/v2/events/dataexport/events/page", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_infrastructure_events(
        self,
        filter_expr: str = "",
        limit: int = 1000,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope infrastructure events (NPA / gateway traffic).

        Calls ``GET /api/v2/events/dataexport/events/infrastructure``.

        Parameters
        ----------
        filter_expr : str, optional
            NQL filter expression.
        limit : int
            Records per page.  Default ``1000``.
        skip : int
            Pagination offset.
        start_time : int, optional
            Unix timestamp.
        end_time : int, optional
            Unix timestamp.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if filter_expr:
            params["query"] = filter_expr
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get(
            "/api/v2/events/dataexport/events/infrastructure", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_network_events(
        self,
        filter_expr: str = "",
        limit: int = 1000,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope network events (firewall / packet-level).

        Calls ``GET /api/v2/events/dataexport/events/network``.

        Parameters
        ----------
        filter_expr : str, optional
            NQL filter expression.
        limit : int
            Records per page.  Default ``1000``.
        skip : int
            Pagination offset.
        start_time : int, optional
            Unix timestamp.
        end_time : int, optional
            Unix timestamp.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if filter_expr:
            params["query"] = filter_expr
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get(
            "/api/v2/events/dataexport/events/network", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_alert_events(
        self,
        filter_expr: str = "",
        limit: int = 1000,
        skip: int = 0,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Netskope alert events from the event export stream.

        Calls ``GET /api/v2/events/dataexport/alerts/alert``.

        Parameters
        ----------
        filter_expr : str, optional
            NQL filter expression (e.g. ``"alert_type eq 'Malware'"``).
        limit : int
            Records per page.  Default ``1000``.
        skip : int
            Pagination offset.
        start_time : int, optional
            Unix timestamp.
        end_time : int, optional
            Unix timestamp.
        """
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if filter_expr:
            params["query"] = filter_expr
        if start_time:
            params["starttime"] = start_time
        if end_time:
            params["endtime"] = end_time
        resp = self.get(
            "/api/v2/events/dataexport/alerts/alert", params=params
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Policy ────────────────────────────────────────────────────────────

    def list_policy_rules(
        self,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List Netskope real-time protection policy rules.

        Calls ``GET /api/v2/policy/rules``.

        Parameters
        ----------
        limit : int
            Maximum rules to return.  Default ``100``.
        skip : int
            Pagination offset.
        """
        resp = self.get(
            "/api/v2/policy/rules",
            params={"limit": limit, "skip": skip},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_policy_rule(self, rule_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Netskope policy rule.

        Calls ``GET /api/v2/policy/rules/{rule_id}``.

        Parameters
        ----------
        rule_id : str
            Policy rule ID.
        """
        resp = self.get(f"/api/v2/policy/rules/{rule_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ── Private application management ───────────────────────────────────

    def list_private_apps(
        self,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List Netskope NPA (Network Private Access) private applications.

        Calls ``GET /api/v2/policy/privateapps``.

        Parameters
        ----------
        limit : int
            Maximum apps to return.  Default ``100``.
        skip : int
            Pagination offset.
        """
        resp = self.get(
            "/api/v2/policy/privateapps",
            params={"limit": limit, "skip": skip},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_private_app(self, app_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Netskope NPA private application.

        Calls ``GET /api/v2/policy/privateapps/{app_id}``.

        Parameters
        ----------
        app_id : str
            Private application ID.
        """
        resp = self.get(f"/api/v2/policy/privateapps/{app_id}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def create_private_app(
        self,
        name: str,
        hosts: list[str],
        protocols: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new Netskope NPA private application definition.

        Calls ``POST /api/v2/policy/privateapps``.

        Parameters
        ----------
        name : str
            Friendly name for the private application.
        hosts : list of str
            Hostnames or CIDR ranges the application listens on.
        protocols : list of dict, optional
            Protocol definitions (e.g.
            ``[{"type": "tcp", "port": "443"}]``).
        """
        payload: dict[str, Any] = {
            "app_name": name,
            "host": hosts,
            "protocols": protocols or [{"type": "tcp", "port": "443"}],
        }
        resp = self.post("/api/v2/policy/privateapps", json=payload)
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    # ── User configuration ────────────────────────────────────────────────

    def get_user_config(self, username: str) -> dict[str, Any]:
        """
        Retrieve Netskope configuration for a specific user.

        Calls ``GET /api/v2/userconfig/{username}``.

        Parameters
        ----------
        username : str
            Netskope username (typically email address).
        """
        import urllib.parse
        encoded = urllib.parse.quote(username, safe="")
        resp = self.get(f"/api/v2/userconfig/{encoded}")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def list_users(
        self,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List Netskope managed users.

        Calls ``GET /api/v2/userconfig``.

        Parameters
        ----------
        limit : int
            Maximum users to return.  Default ``100``.
        skip : int
            Pagination offset.
        """
        resp = self.get(
            "/api/v2/userconfig",
            params={"limit": limit, "skip": skip},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    # ── Steering configuration ────────────────────────────────────────────

    def list_web_categories(
        self,
        limit: int = 200,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List Netskope web application categories (cloud app categories).

        Calls ``GET /api/v2/steering/apps/web``.

        Parameters
        ----------
        limit : int
            Maximum categories to return.  Default ``200``.
        skip : int
            Pagination offset.
        """
        resp = self.get(
            "/api/v2/steering/apps/web",
            params={"limit": limit, "skip": skip},
        )
        return resp.get("data", []) if isinstance(resp, dict) else []

    def list_client_configs(self) -> list[dict[str, Any]]:
        """
        List Netskope Client (endpoint agent) configuration profiles.

        Calls ``GET /api/v2/infrastructure/clients``.
        """
        resp = self.get("/api/v2/infrastructure/clients")
        return resp.get("data", []) if isinstance(resp, dict) else []

    def get_siem_config(self) -> dict[str, Any]:
        """
        Retrieve Netskope SIEM export configuration.

        Calls ``GET /api/v2/infrastructure/siem``.
        """
        resp = self.get("/api/v2/infrastructure/siem")
        return resp.get("data", resp) if isinstance(resp, dict) else {}

    def update_siem_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Update Netskope SIEM export configuration.

        Calls ``PUT /api/v2/infrastructure/siem``.

        Parameters
        ----------
        config : dict
            SIEM configuration payload (source, destination, events, etc.).
        """
        resp = self.put("/api/v2/infrastructure/siem", json=config)
        return resp if isinstance(resp, dict) else {}

    # ── Tenant information ────────────────────────────────────────────────

    def get_tenant_info(self) -> dict[str, Any]:
        """
        Return Netskope tenant metadata and licence details.

        Calls ``GET /api/v2/tenant``.
        """
        resp = self.get("/api/v2/tenant")
        return resp.get("data", resp) if isinstance(resp, dict) else {}
