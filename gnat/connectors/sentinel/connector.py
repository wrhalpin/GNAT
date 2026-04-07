# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sentinel.connector
=====================================
ConnectorMixin facade for the Microsoft Sentinel connector.

Wraps SentinelClient + domain command objects in the standard GNAT interface.

STIX type routing
-----------------
list_objects / get_object dispatch on stix_type:
  "indicator"      → SentinelThreatIntelCommands (TI indicators API)
  "observed-data"  → SentinelIncidentCommands (incidents / alerts)
  None             → defaults to "indicator"

Auth: OAuth2 client credentials (Azure AD). SentinelAuthManager handles
token acquisition and refresh transparently.
"""

from __future__ import annotations

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

from .alerts import SentinelAlertCommands
from .analytic_rules import SentinelAnalyticRuleCommands
from .client import SentinelClient
from .config import SentinelConfig
from .hunting import SentinelHuntingCommands
from .incidents import SentinelIncidentCommands
from .stix_mapper import SentinelSTIXMapper
from .threat_intel import SentinelThreatIntelCommands
from .watchlists import SentinelWatchlistCommands


class SentinelConnector(BaseClient, ConnectorMixin):
    """
    GNAT connector for Microsoft Sentinel.

    Implements the standard ConnectorMixin interface on top of the rich
    SentinelClient transport. Threat intelligence indicators map to STIX
    ``indicator`` SDOs; incidents map to STIX ``observed-data`` bundles.

    Parameters
    ----------
    host : str
        Ignored for Sentinel (Azure management endpoint is fixed).
        Accepted for interface compatibility; pass any non-empty string.
    tenant_id : str
        Azure Active Directory tenant ID.
    client_id : str
        Service principal application (client) ID.
    client_secret : str
        Service principal client secret.
    subscription_id : str
        Azure subscription ID.
    resource_group : str
        Resource group containing the Sentinel workspace.
    workspace_name : str
        Log Analytics workspace name.
    workspace_id : str, optional
        Log Analytics workspace ID (GUID). Used for advanced queries.
    verify_ssl : bool
        TLS certificate verification. Default ``True``.
    timeout : float
        Request timeout in seconds. Default ``30``.
    """

    def __init__(
        self,
        host: str = "management.azure.com",
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
        subscription_id: str = "",
        resource_group: str = "",
        workspace_name: str = "",
        workspace_id: str = "",
        verify_ssl: bool = True,
        timeout: float = 30.0,
        **kwargs,
    ) -> None:
        """Initialize SentinelConnector."""
        super().__init__(
            host=host or "management.azure.com",
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        cfg = SentinelConfig(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            subscription_id=subscription_id,
            resource_group=resource_group,
            workspace_name=workspace_name,
            workspace_id=workspace_id,
            verify_ssl=bool(verify_ssl),
            timeout=int(float(timeout)),
        )
        self._sentinel = SentinelClient(cfg)
        self._ti = SentinelThreatIntelCommands(self._sentinel)
        self._incidents = SentinelIncidentCommands(self._sentinel)
        self._alerts = SentinelAlertCommands(self._sentinel)
        self._rules = SentinelAnalyticRuleCommands(self._sentinel)
        self._hunting = SentinelHuntingCommands(self._sentinel)
        self._watchlists = SentinelWatchlistCommands(self._sentinel)
        self._mapper = SentinelSTIXMapper()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Acquire an Azure AD OAuth2 token.

        SentinelAuthManager acquires and caches the token lazily on first
        request; calling authenticate() explicitly triggers it eagerly.
        """
        try:
            self._sentinel.auth.get_headers()
            self._authenticated = True
        except Exception as exc:
            raise GNATClientError(f"Sentinel authentication failed: {exc}") from exc

    def health_check(self) -> bool:
        """Return True if the Sentinel workspace endpoint is reachable."""
        try:
            self._sentinel.get("incidents", params={"$top": "1"})
            return True
        except Exception as exc:
            raise GNATClientError(f"Sentinel health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs) -> dict:
        """
        Fetch a single Sentinel object by ID.

        Parameters
        ----------
        stix_type : str
            ``"indicator"`` (TI indicator) or ``"observed-data"`` (incident).
        object_id : str
            Sentinel resource name / GUID.
        """
        if stix_type == "observed-data":
            raw = self._incidents.get_incident(object_id)
            norm = self._incidents.normalise_incident(raw)
            return self._mapper.incident_to_stix_bundle(norm)
        # Default: TI indicator
        raw = self._ti.get_indicator(object_id)
        norm = self._ti.normalise_indicator(raw)
        return self._mapper.ti_indicator_to_stix(norm)

    def list_objects(
        self,
        stix_type: str | None = None,
        limit: int = 100,
        **kwargs,
    ) -> list[dict]:
        """
        Return a list of STIX objects from Sentinel.

        Parameters
        ----------
        stix_type : str | None
            ``"indicator"`` (default) or ``"observed-data"`` (incidents).
        limit : int
            Maximum results. Default 100.
        """
        if stix_type == "observed-data":
            incidents = self._incidents.list_incidents(limit=limit)
            return [
                self._mapper.incident_to_stix_bundle(self._incidents.normalise_incident(inc))
                for inc in incidents
            ]
        # Default: TI indicators
        indicators = self._ti.list_indicators(limit=limit)
        return [
            self._mapper.ti_indicator_to_stix(self._ti.normalise_indicator(ind))
            for ind in indicators
        ]

    def upsert_object(self, stix_type: str, payload: dict, **kwargs) -> dict:
        """
        Create or update a Sentinel TI indicator from a STIX indicator SDO.

        Parameters
        ----------
        stix_type : str
            Must be ``"indicator"``. Incident upsert is not supported.
        payload : dict
            STIX 2.1 indicator SDO.
        """
        if stix_type == "observed-data":
            raise GNATClientError(
                "Sentinel incidents cannot be created via upsert_object. "
                "Use the underlying _incidents client to create incidents."
            )
        sentinel_indicator = self._mapper.stix_indicator_to_ti_properties(payload)
        return self._ti.create_indicator(sentinel_indicator)

    def delete_object(self, stix_type: str, object_id: str, **kwargs) -> None:
        """Delete a Sentinel TI indicator by resource name."""
        if stix_type == "observed-data":
            raise GNATClientError("Sentinel incidents cannot be deleted via this interface.")
        self._ti.delete_indicator(object_id)

    def to_stix(self, native_object: dict) -> dict:
        """
        Convert a native Sentinel object to STIX.

        Dispatches on the presence of ``"properties.pattern"`` (indicator)
        or ``"properties.severity"`` (incident).
        """
        props = native_object.get("properties", {})
        if "pattern" in props or "patternType" in props:
            norm = self._ti.normalise_indicator(native_object)
            return self._mapper.ti_indicator_to_stix(norm)
        # Assume incident
        norm = self._incidents.normalise_incident(native_object)
        return self._mapper.incident_to_stix_bundle(norm)

    def from_stix(self, stix_dict: dict) -> dict:
        """Convert a STIX indicator SDO to a Sentinel TI indicator dict."""
        return self._mapper.stix_indicator_to_ti_properties(stix_dict)

    # ── Incident lifecycle ────────────────────────────────────────────────────

    def create_incident(
        self,
        title: str,
        severity: str = "Medium",
        status: str = "New",
        description: str = "",
    ) -> dict:
        """
        Create a new Sentinel incident.

        ``severity`` options: ``"High"``, ``"Medium"``, ``"Low"``, ``"Informational"``.
        ``status`` options: ``"New"``, ``"Active"``, ``"Closed"``.
        """
        return self._incidents.create_incident(
            title=title, severity=severity, status=status, description=description
        )

    def update_incident(self, incident_id: str, updates: dict) -> dict:
        """Update an existing incident (severity, status, owner, labels, etc.)."""
        return self._incidents.update_incident(incident_id, updates)

    def close_incident(
        self,
        incident_id: str,
        classification: str = "Undetermined",
        reason: str = "",
    ) -> dict:
        """
        Close a Sentinel incident with a classification.

        ``classification`` options: ``"Undetermined"``, ``"TruePositive"``,
        ``"BenignPositive"``, ``"FalsePositive"``.
        """
        return self._incidents.close_incident(
            incident_id, classification=classification, reason=reason
        )

    def add_incident_comment(self, incident_id: str, message: str) -> dict:
        """Add a comment to a Sentinel incident."""
        return self._incidents.add_comment(incident_id, message)

    def list_incident_comments(self, incident_id: str) -> list[dict]:
        """List all comments on a Sentinel incident."""
        return self._incidents.list_comments(incident_id)

    def list_incident_entities(self, incident_id: str) -> list[dict]:
        """List entities (IPs, hosts, accounts, etc.) linked to an incident."""
        return self._incidents.list_entities(incident_id)

    def get_incident_count(
        self,
        severity: str | None = None,
        status: str | None = None,
    ) -> int:
        """Return the count of incidents matching optional severity/status filters."""
        return self._incidents.get_incident_count(severity=severity, status=status)

    def iter_all_incidents(self):
        """Generator that yields every incident page by page."""
        yield from self._incidents.iter_all_incidents()

    # ── Threat intelligence (extended) ────────────────────────────────────────

    def update_ti_indicator(self, indicator_name: str, updates: dict) -> dict:
        """Update a TI indicator by resource name."""
        return self._ti.update_indicator(indicator_name, updates)

    def bulk_create_ti_indicators(self, indicators: list[dict]) -> list[dict]:
        """
        Create multiple TI indicators in a single API call.

        Each item in ``indicators`` should be a Sentinel TI indicator properties dict.
        The response is a list of created indicator resources.
        """
        return self._ti.bulk_create_indicators(indicators)

    def query_ti_indicators(self, query: dict) -> list[dict]:
        """
        Query TI indicators with a filter expression.

        ``query`` example::

            {"keywords": "ransomware", "pageSize": 50}
        """
        return self._ti.query_indicators(query)

    def iter_all_ti_indicators(self):
        """Generator that yields every TI indicator page by page."""
        yield from self._ti.iter_all_indicators()

    # ── Alerts ────────────────────────────────────────────────────────────────

    def list_alerts(
        self,
        filter_val: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List Sentinel security alerts.

        ``filter_val`` is an OData ``$filter`` expression, e.g.
        ``"properties/severity eq 'High'"``.
        """
        return self._alerts.list_alerts(filter_val=filter_val, limit=limit)

    def get_incident_alerts(self, incident_id: str) -> list[dict]:
        """List alerts grouped under a specific incident."""
        return self._alerts.get_incident_alerts(incident_id)

    # ── Analytic rules ────────────────────────────────────────────────────────

    def list_analytic_rules(
        self,
        kind: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        List analytic rules in the Sentinel workspace.

        ``kind`` filter options: ``"Scheduled"``, ``"MicrosoftSecurityIncidentCreation"``,
        ``"Fusion"``, ``"MLBehaviorAnalytics"``, ``"ThreatIntelligence"``.
        """
        return self._rules.list_rules(kind=kind, limit=limit)

    def get_analytic_rule(self, rule_id: str) -> dict:
        """Retrieve a single analytic rule by ID."""
        return self._rules.get_rule(rule_id)

    def enable_analytic_rule(self, rule_id: str) -> dict:
        """Enable an analytic rule."""
        return self._rules.enable_rule(rule_id)

    def disable_analytic_rule(self, rule_id: str) -> dict:
        """Disable an analytic rule."""
        return self._rules.disable_rule(rule_id)

    def delete_analytic_rule(self, rule_id: str) -> dict:
        """Delete an analytic rule."""
        return self._rules.delete_rule(rule_id)

    def list_rule_templates(self, kind: str | None = None) -> list[dict]:
        """List available analytic rule templates."""
        return self._rules.list_rule_templates(kind=kind)

    def iter_all_analytic_rules(self, kind: str | None = None):
        """Generator that yields every analytic rule page by page."""
        yield from self._rules.iter_all_rules(kind=kind)

    # ── Hunting queries ───────────────────────────────────────────────────────

    def list_hunting_queries(self, limit: int | None = None) -> list[dict]:
        """List saved hunting queries in the Sentinel workspace."""
        return self._hunting.list_queries(limit=limit)

    def get_hunting_query(self, query_id: str) -> dict:
        """Retrieve a hunting query by ID."""
        return self._hunting.get_query(query_id)

    def create_hunting_query(
        self,
        display_name: str,
        query: str,
        description: str = "",
        tactics: list[str] | None = None,
        techniques: list[str] | None = None,
    ) -> dict:
        """
        Create a new hunting query.

        ``tactics`` — list of MITRE ATT&CK tactic names.
        ``techniques`` — list of MITRE ATT&CK technique IDs (e.g. ``["T1078"]``).
        """
        return self._hunting.create_query(
            display_name=display_name,
            query=query,
            description=description,
            tactics=tactics or [],
            techniques=techniques or [],
        )

    def delete_hunting_query(self, query_id: str) -> dict:
        """Delete a hunting query by ID."""
        return self._hunting.delete_query(query_id)

    # ── Watchlists ────────────────────────────────────────────────────────────

    def list_watchlists(self) -> list[dict]:
        """List all watchlists in the Sentinel workspace."""
        return self._watchlists.list_watchlists()

    def get_watchlist(self, alias: str) -> dict:
        """Retrieve a watchlist by alias."""
        return self._watchlists.get_watchlist(alias)

    def create_watchlist(
        self,
        alias: str,
        display_name: str,
        source: str,
        content_type: str = "text/csv",
        description: str = "",
        items_search_key: str = "",
        number_of_lines_to_skip: int = 1,
    ) -> dict:
        """
        Create a new watchlist.

        ``source`` — CSV file name (e.g. ``"watchlist.csv"``).
        ``items_search_key`` — column name used as the primary key for deduplication.
        """
        return self._watchlists.create_watchlist(
            alias=alias,
            display_name=display_name,
            source=source,
            content_type=content_type,
            description=description,
            items_search_key=items_search_key,
            number_of_lines_to_skip=number_of_lines_to_skip,
        )

    def delete_watchlist(self, alias: str) -> dict:
        """Delete a watchlist by alias."""
        return self._watchlists.delete_watchlist(alias)

    def list_watchlist_items(self, alias: str) -> list[dict]:
        """List all items in a watchlist."""
        return self._watchlists.list_watchlist_items(alias)

    def add_watchlist_item(
        self,
        alias: str,
        item_data: dict,
    ) -> dict:
        """
        Add a single item to a watchlist.

        ``item_data`` is a key/value dict matching the watchlist column schema.
        """
        return self._watchlists.add_watchlist_item(alias=alias, item_data=item_data)

    def bulk_add_watchlist_items(
        self,
        alias: str,
        items: list[dict],
    ) -> list[dict]:
        """Add multiple items to a watchlist in batch."""
        return self._watchlists.bulk_add_items(alias=alias, items=items)
