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

from .client import SentinelClient
from .config import SentinelConfig
from .incidents import SentinelIncidentCommands
from .stix_mapper import SentinelSTIXMapper
from .threat_intel import SentinelThreatIntelCommands


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
                self._mapper.incident_to_stix_bundle(
                    self._incidents.normalise_incident(inc)
                )
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
            raise GNATClientError(
                "Sentinel incidents cannot be deleted via this interface."
            )
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
