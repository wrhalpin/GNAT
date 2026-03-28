"""
gnat.connectors.wazuh.connector
==================================
ConnectorMixin facade for the Wazuh SIEM/XDR connector.

Wraps WazuhClient + domain command objects in the standard GNAT interface.

STIX type routing
-----------------
list_objects / get_object dispatch on stix_type:
  "observed-data"  → WazuhAlertCommands (security alerts)
  "identity"       → WazuhAgentCommands (agent records)
  "vulnerability"  → WazuhVulnerabilityCommands (CVE findings)
  None             → defaults to "observed-data" (alerts)

Auth: JWT via WazuhAuthManager. Token is acquired on first request and
refreshed automatically when it expires (Wazuh error code 4009).
"""

from __future__ import annotations

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.base_connector import ConnectorMixin

from .agents import WazuhAgentCommands
from .alerts import WazuhAlertCommands
from .client import WazuhClient
from .config import WazuhConfig
from .stix_mapper import WazuhSTIXMapper
from .vulnerabilities import WazuhVulnerabilityCommands


class WazuhConnector(BaseClient, ConnectorMixin):
    """
    GNAT connector for Wazuh SIEM/XDR.

    Implements the standard ConnectorMixin interface on top of the rich
    WazuhClient transport. Wazuh alerts map to STIX ``observed-data``
    bundles; agents map to STIX ``identity`` SDOs; vulnerability findings
    map to STIX ``vulnerability`` SDOs.

    Parameters
    ----------
    host : str
        Wazuh manager hostname or IP.
    username : str
        Wazuh API username. Default ``"wazuh"``.
    password : str
        Wazuh API password.
    verify_ssl : bool
        TLS certificate verification. Default ``False`` (Wazuh typically
        uses self-signed certs in on-premise deployments).
    timeout : float
        Request timeout in seconds. Default ``30``.
    """

    def __init__(
        self,
        host: str = "",
        username: str = "wazuh",
        password: str = "",
        verify_ssl: bool = False,
        timeout: float = 30.0,
        **kwargs,
    ) -> None:
        super().__init__(host=host, verify_ssl=verify_ssl, timeout=timeout)
        cfg = WazuhConfig(
            host=host,
            username=username,
            password=password,
            verify_ssl=bool(verify_ssl),
            timeout=int(float(timeout)),
        )
        self._wazuh = WazuhClient(cfg)
        self._alert_cmds = WazuhAlertCommands(self._wazuh)
        self._agent_cmds = WazuhAgentCommands(self._wazuh)
        self._vuln_cmds = WazuhVulnerabilityCommands(self._wazuh)
        self._mapper = WazuhSTIXMapper()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Acquire a Wazuh JWT token.

        WazuhAuthManager acquires the token lazily; calling authenticate()
        explicitly triggers eager acquisition and validates credentials.
        """
        try:
            self._wazuh.auth.get_auth_headers()
            self._authenticated = True
        except Exception as exc:
            raise SAKClientError(f"Wazuh authentication failed: {exc}") from exc

    def health_check(self) -> bool:
        """Return True if the Wazuh manager API is reachable."""
        try:
            self._wazuh.get("", params={"pretty": "true"})
            return True
        except Exception as exc:
            raise SAKClientError(f"Wazuh health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs) -> dict:
        """
        Fetch a single Wazuh object by ID.

        Parameters
        ----------
        stix_type : str
            ``"identity"`` (agent), ``"vulnerability"``, or ``"observed-data"``
            (alert — limited support, Wazuh alerts use time-based queries).
        object_id : str
            Agent ID for ``"identity"``; CVE ID for ``"vulnerability"``.
        """
        if stix_type == "identity":
            raw = self._agent_cmds.get_agent(object_id)
            return self._mapper.agent_to_stix_identity(raw)
        if stix_type == "vulnerability":
            raise SAKClientError(
                "Wazuh vulnerabilities are queried per-agent. "
                "Use list_objects(stix_type='vulnerability', agent_id=<id>)."
            )
        # observed-data: alerts don't support single-item lookup by ID
        raise SAKClientError(
            "Wazuh alerts do not support single-item lookup. "
            "Use list_objects(stix_type='observed-data') for time-based queries."
        )

    def list_objects(
        self,
        stix_type: str | None = None,
        limit: int = 100,
        **kwargs,
    ) -> list[dict]:
        """
        Return a list of STIX objects from Wazuh.

        Parameters
        ----------
        stix_type : str | None
            ``"observed-data"`` alerts (default), ``"identity"`` agents, or
            ``"vulnerability"`` CVE findings.
        limit : int
            Maximum results. Default 100.
        **kwargs
            ``agent_id`` — required for ``"vulnerability"`` queries.
        """
        if stix_type == "identity":
            agents = self._agent_cmds.list_agents(limit=limit)
            return [self._mapper.agent_to_stix_identity(a) for a in agents]

        if stix_type == "vulnerability":
            agent_id = kwargs.get("agent_id")
            if not agent_id:
                raise SAKClientError(
                    "agent_id is required for list_objects(stix_type='vulnerability')."
                )
            vulns = self._vuln_cmds.get_agent_vulnerabilities(agent_id, limit=limit)
            return [self._mapper.vulnerability_to_stix(v) for v in vulns]

        # Default: alerts → observed-data
        alerts = self._alert_cmds.get_alerts(limit=limit)
        return [
            self._mapper.alert_to_stix_bundle(
                self._alert_cmds.normalise_alert(a)
            )
            for a in alerts
        ]

    def upsert_object(self, stix_type: str, payload: dict, **kwargs) -> dict:
        """
        Not supported — Wazuh is a read-only platform from GNAT's perspective.

        Raises
        ------
        SAKClientError
            Always raised; Wazuh data cannot be pushed via this interface.
        """
        raise SAKClientError(
            "Wazuh is a read-only platform. upsert_object is not supported. "
            "Use the Wazuh manager console or API directly to manage agents/rules."
        )

    def delete_object(self, stix_type: str, object_id: str, **kwargs) -> None:
        """
        Not supported — Wazuh alert data is managed by the platform.

        Raises
        ------
        SAKClientError
            Always raised.
        """
        raise SAKClientError(
            "Wazuh is a read-only platform. delete_object is not supported."
        )

    def to_stix(self, native_object: dict) -> dict:
        """
        Convert a native Wazuh object to STIX.

        Dispatches on the presence of ``"rule"`` (alert), ``"id"`` without
        ``"cve"`` (agent identity), or ``"cve"`` (vulnerability).
        """
        if "cve" in native_object or native_object.get("condition"):
            return self._mapper.vulnerability_to_stix(native_object)
        if "rule" in native_object or "agent" in native_object:
            norm = self._alert_cmds.normalise_alert(native_object)
            return self._mapper.alert_to_stix_bundle(norm)
        # Assume agent identity
        return self._mapper.agent_to_stix_identity(native_object)

    def from_stix(self, stix_dict: dict) -> dict:
        """
        Convert a STIX indicator SDO to a Wazuh custom rule XML snippet.

        Returns a dict with ``{"rule_xml": "<rule>...</rule>"}`` suitable
        for manual import into Wazuh's custom rules directory.
        """
        return self._mapper.stix_indicator_to_wazuh_rule(stix_dict)
