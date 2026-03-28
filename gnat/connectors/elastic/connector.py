"""
gnat.connectors.elastic.connector
==================================
ConnectorMixin facade for the Elastic Security connector.

Wraps the rich ElasticClient HTTP transport + domain command objects
in the standard GNAT 7-method interface so that ElasticConnector can
be used via SAKClient like any other connector.

STIX type routing
-----------------
list_objects / get_object dispatch on stix_type:
  "indicator"      → ElasticThreatIntelCommands (logs-ti_* data stream)
  "observed-data"  → KibanaAlertsCommands (Kibana Security alerts)
  None             → defaults to threat-intel indicators
"""

from __future__ import annotations

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.base_connector import ConnectorMixin

from .client import ElasticClient
from .config import ElasticConfig
from .kibana_alerts import KibanaAlertsCommands
from .stix_mapper import ElasticSTIXMapper
from .threat_intel import ElasticThreatIntelCommands


class ElasticConnector(BaseClient, ConnectorMixin):
    """
    GNAT connector for Elastic Security (Elasticsearch + Kibana).

    Implements the standard ConnectorMixin interface on top of the rich
    ElasticClient transport, routing STIX types to the appropriate
    Elastic API surface:

    - STIX ``indicator`` ↔ Elastic threat-intel data stream (``logs-ti_*``)
    - STIX ``observed-data`` ↔ Kibana Security alerts (``.alerts-security.*``)

    Parameters
    ----------
    host : str
        Elasticsearch base URL, e.g. ``"https://my-cluster.es.io:9200"``.
    api_key_id : str
        Elastic API key ID component.
    api_key_secret : str
        Elastic API key secret component.
    kibana_host : str, optional
        Kibana base URL. Defaults to *host* when omitted.
    verify_ssl : bool
        TLS certificate verification. Default ``True``.
    timeout : float
        Request timeout in seconds. Default ``30``.
    """

    def __init__(
        self,
        host: str = "",
        api_key_id: str = "",
        api_key_secret: str = "",
        kibana_host: str = "",
        verify_ssl: bool = True,
        timeout: float = 30.0,
        **kwargs,
    ) -> None:
        super().__init__(host=host, verify_ssl=verify_ssl, timeout=timeout)
        cfg = ElasticConfig(
            api_key_id=api_key_id,
            api_key_secret=api_key_secret,
            es_host=host,
            kibana_host=kibana_host or host,
            verify_ssl=bool(verify_ssl),
            timeout=int(float(timeout)),
        )
        self._elastic = ElasticClient(cfg)
        self._ti = ElasticThreatIntelCommands(self._elastic)
        self._alerts = KibanaAlertsCommands(self._elastic)
        self._mapper = ElasticSTIXMapper()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """No explicit auth step — API key is injected per-request."""
        self._authenticated = True

    def health_check(self) -> bool:
        """Return True if the Elasticsearch cluster is reachable."""
        try:
            self._elastic.es_get("_cluster/health")
            return True
        except Exception as exc:
            raise SAKClientError(f"Elastic health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs) -> dict:
        """
        Fetch a single object by ID.

        Parameters
        ----------
        stix_type : str
            ``"indicator"`` (TI data stream) or ``"observed-data"`` (alert).
        object_id : str
            Elastic document ``_id``.
        """
        if stix_type == "observed-data":
            alert = self._alerts.get_alert_by_id(object_id)
            if alert is None:
                raise SAKClientError(f"Alert {object_id!r} not found", status=404)
            return self._mapper.alert_to_stix_bundle(
                self._alerts.normalise_alert(alert)
            )
        # Default: threat-intel indicator
        raw = self._elastic.es_get(
            f"{self._elastic.config.es_index_ti}/_doc/{object_id}"
        )
        return self._mapper.ecs_indicator_to_stix(self._ti.normalise_indicator(raw))

    def list_objects(
        self,
        stix_type: str | None = None,
        limit: int = 100,
        **kwargs,
    ) -> list[dict]:
        """
        Return a list of STIX objects.

        Parameters
        ----------
        stix_type : str | None
            ``"indicator"`` or ``"observed-data"``. Default: ``"indicator"``.
        limit : int
            Maximum number of results. Default 100.
        """
        if stix_type == "observed-data":
            raw_alerts = self._alerts.search_alerts(size=limit)
            return [
                self._mapper.alert_to_stix_bundle(
                    self._alerts.normalise_alert(a)
                )
                for a in raw_alerts
            ]
        # Default: threat-intel indicators
        raw_indicators = self._ti.search_indicators(size=limit)
        return [
            self._mapper.ecs_indicator_to_stix(self._ti.normalise_indicator(doc))
            for doc in raw_indicators
        ]

    def upsert_object(self, stix_type: str, payload: dict, **kwargs) -> dict:
        """
        Index a STIX indicator into the Elastic TI data stream.

        Only ``"indicator"`` STIX type is supported; ``"observed-data"``
        alerts are read-only.
        """
        if stix_type == "observed-data":
            raise SAKClientError(
                "Elastic alerts are read-only; upsert is not supported for "
                "stix_type='observed-data'."
            )
        ecs_doc = self._mapper.stix_object_to_ecs_indicator(payload)
        return self._ti.index_indicator(ecs_doc)

    def delete_object(self, stix_type: str, object_id: str, **kwargs) -> None:
        """Delete a TI indicator by Elastic document ID."""
        if stix_type == "observed-data":
            raise SAKClientError(
                "Elastic alerts are read-only; delete is not supported for "
                "stix_type='observed-data'."
            )
        self._elastic.es_delete(
            f"{self._elastic.config.es_index_ti}/_doc/{object_id}"
        )

    def to_stix(self, native_object: dict) -> dict:
        """
        Convert a native Elastic document to a STIX object.

        Dispatches on ``native_object.get("event.kind")``:
        - ``"signal"`` / ``"alert"`` → ``observed-data`` via alert mapper
        - anything else → ECS threat indicator → STIX indicator
        """
        event_kind = (
            native_object.get("event", {}).get("kind")
            or native_object.get("event.kind", "")
        )
        if event_kind in ("signal", "alert"):
            return self._mapper.alert_to_stix_bundle(
                self._alerts.normalise_alert(native_object)
            )
        return self._mapper.ecs_indicator_to_stix(
            self._ti.normalise_indicator(native_object)
        )

    def from_stix(self, stix_dict: dict) -> dict:
        """Convert a STIX indicator SDO to an ECS threat-indicator document."""
        return self._mapper.stix_object_to_ecs_indicator(stix_dict)
