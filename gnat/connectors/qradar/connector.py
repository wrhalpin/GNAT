# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.qradar.connector
==================================
ConnectorMixin facade for the IBM QRadar SIEM connector.

Wraps QRadarClient + domain command objects in the standard GNAT interface.

STIX type routing
-----------------
list_objects / get_object dispatch on stix_type:
  "observed-data"  → QRadarOffenseCommands (SIEM offenses)
  "indicator"      → QRadarReferenceDataCommands (read from reference sets)
  None             → defaults to observed-data (offenses)

upsert_object for "indicator" ingests IOCs into QRadar reference sets.
Offenses are read-only (QRadar manages offense lifecycle internally).
"""

from __future__ import annotations

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

from .client import QRadarClient
from .config import QRadarConfig
from .offenses import QRadarOffenseCommands
from .reference_data import QRadarReferenceDataCommands
from .stix_mapper import QRadarSTIXMapper


class QRadarConnector(BaseClient, ConnectorMixin):
    """
    GNAT connector for IBM QRadar SIEM.

    Implements the standard ConnectorMixin interface on top of the rich
    QRadarClient transport. QRadar offenses map to STIX ``observed-data``
    bundles. IOC ingestion uses QRadar reference sets.

    Parameters
    ----------
    host : str
        QRadar console hostname or IP, e.g. ``"qradar.internal"``.
    token : str
        Authorized Service token (UUID string from QRadar admin console).
    verify_ssl : bool
        TLS certificate verification. Default ``True``.
    timeout : float
        Request timeout in seconds. Default ``30``.
    """

    def __init__(
        self,
        host: str = "",
        token: str = "",
        verify_ssl: bool = True,
        timeout: float = 30.0,
        **kwargs,
    ) -> None:
        super().__init__(host=host, verify_ssl=verify_ssl, timeout=timeout)
        cfg = QRadarConfig(
            host=host,
            token=token,
            verify_ssl=bool(verify_ssl),
            timeout=int(float(timeout)),
        )
        self._qradar = QRadarClient(cfg)
        self._offenses = QRadarOffenseCommands(self._qradar)
        self._refdata = QRadarReferenceDataCommands(self._qradar)
        self._mapper = QRadarSTIXMapper()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """No explicit auth step — SEC token is injected per-request."""
        self._authenticated = True

    def health_check(self) -> bool:
        """Return True if QRadar is reachable (GET /api/system/about)."""
        try:
            self._qradar.get("system/about")
            return True
        except Exception as exc:
            raise GNATClientError(f"QRadar health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs) -> dict:
        """
        Fetch a QRadar offense by ID as a STIX observed-data bundle.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` (offense) is the primary supported type.
        object_id : str
            QRadar offense ID (integer string).
        """
        if stix_type == "indicator":
            raise GNATClientError(
                "QRadar reference sets do not support single-item lookup by ID. "
                "Use list_objects(stix_type='indicator') to retrieve all IOCs."
            )
        raw = self._offenses.get_offense(int(object_id))
        norm = self._offenses.normalise_offense(raw)
        return self._mapper.offense_to_stix_bundle(norm)

    def list_objects(
        self,
        stix_type: str | None = None,
        limit: int = 50,
        **kwargs,
    ) -> list[dict]:
        """
        Return a list of STIX objects.

        Parameters
        ----------
        stix_type : str | None
            ``"observed-data"`` (offenses, default) or ``"indicator"``
            (reference set IOCs).
        limit : int
            Maximum results. Default 50.
        """
        if stix_type == "indicator":
            sets = self._refdata.list_sets()
            results = []
            for ref_set in sets[:limit]:
                results.append(
                    {
                        "type": "indicator",
                        "id": f"indicator--{ref_set.get('name', '')}",
                        "name": ref_set.get("name", ""),
                        "x_qradar_set": ref_set,
                    }
                )
            return results
        # Default: offenses → observed-data
        offenses = self._offenses.list_offenses(limit=limit)
        return [
            self._mapper.offense_to_stix_bundle(self._offenses.normalise_offense(o))
            for o in offenses
        ]

    def upsert_object(self, stix_type: str, payload: dict, **kwargs) -> dict:
        """
        Ingest a STIX bundle into QRadar reference sets.

        Extracts IOC values from the bundle and adds them to the appropriate
        QRadar reference set (IP set, domain set, hash set).

        Parameters
        ----------
        stix_type : str
            Must be ``"indicator"``; offenses are read-only.
        payload : dict
            STIX 2.1 bundle or indicator SDO.
        """
        if stix_type == "observed-data":
            raise GNATClientError(
                "QRadar offenses are read-only; upsert is not supported for "
                "stix_type='observed-data'."
            )
        ioc_groups = self._mapper.stix_bundle_to_reference_sets(payload)
        results = {}
        for set_type, values in ioc_groups.items():
            set_name = f"GNAT_{set_type.upper()}"
            self._refdata.ensure_set_exists(set_name, element_type="ALN")
            for value in values:
                self._refdata.add_set_value(set_name, str(value))
            results[set_name] = len(values)
        return results

    def delete_object(self, stix_type: str, object_id: str, **kwargs) -> None:
        """Delete a value from a QRadar reference set."""
        if stix_type == "observed-data":
            raise GNATClientError(
                "QRadar offenses cannot be deleted via the API. "
                "Use close_offense() on the underlying client instead."
            )
        raise GNATClientError(
            "delete_object for QRadar reference sets requires set_name and value. "
            "Use the underlying _refdata client directly."
        )

    def to_stix(self, native_object: dict) -> dict:
        """
        Convert a native QRadar offense dict to a STIX observed-data bundle.

        Parameters
        ----------
        native_object : dict
            Raw QRadar offense dict.
        """
        norm = self._offenses.normalise_offense(native_object)
        return self._mapper.offense_to_stix_bundle(norm)

    def from_stix(self, stix_dict: dict) -> dict:
        """
        Convert a STIX bundle to QRadar reference set IOC groups.

        Returns a dict of ``{set_type: [values]}`` for use with
        QRadarReferenceDataCommands.
        """
        return self._mapper.stix_bundle_to_reference_sets(stix_dict)
