# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.connector
================================
ConnectorMixin facade for the MISP connector.

Wraps MISPClient + domain command objects in the standard GNAT interface.
MISP events are the primary first-class object; attributes are accessed
through events. upsert_object creates or updates a MISP event.
"""

from __future__ import annotations

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

from .client import MISPClient
from .config import MISPConfig
from .events import MISPEventCommands
from .stix_mapper import MISPSTIXMapper


class MISPConnector(BaseClient, ConnectorMixin):
    """
    GNAT connector for MISP Threat Sharing.

    Implements the standard ConnectorMixin interface on top of the rich
    MISPClient transport. MISP events map to STIX report bundles;
    individual attributes map to STIX SCOs / indicator SDOs.

    Parameters
    ----------
    host : str
        MISP base URL, e.g. ``"https://misp.internal"`` or just a hostname.
    api_key : str
        MISP API key (``Authorization`` header value).
    verify_ssl : bool
        TLS certificate verification. Default ``True``.
    timeout : float
        Request timeout in seconds. Default ``30``.
    """

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        verify_ssl: bool = True,
        timeout: float = 30.0,
        **kwargs,
    ) -> None:
        """Initialize MISPConnector."""
        super().__init__(host=host, verify_ssl=verify_ssl, timeout=timeout)
        url = host if host.startswith(("http://", "https://")) else f"https://{host}"
        cfg = MISPConfig(
            url=url,
            api_key=api_key,
            verify_ssl=bool(verify_ssl),
            timeout=int(float(timeout)),
        )
        self._misp = MISPClient(cfg)
        self._events = MISPEventCommands(self._misp)
        self._mapper = MISPSTIXMapper()

    # ── ConnectorMixin interface ──────────────────────────────────────────

    def authenticate(self) -> None:
        """No explicit auth step — API key is injected per-request."""
        self._authenticated = True

    def health_check(self) -> bool:
        """Return True if the MISP instance is reachable (users/view/me)."""
        try:
            self._misp.get_json("users/view/me")
            return True
        except Exception as exc:
            raise GNATClientError(f"MISP health check failed: {exc}") from exc

    def get_object(self, stix_type: str, object_id: str, **kwargs) -> dict:
        """
        Fetch a MISP event by ID and return as a STIX bundle dict.

        Parameters
        ----------
        stix_type : str
            Ignored — MISP objects are always returned as STIX report bundles.
        object_id : str
            MISP event ID (integer string) or UUID.
        """
        raw = self._events.get_event(object_id)
        norm = self._events.normalise_event(raw)
        return self._mapper.event_to_stix_bundle(norm, norm.get("attributes", []))

    def list_objects(
        self,
        stix_type: str | None = None,
        limit: int = 100,
        **kwargs,
    ) -> list[dict]:
        """
        Return a list of MISP events as STIX report bundle dicts.

        Parameters
        ----------
        stix_type : str | None
            Ignored — MISP events are always returned as STIX report bundles.
        limit : int
            Maximum number of events. Default 100.
        """
        events = self._events.list_events(limit=limit)
        results = []
        for raw in events:
            norm = self._events.normalise_event(raw)
            results.append(self._mapper.event_to_stix_bundle(norm, norm.get("attributes", [])))
        return results

    def upsert_object(self, stix_type: str, payload: dict, **kwargs) -> dict:
        """
        Create a MISP event from a STIX bundle dict, or update if it exists.

        Parameters
        ----------
        stix_type : str
            Ignored — input is always treated as a STIX bundle.
        payload : dict
            STIX 2.1 bundle dict.
        """
        event_dict = self._mapper.stix_bundle_to_misp_event(payload)
        event_id = event_dict.get("uuid") or event_dict.get("id")
        if event_id:
            try:
                existing = self._events.get_event(event_id)
                if existing:
                    return self._events.update_event(event_id, event_dict)
            except Exception:
                pass
        return self._events.create_event(event_dict)

    def delete_object(self, stix_type: str, object_id: str, **kwargs) -> None:
        """Delete a MISP event by ID."""
        self._events.delete_event(object_id)

    def to_stix(self, native_object: dict) -> dict:
        """
        Convert a native MISP event dict to a STIX report bundle.

        Parameters
        ----------
        native_object : dict
            Raw MISP event dict (as returned by the MISP API).
        """
        norm = self._events.normalise_event(native_object)
        return self._mapper.event_to_stix_bundle(norm, norm.get("attributes", []))

    def from_stix(self, stix_dict: dict) -> dict:
        """Convert a STIX bundle dict to a MISP event creation dict."""
        return self._mapper.stix_bundle_to_misp_event(stix_dict)
