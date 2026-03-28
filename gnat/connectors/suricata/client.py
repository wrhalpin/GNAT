"""
gnat.connectors.suricata.client
=====================================

Suricata IDS/IPS connector (file-based — no HTTP API).

Suricata writes alerts in EVE JSON format (``/var/log/suricata/eve.json``).
This connector parses the EVE log and translates alerts to STIX 2.1
``observed-data`` bundles.

Configuration
-------------
::

    [suricata]
    eve_log_path = /var/log/suricata/eve.json

Notes
-----
* There is no Suricata REST API — all data comes from the EVE JSON log.
* ``upsert_object`` and ``delete_object`` are not supported.
* Use ``parse_eve_log()`` for bulk parsing or ``iter_stix_alerts()`` for
  a streaming STIX pipeline.
"""

from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SuricataClient(BaseClient, ConnectorMixin):
    """
    File-based connector for Suricata EVE JSON alert logs.

    Parameters
    ----------
    host : str
        Unused (pass ``""``).  Suricata has no HTTP API.
    eve_log_path : str, optional
        Path to the Suricata EVE JSON log.
    """

    stix_type_map: Dict[str, str] = {
        "observed-data": "alerts",
    }

    def __init__(
        self,
        host: str = "",
        eve_log_path: str = "/var/log/suricata/eve.json",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self.eve_log_path = eve_log_path

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No-op — Suricata has no HTTP API."""

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify the EVE log file exists and is readable."""
        path = Path(self.eve_log_path)
        if not path.exists():
            raise SAKClientError(
                f"Suricata EVE log not found: {self.eve_log_path}"
            )
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        raise SAKClientError(
            "Suricata is file-based — individual alert lookup by id is not supported."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Read alert events from the EVE JSON log.

        Parameters
        ----------
        filters : dict, optional
            * ``path``  — override log file path
            * ``limit`` — max alerts (default: page_size)

        Returns
        -------
        list of dict
            Normalised alert dicts.
        """
        filters = dict(filters or {})
        path  = filters.pop("path", self.eve_log_path)
        limit = filters.pop("limit", page_size)
        alerts = []
        for i, alert in enumerate(self._iter_alerts(path)):
            if i >= limit:
                break
            alerts.append(alert)
        return alerts

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise SAKClientError("Suricata is read-only — no write API available.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise SAKClientError("Suricata is read-only — no delete API available.")

    # ── Domain-specific operations ────────────────────────────────────────

    def parse_eve_log(
        self,
        path: Optional[str] = None,
        event_type: Optional[str] = "alert",
    ) -> List[Dict[str, Any]]:
        """
        Parse events from the EVE JSON log.

        Parameters
        ----------
        path : str, optional
            Override the configured ``eve_log_path``.
        event_type : str, optional
            Filter by ``event_type`` (e.g. ``"alert"``, ``"flow"``, ``"dns"``).
            ``None`` returns all event types.

        Returns
        -------
        list of dict
            Normalised event dicts.
        """
        return list(self._iter_alerts(path or self.eve_log_path, event_type=event_type))

    def iter_stix_alerts(
        self, path: Optional[str] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Yield STIX observed-data objects from the EVE log.

        Parameters
        ----------
        path : str, optional
            Override the configured ``eve_log_path``.
        """
        for alert in self._iter_alerts(path or self.eve_log_path, event_type="alert"):
            yield self.to_stix(alert)

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate a normalised Suricata alert to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            Normalised alert dict (from ``parse_eve_log()`` or raw EVE JSON).

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        alert = self._normalise(native)
        now   = _now_ts()
        ts    = alert.get("timestamp") or now

        objects: List[Dict[str, Any]] = []
        refs: List[str] = []
        seen: set = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append({
                        "type": "ipv4-addr",
                        "id":   ip_id,
                        "spec_version": "2.1",
                        "value": ip,
                    })
                refs.append(ip_id)

        src_ip = alert.get("src_ip")
        dst_ip = alert.get("dst_ip")
        src_p  = alert.get("src_port")
        dst_p  = alert.get("dst_port")
        if src_ip and dst_ip and (src_p or dst_p):
            key = f"{src_ip}:{src_p}-{dst_ip}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: Dict[str, Any] = {
                    "type": "network-traffic",
                    "id":   nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_p:
                    try:
                        nt["src_port"] = int(src_p)
                    except (TypeError, ValueError):
                        pass
                if dst_p:
                    try:
                        nt["dst_port"] = int(dst_p)
                    except (TypeError, ValueError):
                        pass
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        obs: Dict[str, Any] = {
            "type":           "observed-data",
            "id":             obs_id,
            "spec_version":   "2.1",
            "created":        now,
            "modified":       now,
            "first_observed": ts,
            "last_observed":  ts,
            "number_observed": 1,
            "object_refs":    refs,
            "x_suricata_alert": {
                "signature":    alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "category":     alert.get("category"),
                "severity":     alert.get("severity"),
                "severity_raw": alert.get("severity_raw"),
                "action":       alert.get("action"),
                "rev":          alert.get("rev"),
                "gid":          alert.get("gid"),
                "flow_id":      alert.get("flow_id"),
                "in_iface":     alert.get("in_iface"),
            },
        }
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Suricata is read-only — from_stix returns an informational dict."""
        return {
            "note":     "Suricata is file-based and read-only.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _iter_alerts(
        self,
        path: str,
        event_type: Optional[str] = "alert",
    ) -> Iterator[Dict[str, Any]]:
        """Yield normalised alert dicts from the EVE log."""
        log_path = Path(path)
        if not log_path.exists():
            raise SAKClientError(f"Suricata EVE log not found: {path}")
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event_type and event.get("event_type") != event_type:
                    continue
                yield self._normalise_event(event, sev_map)

    @staticmethod
    def _normalise_event(
        event: Dict[str, Any],
        sev_map: Dict[int, int],
    ) -> Dict[str, Any]:
        """Normalise a raw Suricata EVE JSON event."""
        alert_block = event.get("alert", {})
        sev_raw = int(alert_block.get("severity", 3))
        return {
            "timestamp":    event.get("timestamp"),
            "flow_id":      event.get("flow_id"),
            "in_iface":     event.get("in_iface"),
            "src_ip":       event.get("src_ip"),
            "src_port":     event.get("src_port"),
            "dst_ip":       event.get("dest_ip"),
            "dst_port":     event.get("dest_port"),
            "proto":        event.get("proto"),
            "signature":    alert_block.get("signature"),
            "signature_id": alert_block.get("signature_id"),
            "category":     alert_block.get("category"),
            "severity":     sev_map.get(sev_raw, 2),
            "severity_raw": sev_raw,
            "action":       alert_block.get("action"),
            "rev":          alert_block.get("rev"),
            "gid":          alert_block.get("gid"),
            "_raw":         event,
        }

    @staticmethod
    def _normalise(alert: Dict[str, Any]) -> Dict[str, Any]:
        """Pass-through for already-normalised alert dicts."""
        return alert
