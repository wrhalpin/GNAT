# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.snort.client
==================================

Snort IDS connector (file-based — no HTTP API).

Snort writes alerts to log files in either JSON (Snort 3) or fast-alert
text format (Snort 2).  This connector parses those files and translates
alerts to STIX 2.1 ``observed-data`` bundles.

Configuration
-------------
::

    [snort]
    alert_log_path = /var/log/snort/alert.json
    log_format     = json        # or: fast

Notes
-----
* There is no Snort REST API — all data comes from local log files.
* ``upsert_object`` and ``delete_object`` are not supported.
* ``list_objects`` raises ``GNATClientError``; use ``parse_log_file()``
  or the ``SnortLogReader`` from ``gnat.connectors.snort`` instead.
"""

from __future__ import annotations

import contextlib
import json
import re
import uuid as _uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Snort 2 fast alert pattern
_FAST_PATTERN = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"
    r"\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]"
    r"(?:\s+\[Classification:\s*(?P<classification>[^\]]+)\])?"
    r"\s+\[Priority:\s*(?P<priority>\d+)\]"
    r"\s+\{(?P<proto>\w+)\}"
    r"\s+(?P<src_ip>[\d.]+)(?::(?P<src_port>\d+))?"
    r"\s+->\s+(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?",
    re.IGNORECASE,
)


def _det_uuid(t: str, v: str) -> str:
    """Internal helper for det uuid."""
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SnortClient(BaseClient, ConnectorMixin):
    """
    File-based connector for Snort IDS alert logs.

    Parameters
    ----------
    host : str
        Unused (pass ``""``).  Snort has no HTTP API.
    alert_log_path : str, optional
        Path to the Snort alert log file.
    log_format : str
        ``"json"`` (Snort 3) or ``"fast"`` (Snort 2 fast alerts).
    """

    stix_type_map: dict[str, str] = {
        "observed-data": "alerts",
    }

    def __init__(
        self,
        host: str = "",
        alert_log_path: str = "/var/log/snort/alert.json",
        log_format: str = "json",
        **kwargs: Any,
    ):
        """Initialize SnortClient."""
        super().__init__(host=host, **kwargs)
        self.alert_log_path = alert_log_path
        self.log_format = log_format

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No-op — Snort has no HTTP API."""

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify the alert log file exists and is readable."""
        path = Path(self.alert_log_path)
        if not path.exists():
            raise GNATClientError(f"Snort alert log not found: {self.alert_log_path}")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        raise GNATClientError(
            "Snort is file-based — individual alert lookup by id is not supported."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Read alerts from the configured log file.

        Parameters
        ----------
        filters : dict, optional
            * ``path`` — override log file path
            * ``limit`` — max alerts to return (default: page_size)

        Returns
        -------
        list of dict
            Normalised alert dicts.
        """
        filters = dict(filters or {})
        path = filters.pop("path", self.alert_log_path)
        limit = filters.pop("limit", page_size)
        alerts = []
        for i, alert in enumerate(self._iter_alerts(path)):
            if i >= limit:
                break
            alerts.append(alert)
        return alerts

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Snort is read-only — no write API available.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Snort is read-only — no delete API available.")

    # ── Domain-specific operations ────────────────────────────────────────

    def parse_log_file(self, path: str | None = None) -> list[dict[str, Any]]:
        """
        Parse all alerts from the log file.

        Parameters
        ----------
        path : str, optional
            Override the configured ``alert_log_path``.

        Returns
        -------
        list of dict
            Normalised alert dicts.
        """
        return list(self._iter_alerts(path or self.alert_log_path))

    def iter_stix_alerts(self, path: str | None = None) -> Iterator[dict[str, Any]]:
        """
        Yield STIX observed-data objects from the log file.

        Parameters
        ----------
        path : str, optional
            Override the configured ``alert_log_path``.
        """
        for alert in self._iter_alerts(path or self.alert_log_path):
            yield self.to_stix(alert)

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a normalised Snort alert to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            Normalised alert dict (from ``parse_log_file()`` or raw JSON).

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        alert = self._normalise(native)
        now = _now_ts()
        ts = alert.get("timestamp") or now

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append(
                        {
                            "type": "ipv4-addr",
                            "id": ip_id,
                            "spec_version": "2.1",
                            "value": ip,
                        }
                    )
                refs.append(ip_id)

        src_ip = alert.get("src_ip")
        dst_ip = alert.get("dst_ip")
        src_p = alert.get("src_port")
        dst_p = alert.get("dst_port")
        if src_ip and dst_ip and (src_p or dst_p):
            key = f"{src_ip}:{src_p}-{dst_ip}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_port"] = int(src_p)
                if dst_p:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_port"] = int(dst_p)
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        obs: dict[str, Any] = {
            "type": "observed-data",
            "id": obs_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": refs,
            "x_snort_alert": {
                "signature": alert.get("signature"),
                "sid": alert.get("sid"),
                "gid": alert.get("gid"),
                "rev": alert.get("rev"),
                "classification": alert.get("classification"),
                "priority": alert.get("priority"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
            },
        }
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Snort is read-only — from_stix returns an informational dict."""
        return {
            "note": "Snort is file-based and read-only.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _iter_alerts(self, path: str) -> Iterator[dict[str, Any]]:
        """Yield normalised alerts from the log file."""
        log_path = Path(path)
        if not log_path.exists():
            raise GNATClientError(f"Snort alert log not found: {path}")
        if self.log_format == "json":
            yield from self._iter_json_alerts(log_path)
        else:
            yield from self._iter_fast_alerts(log_path)

    @staticmethod
    def _iter_json_alerts(path: Path) -> Iterator[dict[str, Any]]:
        """Yield normalised alerts from a Snort 3 JSON alert file."""
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                prio = int(raw.get("priority", 2))
                yield {
                    "timestamp": raw.get("timestamp"),
                    "gid": raw.get("gid"),
                    "sid": raw.get("sid"),
                    "rev": raw.get("rev"),
                    "signature": raw.get("msg"),
                    "classification": raw.get("classification"),
                    "priority": prio,
                    "severity": sev_map.get(prio, 2),
                    "proto": raw.get("proto"),
                    "src_ip": raw.get("src_addr"),
                    "src_port": raw.get("src_port"),
                    "dst_ip": raw.get("dst_addr"),
                    "dst_port": raw.get("dst_port"),
                    "action": raw.get("action"),
                    "_raw": raw,
                }

    @staticmethod
    def _iter_fast_alerts(path: Path) -> Iterator[dict[str, Any]]:
        """Yield normalised alerts from a Snort 2 fast-alert text file."""
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _FAST_PATTERN.match(line.strip())
                if not m:
                    continue
                prio = int(m.group("priority") or 2)
                yield {
                    "timestamp": m.group("timestamp"),
                    "gid": int(m.group("gid")),
                    "sid": int(m.group("sid")),
                    "rev": int(m.group("rev")),
                    "signature": m.group("msg").strip(),
                    "classification": m.group("classification"),
                    "priority": prio,
                    "severity": sev_map.get(prio, 2),
                    "proto": m.group("proto"),
                    "src_ip": m.group("src_ip"),
                    "src_port": int(m.group("src_port")) if m.group("src_port") else None,
                    "dst_ip": m.group("dst_ip"),
                    "dst_port": int(m.group("dst_port")) if m.group("dst_port") else None,
                    "_raw": {"line": line},
                }

    @staticmethod
    def _normalise(alert: dict[str, Any]) -> dict[str, Any]:
        """Pass-through for already-normalised alert dicts."""
        return alert
