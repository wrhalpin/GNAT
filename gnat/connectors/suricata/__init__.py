# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Suricata Connector
============================
Connector for Suricata IDS/IPS/NSM engine.

Suricata has no REST API. Integration patterns:
  1. EVE JSON log consumption (primary) — read alerts from eve.json
  2. Unix socket commands via suricatasc (runtime control)
  3. Redis/Kafka/Unix socket output (streaming)

This connector implements patterns 1 and 2.

EVE JSON format
---------------
Suricata writes all events to a single eve.json file in JSON-per-line
format. Key event types:
  alert    — IDS/IPS alert (most important for GNAT)
  flow     — network flow record
  dns      — DNS query/response
  http     — HTTP transaction
  tls      — TLS handshake
  fileinfo — file metadata
  stats    — engine statistics

Alert event key fields:
  timestamp, src_ip, src_port, dest_ip, dest_port, proto
  alert.signature, alert.signature_id, alert.category, alert.severity
  alert.action (allowed/blocked), alert.rev
  payload, payload_printable, packet

Unix socket (suricatasc)
------------------------
The suricatasc command-line tool communicates with the running Suricata
process via a Unix domain socket. GNAT wraps selected socket commands:
  dump-counters  — engine performance counters
  iface-stat     — interface statistics
  shutdown       — graceful shutdown
  reload-rules   — reload rule files

STIX: EVE alert events → STIX observed-data bundles.

Dev access: Completely free, open source.
  https://suricata.io/download/

Configuration (gnat.ini):
  [suricata]
  eve_log_path    = /var/log/suricata/eve.json
  socket_path     = /var/run/suricata/suricata-command.socket
  timeout         = 10
  tail_chunk_size = 65536   ; bytes to read per tail operation
"""

import configparser
import contextlib
import json
import os
import socket as _socket
import uuid as _uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from gnat.stix.version import CURRENT_SPEC_VERSION

# ── Exceptions ────────────────────────────────────────────────────────────────


class SuricataError(Exception):
    """Raised when a suricata error error occurs."""


class SuricataConfigError(SuricataError):
    """Raised when a suricata config error error occurs."""


class SuricataLogError(SuricataError):
    """Raised when a suricata log error error occurs."""


class SuricataSocketError(SuricataError):
    """Raised when a suricata socket error error occurs."""


class SuricataSTIXError(SuricataError):
    """Raised when a suricata s t i x error error occurs."""


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class SuricataConfig:
    """Configuration container for suricata."""

    eve_log_path: str = "/var/log/suricata/eve.json"
    socket_path: str = "/var/run/suricata/suricata-command.socket"
    timeout: int = 10
    tail_chunk_size: int = 65536

    def __post_init__(self):
        """Post-init setup for SuricataConfig."""
        if not self.eve_log_path:
            raise SuricataConfigError("'eve_log_path' required in [suricata].")


def load_suricata_config(
    config: configparser.ConfigParser, section: str = "suricata"
) -> SuricataConfig:
    """Load suricata config from the configured source."""
    if not config.has_section(section):
        raise SuricataConfigError(f"Section '[{section}]' not found.")
    raw = {
        "eve_log_path": "/var/log/suricata/eve.json",
        "socket_path": "/var/run/suricata/suricata-command.socket",
        "timeout": "10",
        "tail_chunk_size": "65536",
    }
    raw.update(dict(config.items(section)))
    return SuricataConfig(
        eve_log_path=raw["eve_log_path"].strip(),
        socket_path=raw["socket_path"].strip(),
        timeout=int(raw["timeout"]),
        tail_chunk_size=int(raw["tail_chunk_size"]),
    )


# ── EVE Log Reader ────────────────────────────────────────────────────────────


class SuricataEVEReader:
    """
    Reads and parses Suricata EVE JSON log files.

    EVE JSON is one JSON object per line. This reader supports:
      - Full file read (iter_events)
      - Alert-only filtering (iter_alerts)
      - Tail-from-offset for incremental ingestion (iter_events_from)
      - Parsing individual event lines

    Usage
    -----
        reader = SuricataEVEReader(config)
        for alert in reader.iter_alerts():
            process(alert)
    """

    def __init__(self, config: SuricataConfig):
        """Initialize SuricataEVEReader."""
        self.config = config

    def iter_events(
        self,
        event_type: str | None = None,
        path: str | None = None,
    ) -> Iterator[dict]:
        """
        Yield all events from the EVE JSON log file.

        Parameters
        ----------
        event_type : str | None
            Filter by event_type ('alert', 'flow', 'dns', 'http', etc.).
        path : str | None
            Override log file path.

        Yields
        ------
        dict
            Parsed EVE JSON event.

        Raises
        ------
        SuricataLogError
            If the log file cannot be opened.
        """
        log_path = path or self.config.eve_log_path
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event_type and event.get("event_type") != event_type:
                        continue
                    yield event
        except FileNotFoundError:
            raise SuricataLogError(
                f"EVE log not found: {log_path}. Ensure Suricata is running and eve-log is enabled."
            )
        except PermissionError:
            raise SuricataLogError(
                f"Permission denied reading {log_path}. Run GNAT with appropriate file permissions."
            )

    def iter_events_from(
        self,
        offset: int,
        event_type: str | None = None,
        path: str | None = None,
    ) -> tuple[Iterator[dict], int]:
        """
        Yield events starting from a byte offset (for incremental ingestion).

        Parameters
        ----------
        offset : int
            Byte offset to start reading from.
        event_type : str | None
            Event type filter.
        path : str | None
            Override log file path.

        Returns
        -------
        tuple[Iterator[dict], int]
            (event_generator, new_offset_after_reading)
        """
        log_path = path or self.config.eve_log_path
        try:
            file_size = os.path.getsize(log_path)
        except OSError:
            file_size = 0

        def _gen():
            """Internal helper for gen."""
            try:
                with open(log_path, encoding="utf-8", errors="replace") as f:
                    f.seek(offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if event_type and event.get("event_type") != event_type:
                            continue
                        yield event
            except (FileNotFoundError, PermissionError) as e:
                raise SuricataLogError(str(e)) from e

        return _gen(), file_size

    def iter_alerts(self, path: str | None = None) -> Iterator[dict]:
        """Yield only alert events from EVE log."""
        yield from self.iter_events(event_type="alert", path=path)

    def iter_flows(self, path: str | None = None) -> Iterator[dict]:
        """Yield only flow events."""
        yield from self.iter_events(event_type="flow", path=path)

    def iter_dns(self, path: str | None = None) -> Iterator[dict]:
        """Yield only DNS events."""
        yield from self.iter_events(event_type="dns", path=path)

    def get_log_size(self, path: str | None = None) -> int:
        """Return current EVE log file size in bytes."""
        log_path = path or self.config.eve_log_path
        try:
            return os.path.getsize(log_path)
        except OSError:
            return 0

    def count_alerts(self, path: str | None = None) -> int:
        """Count all alert events in the log file."""
        return sum(1 for _ in self.iter_alerts(path=path))

    @staticmethod
    def normalise_alert(event: dict) -> dict:
        """
        Flatten a Suricata EVE alert event to GNAT normalised format.

        Parameters
        ----------
        event : dict
            Raw EVE JSON alert event dict.

        Returns
        -------
        dict
        """
        alert = event.get("alert", {})
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}  # Suricata 1=high, 4=low
        sev_raw = int(alert.get("severity", 3))
        return {
            "timestamp": event.get("timestamp"),
            "flow_id": event.get("flow_id"),
            "in_iface": event.get("in_iface"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dst_ip": event.get("dest_ip"),
            "dst_port": event.get("dest_port"),
            "proto": event.get("proto"),
            "signature": alert.get("signature"),
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "severity": sev_map.get(sev_raw, 2),
            "severity_raw": sev_raw,
            "action": alert.get("action"),
            "rev": alert.get("rev"),
            "gid": alert.get("gid"),
            "metadata": alert.get("metadata", {}),
            "_raw": event,
        }


# ── Unix Socket Commands ──────────────────────────────────────────────────────


class SuricataSocketCommands:
    """
    Runtime control via Suricata Unix socket (suricatasc protocol).

    Requires Suricata to be started with unix-command enabled in suricata.yaml:
      unix-command:
        enabled: yes
        filename: /var/run/suricata/suricata-command.socket

    The protocol is simple JSON request/response:
      Request:  {"command": "<cmd>", "arguments": {...}}
      Response: {"return": "OK", "message": {...}}
    """

    def __init__(self, config: SuricataConfig):
        """Initialize SuricataSocketCommands."""
        self.config = config

    def _send_command(self, command: str, arguments: dict | None = None) -> dict:
        """Send a command via the Suricata Unix socket."""
        request = {"command": command}
        if arguments:
            request["arguments"] = arguments

        try:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect(self.config.socket_path)

            # Suricata expects newline-terminated JSON
            sock.sendall(json.dumps(request).encode() + b"\n")

            # Read response (may come in chunks)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            sock.close()

            return json.loads(data.decode("utf-8").strip())
        except FileNotFoundError:
            raise SuricataSocketError(
                f"Suricata socket not found: {self.config.socket_path}. "
                "Is Suricata running with unix-command enabled?"
            )
        except ConnectionRefusedError:
            raise SuricataSocketError("Cannot connect to Suricata socket. Is Suricata running?")
        except (_socket.timeout, OSError) as e:
            raise SuricataSocketError(f"Socket error: {e}") from e

    def get_counters(self) -> dict:
        """Retrieve Suricata performance counters."""
        return self._send_command("dump-counters")

    def get_iface_stats(self, iface: str | None = None) -> dict:
        """
        Get interface capture statistics.

        Parameters
        ----------
        iface : str | None
            Interface name. If None, returns all interfaces.
        """
        args = {"iface": iface} if iface else None
        return self._send_command("iface-stat", args)

    def reload_rules(self) -> dict:
        """Reload Suricata rules without restart."""
        return self._send_command("reload-rules")

    def get_version(self) -> dict:
        """Get Suricata engine version."""
        return self._send_command("version")

    def shutdown(self) -> dict:
        """Gracefully shut down the Suricata engine."""
        return self._send_command("shutdown")

    def is_running(self) -> bool:
        """Check whether the Suricata process is reachable via socket."""
        try:
            result = self.get_version()
            return result.get("return") == "OK"
        except SuricataSocketError:
            return False


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class SuricataSTIXMapper:
    """Maps Suricata EVE alert events to STIX 2.1 observed-data bundles."""

    def alert_to_stix_bundle(self, alert: dict) -> dict:
        """
        Convert a normalised Suricata alert to a STIX 2.1 bundle.

        Parameters
        ----------
        alert : dict
            Normalised alert from SuricataEVEReader.normalise_alert().

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now = _now_ts()
        ts = alert.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            if ip:
                obj = {
                    "type": "ipv4-addr",
                    "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}",
                    "spec_version": CURRENT_SPEC_VERSION,
                    "value": ip,
                }
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        src_p = alert.get("src_port")
        dst_p = alert.get("dst_port")
        if alert.get("src_ip") and alert.get("dst_ip") and (src_p or dst_p):
            key = f"{alert['src_ip']}:{src_p}-{alert['dst_ip']}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": CURRENT_SPEC_VERSION,
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['src_ip'])}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['dst_ip'])}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_p:
                    with contextlib.suppress(ValueError, TypeError):
                        nt["src_port"] = int(src_p)
                if dst_p:
                    with contextlib.suppress(ValueError, TypeError):
                        nt["dst_port"] = int(dst_p)
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        objects.append(
            {
                "type": "observed-data",
                "id": obs_id,
                "spec_version": CURRENT_SPEC_VERSION,
                "created": now,
                "modified": now,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_suricata_alert": {
                    "signature": alert.get("signature"),
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "severity_raw": alert.get("severity_raw"),
                    "action": alert.get("action"),
                    "rev": alert.get("rev"),
                    "in_iface": alert.get("in_iface"),
                    "flow_id": alert.get("flow_id"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": objects,
        }

    def alerts_to_stix_bundle(self, alerts: list[dict]) -> dict:
        """Convert multiple alerts to a single deduplicated bundle."""
        all_objects: list[dict] = []
        seen: set[str] = set()
        for a in alerts:
            for obj in self.alert_to_stix_bundle(a).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": CURRENT_SPEC_VERSION,
            "objects": all_objects,
        }


def _det_uuid(t: str, v: str) -> str:
    """Internal helper for det uuid."""
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
