"""
CTM-SAK Snort Connector
=========================
Connector for Snort IDS/IPS (v2.x and v3.x).

Snort has no REST API. Integration is via log file consumption:
  - Snort v2: unified2 binary logs + fast/full/syslog text alerts
  - Snort v3: JSON alert output (alert_json), syslog, fast text alerts

This connector focuses on:
  1. Snort 3 JSON alert log parsing (alert_json plugin output)
  2. Snort 2 fast alert text log parsing
  3. Rule file inspection (read-only)

Snort 3 JSON alert format
--------------------------
When configured with alert_json, Snort 3 writes one JSON object per line:
{
  "timestamp": "01/15-12:00:00.123456",
  "gid": 1, "sid": 1000001, "rev": 1,
  "msg": "ET MALWARE C2 Traffic",
  "proto": "TCP",
  "src_addr": "192.168.1.100", "src_port": 49152,
  "dst_addr": "1.2.3.4", "dst_port": 443,
  "action": "alert",
  "priority": 2,
  "classification": "Potential Corporate Privacy Violation",
  "service": "https"
}

Snort 2 fast alert text format (one line per alert):
  MM/DD-HH:MM:SS.uuuuuu  [**] [GID:SID:REV] MSG [**] [Priority: N] {PROTO} SRC:PORT -> DST:PORT

STIX: Alert events → STIX observed-data bundles.

Dev access: Completely free, open source.
  https://www.snort.org/downloads

Configuration (ctm_sak.ini):
  [snort]
  alert_log_path  = /var/log/snort/alert_json.txt
  log_format      = json      ; 'json' (Snort 3) or 'fast' (Snort 2)
  timeout         = 10
"""

import configparser
import json
import os
import re
from dataclasses import dataclass
from typing import Iterator
import uuid as _uuid
from datetime import datetime, timezone


# ── Exceptions ────────────────────────────────────────────────────────────────

class SnortError(Exception):
    pass

class SnortConfigError(SnortError):
    pass

class SnortLogError(SnortError):
    pass

class SnortSTIXError(SnortError):
    pass


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class SnortConfig:
    alert_log_path: str = "/var/log/snort/alert_json.txt"
    log_format: str = "json"      # 'json' or 'fast'
    timeout: int = 10

    def __post_init__(self):
        if not self.alert_log_path:
            raise SnortConfigError("'alert_log_path' required in [snort].")
        if self.log_format not in ("json", "fast"):
            raise SnortConfigError("'log_format' must be 'json' or 'fast'.")


def load_snort_config(
    config: configparser.ConfigParser, section: str = "snort"
) -> SnortConfig:
    if not config.has_section(section):
        raise SnortConfigError(f"Section '[{section}]' not found.")
    raw = {
        "alert_log_path": "/var/log/snort/alert_json.txt",
        "log_format": "json",
        "timeout": "10",
    }
    raw.update(dict(config.items(section)))
    return SnortConfig(
        alert_log_path=raw["alert_log_path"].strip(),
        log_format=raw["log_format"].strip().lower(),
        timeout=int(raw["timeout"]),
    )


# ── Snort 3 JSON Alert Reader ─────────────────────────────────────────────────

class SnortJSONReader:
    """
    Reads Snort 3 JSON alert log output (alert_json plugin).

    Snort 3 alert_json configuration (snort.lua):
      alert_json = {
        file = true,
        fields = 'timestamp gid sid rev msg proto src_addr src_port
                  dst_addr dst_port action priority classification'
      }
    """

    def __init__(self, config: SnortConfig):
        self.config = config

    def iter_alerts(self, path: str | None = None) -> Iterator[dict]:
        """
        Yield parsed alert objects from the JSON log.

        Parameters
        ----------
        path : str | None
            Override log file path.

        Yields
        ------
        dict
            Parsed alert dict.
        """
        log_path = path or self.config.alert_log_path
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            raise SnortLogError(
                f"Snort alert log not found: {log_path}. "
                "Ensure Snort is running and alert_json is enabled."
            )

    def iter_alerts_from(self, offset: int, path: str | None = None):
        """Yield alerts from a byte offset (incremental ingestion)."""
        log_path = path or self.config.alert_log_path
        new_offset = offset
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                for line in f:
                    new_offset += len(line.encode("utf-8"))
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            raise SnortLogError(f"Alert log not found: {log_path}")
        return new_offset

    def count_alerts(self, path: str | None = None) -> int:
        return sum(1 for _ in self.iter_alerts(path=path))

    def get_log_size(self, path: str | None = None) -> int:
        try:
            return os.path.getsize(path or self.config.alert_log_path)
        except OSError:
            return 0

    @staticmethod
    def normalise_alert(alert: dict) -> dict:
        """Flatten a Snort 3 JSON alert to CTM-SAK normalised format."""
        prio = int(alert.get("priority", 2))
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}
        return {
            "timestamp": alert.get("timestamp"),
            "gid": alert.get("gid"),
            "sid": alert.get("sid"),
            "rev": alert.get("rev"),
            "signature": alert.get("msg"),
            "classification": alert.get("classification"),
            "priority": prio,
            "severity": sev_map.get(prio, 2),
            "proto": alert.get("proto"),
            "src_ip": alert.get("src_addr"),
            "src_port": alert.get("src_port"),
            "dst_ip": alert.get("dst_addr"),
            "dst_port": alert.get("dst_port"),
            "action": alert.get("action"),
            "service": alert.get("service"),
            "_raw": alert,
        }


# ── Snort 2 Fast Alert Reader ─────────────────────────────────────────────────

# Snort 2 fast alert pattern:
# 01/15-12:00:00.123456  [**] [1:1000001:1] ET MALWARE [**] [Priority: 2] {TCP} 192.168.1.1:49152 -> 1.2.3.4:443
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


class SnortFastReader:
    """Reads Snort 2 fast alert text log format."""

    def __init__(self, config: SnortConfig):
        self.config = config

    def iter_alerts(self, path: str | None = None) -> Iterator[dict]:
        """Yield parsed alerts from fast alert text log."""
        log_path = path or self.config.alert_log_path
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    alert = self._parse_fast_line(line.strip())
                    if alert:
                        yield alert
        except FileNotFoundError:
            raise SnortLogError(f"Snort fast alert log not found: {log_path}")

    def count_alerts(self, path: str | None = None) -> int:
        return sum(1 for _ in self.iter_alerts(path=path))

    @staticmethod
    def _parse_fast_line(line: str) -> dict | None:
        m = _FAST_PATTERN.match(line)
        if not m:
            return None
        prio = int(m.group("priority") or 2)
        sev_map = {1: 4, 2: 3, 3: 2, 4: 1}
        return {
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


# ── Alert Reader Factory ──────────────────────────────────────────────────────

class SnortAlertReader:
    """
    Factory that returns the appropriate reader based on log_format config.

    Usage
    -----
        reader = SnortAlertReader(config)
        for alert in reader.iter_alerts():
            process(alert)
    """

    def __init__(self, config: SnortConfig):
        self.config = config
        if config.log_format == "json":
            self._reader = SnortJSONReader(config)
        else:
            self._reader = SnortFastReader(config)

    def iter_alerts(self, path: str | None = None) -> Iterator[dict]:
        yield from self._reader.iter_alerts(path=path)

    def count_alerts(self, path: str | None = None) -> int:
        return self._reader.count_alerts(path=path)

    @staticmethod
    def normalise_alert(alert: dict) -> dict:
        """Normalise works for both JSON and fast format (same output keys)."""
        return SnortJSONReader.normalise_alert(alert)


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class SnortSTIXMapper:
    """Maps Snort alert events to STIX 2.1 observed-data bundles."""

    def alert_to_stix_bundle(self, alert: dict) -> dict:
        """Convert a normalised Snort alert to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = alert.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (alert.get("src_ip"), alert.get("dst_ip")):
            if ip:
                obj = {"type": "ipv4-addr",
                       "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}",
                       "spec_version": "2.1", "value": ip}
                if obj["id"] not in seen:
                    seen.add(obj["id"]); objects.append(obj)
                refs.append(obj["id"])

        src_p = alert.get("src_port")
        dst_p = alert.get("dst_port")
        if alert.get("src_ip") and alert.get("dst_ip") and (src_p or dst_p):
            key = f"{alert['src_ip']}:{src_p}-{alert['dst_ip']}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic", "id": nid, "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['src_ip'])}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', alert['dst_ip'])}",
                    "protocols": [str(alert.get("proto", "tcp")).lower()],
                }
                if src_p:
                    try: nt["src_port"] = int(src_p)
                    except (TypeError, ValueError): pass
                if dst_p:
                    try: nt["dst_port"] = int(dst_p)
                    except (TypeError, ValueError): pass
                objects.append(nt); refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        objects.append({
            "type": "observed-data", "id": obs_id, "spec_version": "2.1",
            "created": now, "modified": now,
            "first_observed": ts, "last_observed": ts, "number_observed": 1,
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
        })
        return {"type": "bundle", "id": f"bundle--{_uuid.uuid4()}",
                "spec_version": "2.1", "objects": objects}

    def alerts_to_stix_bundle(self, alerts: list[dict]) -> dict:
        all_objects: list[dict] = []
        seen: set[str] = set()
        for a in alerts:
            for obj in self.alert_to_stix_bundle(a).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"]); all_objects.append(obj)
        return {"type": "bundle", "id": f"bundle--{_uuid.uuid4()}",
                "spec_version": "2.1", "objects": all_objects}


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
