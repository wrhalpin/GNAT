# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Zeek Connector
========================
Connector for Zeek (formerly Bro) Network Analysis Framework.

Zeek has no REST API. Integration is via log file consumption.
Zeek writes structured logs for every protocol and event it observes.

Log formats supported by GNAT:
  1. JSON (zeek-cut or json-logs plugin) — preferred, one JSON per line
  2. TSV (default Zeek format) — tab-separated with header comments

Key Zeek log files
------------------
  conn.log     — all network connections (most important)
  dns.log      — DNS queries/responses
  http.log     — HTTP transactions
  ssl.log      — TLS/SSL sessions
  weird.log    — unexpected protocol behaviours
  notice.log   — Zeek framework notices (similar to IDS alerts)
  intel.log    — threat intelligence hits (from Intel framework)
  files.log    — file analysis records
  x509.log     — certificate analysis

conn.log key fields (TSV format):
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  proto, service, duration, orig_bytes, resp_bytes,
  conn_state, local_orig, local_resp, missed_bytes, history

notice.log key fields (GNAT priority):
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  fuid, file_mime_type, file_desc, proto, note, msg,
  sub, src, dst, p, n, peer_descr, actions, suppress_for, dropped

STIX: notice.log and conn.log events → STIX observed-data bundles.

Dev access: Completely free, open source.
  https://zeek.org/get-zeek/

Configuration (gnat.ini):
  [zeek]
  log_dir       = /var/log/zeek/current
  log_format    = tsv      ; 'tsv' or 'json'
  timeout       = 10
"""

import configparser
import contextlib
import json
import os
import uuid as _uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

# ── Exceptions ────────────────────────────────────────────────────────────────


class ZeekError(Exception):
    pass


class ZeekConfigError(ZeekError):
    pass


class ZeekLogError(ZeekError):
    pass


class ZeekSTIXError(ZeekError):
    pass


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class ZeekConfig:
    log_dir: str = "/var/log/zeek/current"
    log_format: str = "tsv"  # 'tsv' or 'json'
    timeout: int = 10

    def __post_init__(self):
        if not self.log_dir:
            raise ZeekConfigError("'log_dir' required in [zeek].")
        if self.log_format not in ("tsv", "json"):
            raise ZeekConfigError("'log_format' must be 'tsv' or 'json'.")

    def log_path(self, log_name: str) -> str:
        """Build full path to a Zeek log file."""
        ext = "log" if self.log_format == "tsv" else "json"
        return os.path.join(self.log_dir, f"{log_name}.{ext}")


def load_zeek_config(config: configparser.ConfigParser, section: str = "zeek") -> ZeekConfig:
    if not config.has_section(section):
        raise ZeekConfigError(f"Section '[{section}]' not found.")
    raw = {"log_dir": "/var/log/zeek/current", "log_format": "tsv", "timeout": "10"}
    raw.update(dict(config.items(section)))
    return ZeekConfig(
        log_dir=raw["log_dir"].strip(),
        log_format=raw["log_format"].strip().lower(),
        timeout=int(raw["timeout"]),
    )


# ── TSV Log Reader ────────────────────────────────────────────────────────────


class ZeekTSVReader:
    """
    Reads Zeek TSV log files (default format).

    Zeek TSV files have comment headers:
      #separator \\t
      #set_separator ,
      #empty_field (empty)
      #unset_field -
      #path conn
      #fields ts uid id.orig_h id.orig_p ...
      #types time string addr port ...
      (data lines follow)
    """

    def __init__(self, config: ZeekConfig):
        self.config = config

    def iter_records(
        self,
        log_name: str,
        path: str | None = None,
    ) -> Iterator[dict]:
        """
        Yield parsed records from a Zeek TSV log file.

        Parameters
        ----------
        log_name : str
            Log name without extension, e.g. 'conn', 'notice', 'dns'.
        path : str | None
            Override full file path.

        Yields
        ------
        dict
            Record with field names as keys.
        """
        log_path = path or self.config.log_path(log_name)
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                fields: list[str] = []
                separator = "\t"
                unset = "-"
                empty = "(empty)"

                for line in f:
                    line = line.rstrip("\n")
                    if line.startswith("#separator"):
                        sep_str = line.split(" ", 1)[1].strip()
                        separator = sep_str.encode("utf-8").decode("unicode_escape")
                    elif line.startswith("#unset_field"):
                        unset = line.split(" ", 1)[1].strip()
                    elif line.startswith("#empty_field"):
                        empty = line.split(" ", 1)[1].strip()
                    elif line.startswith("#fields"):
                        fields = line.split(separator)[1:]
                    elif line.startswith("#"):
                        continue
                    elif fields:
                        values = line.split(separator)
                        record: dict = {}
                        for i, field in enumerate(fields):
                            val = values[i] if i < len(values) else unset
                            record[field] = None if val in (unset, empty) else val
                        yield record

        except FileNotFoundError:
            raise ZeekLogError(
                f"Zeek log not found: {log_path}. "
                "Ensure Zeek is running and logging to this directory."
            )

    def count_records(self, log_name: str) -> int:
        return sum(1 for _ in self.iter_records(log_name))


# ── JSON Log Reader ───────────────────────────────────────────────────────────


class ZeekJSONReader:
    """Reads Zeek JSON log files (json-logs package or zeek-cut -j output)."""

    def __init__(self, config: ZeekConfig):
        self.config = config

    def iter_records(self, log_name: str, path: str | None = None) -> Iterator[dict]:
        log_path = path or self.config.log_path(log_name)
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            raise ZeekLogError(f"Zeek JSON log not found: {log_path}")

    def count_records(self, log_name: str) -> int:
        return sum(1 for _ in self.iter_records(log_name))


# ── High-level Log Commands ───────────────────────────────────────────────────


class ZeekLogCommands:
    """
    High-level interface for reading Zeek log files.
    Dispatches to TSV or JSON reader based on config.

    Usage
    -----
        reader = ZeekLogCommands(config)
        for notice in reader.iter_notices():
            process(notice)
    """

    def __init__(self, config: ZeekConfig):
        self.config = config
        if config.log_format == "json":
            self._reader = ZeekJSONReader(config)
        else:
            self._reader = ZeekTSVReader(config)

    def iter_records(self, log_name: str, path: str | None = None) -> Iterator[dict]:
        yield from self._reader.iter_records(log_name, path=path)

    def iter_notices(self, path: str | None = None) -> Iterator[dict]:
        """Yield all notice.log records (closest to IDS alerts)."""
        yield from self.iter_records("notice", path=path)

    def iter_connections(self, path: str | None = None) -> Iterator[dict]:
        """Yield all conn.log connection records."""
        yield from self.iter_records("conn", path=path)

    def iter_dns(self, path: str | None = None) -> Iterator[dict]:
        """Yield all dns.log records."""
        yield from self.iter_records("dns", path=path)

    def iter_http(self, path: str | None = None) -> Iterator[dict]:
        """Yield all http.log records."""
        yield from self.iter_records("http", path=path)

    def iter_ssl(self, path: str | None = None) -> Iterator[dict]:
        """Yield all ssl.log records."""
        yield from self.iter_records("ssl", path=path)

    def iter_intel_hits(self, path: str | None = None) -> Iterator[dict]:
        """Yield all intel.log records (IOC matches from Intel framework)."""
        yield from self.iter_records("intel", path=path)

    def iter_weird(self, path: str | None = None) -> Iterator[dict]:
        """Yield weird.log records (protocol anomalies)."""
        yield from self.iter_records("weird", path=path)

    def list_available_logs(self) -> list[str]:
        """Return names of Zeek log files present in log_dir."""
        try:
            ext = "log" if self.config.log_format == "tsv" else "json"
            return [
                f.replace(f".{ext}", "")
                for f in os.listdir(self.config.log_dir)
                if f.endswith(f".{ext}") and not f.startswith(".")
            ]
        except OSError:
            return []

    @staticmethod
    def normalise_notice(record: dict) -> dict:
        """Flatten a Zeek notice.log record to GNAT normalised format."""
        return {
            "timestamp": record.get("ts"),
            "uid": record.get("uid"),
            "src_ip": record.get("id.orig_h") or record.get("src"),
            "src_port": record.get("id.orig_p"),
            "dst_ip": record.get("id.resp_h") or record.get("dst"),
            "dst_port": record.get("id.resp_p"),
            "proto": record.get("proto"),
            "note": record.get("note"),
            "message": record.get("msg"),
            "sub": record.get("sub"),
            "actions": record.get("actions"),
            "dropped": record.get("dropped") == "T",
            "_raw": record,
        }

    @staticmethod
    def normalise_connection(record: dict) -> dict:
        """Flatten a Zeek conn.log record to GNAT normalised format."""
        return {
            "timestamp": record.get("ts"),
            "uid": record.get("uid"),
            "src_ip": record.get("id.orig_h"),
            "src_port": record.get("id.orig_p"),
            "dst_ip": record.get("id.resp_h"),
            "dst_port": record.get("id.resp_p"),
            "proto": record.get("proto"),
            "service": record.get("service"),
            "duration": record.get("duration"),
            "orig_bytes": record.get("orig_bytes"),
            "resp_bytes": record.get("resp_bytes"),
            "conn_state": record.get("conn_state"),
            "history": record.get("history"),
            "_raw": record,
        }


# ── STIX Mapper ───────────────────────────────────────────────────────────────

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class ZeekSTIXMapper:
    """Maps Zeek log records to STIX 2.1 objects."""

    def notice_to_stix_bundle(self, notice: dict) -> dict:
        """Convert a normalised Zeek notice record to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = notice.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        for ip in (notice.get("src_ip"), notice.get("dst_ip")):
            if ip:
                obj = {
                    "type": "ipv4-addr",
                    "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}",
                    "spec_version": "2.1",
                    "value": ip,
                }
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        src_p = notice.get("src_port")
        dst_p = notice.get("dst_port")
        if notice.get("src_ip") and notice.get("dst_ip") and (src_p or dst_p):
            key = f"{notice['src_ip']}:{src_p}-{notice['dst_ip']}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', notice['src_ip'])}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', notice['dst_ip'])}",
                    "protocols": [str(notice.get("proto", "tcp")).lower()],
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
        objects.append(
            {
                "type": "observed-data",
                "id": obs_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_zeek_notice": {
                    "uid": notice.get("uid"),
                    "note": notice.get("note"),
                    "message": notice.get("message"),
                    "sub": notice.get("sub"),
                    "actions": notice.get("actions"),
                    "dropped": notice.get("dropped"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def connection_to_stix_bundle(self, conn: dict) -> dict:
        """Convert a normalised Zeek conn record to a STIX 2.1 bundle."""
        now = _now_ts()
        ts = conn.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        src = conn.get("src_ip")
        dst = conn.get("dst_ip")
        for ip in (src, dst):
            if ip:
                obj = {
                    "type": "ipv4-addr",
                    "id": f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}",
                    "spec_version": "2.1",
                    "value": ip,
                }
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        if src and dst:
            sp = conn.get("src_port")
            dp = conn.get("dst_port")
            key = f"{src}:{sp}-{dst}:{dp}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": "2.1",
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst)}",
                    "protocols": [str(conn.get("proto", "tcp")).lower()],
                }
                if sp:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_port"] = int(sp)
                if dp:
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_port"] = int(dp)
                if conn.get("orig_bytes"):
                    with contextlib.suppress(TypeError, ValueError):
                        nt["src_byte_count"] = int(conn["orig_bytes"])
                if conn.get("resp_bytes"):
                    with contextlib.suppress(TypeError, ValueError):
                        nt["dst_byte_count"] = int(conn["resp_bytes"])
                objects.append(nt)
                refs.append(nid)

        obs_id = f"observed-data--{_uuid.uuid4()}"
        objects.append(
            {
                "type": "observed-data",
                "id": obs_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_zeek_conn": {
                    "uid": conn.get("uid"),
                    "service": conn.get("service"),
                    "duration": conn.get("duration"),
                    "conn_state": conn.get("conn_state"),
                    "history": conn.get("history"),
                },
            }
        )
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def notices_to_stix_bundle(self, notices: list[dict]) -> dict:
        all_objects: list[dict] = []
        seen: set[str] = set()
        for n in notices:
            for obj in self.notice_to_stix_bundle(n).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return {
            "type": "bundle",
            "id": f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": all_objects,
        }


def _det_uuid(t: str, v: str) -> str:
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
