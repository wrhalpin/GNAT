# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.zeek.client
=================================

Zeek (formerly Bro) NSM connector (file-based — no HTTP API).

Zeek writes structured log files in either TSV (default) or JSON format.
This connector reads ``notice.log`` and ``conn.log`` files and translates
records to STIX 2.1 ``observed-data`` bundles.

Configuration
-------------
::

    [zeek]
    log_dir    = /var/log/zeek/current
    log_format = tsv        # or: json

Notes
-----
* There is no Zeek REST API — all data comes from local log files.
* ``upsert_object`` and ``delete_object`` are not supported.
* Use ``parse_notices()`` / ``parse_connections()`` for bulk parsing,
  or ``iter_stix_notices()`` for a streaming STIX pipeline.
* TSV logs include a ``#fields`` header that maps column names.
"""

from __future__ import annotations

import contextlib
import json
import uuid as _uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

_STIX_NS = _uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _det_uuid(t: str, v: str) -> str:
    """Internal helper for det uuid."""
    return str(_uuid.uuid5(_STIX_NS, f"{t}:{v}"))


def _now_ts() -> str:
    """Internal helper for now ts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ZeekClient(BaseClient, ConnectorMixin):
    """
    File-based connector for Zeek log files.

    Parameters
    ----------
    host : str
        Unused (pass ``""``).  Zeek has no HTTP API.
    log_dir : str, optional
        Directory containing Zeek log files.
    log_format : str
        ``"tsv"`` (default Zeek) or ``"json"`` (json-logs package).
    """

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = ""

    stix_type_map: dict[str, str] = {
        "observed-data": "notices",
    }

    def __init__(
        self,
        host: str = "",
        log_dir: str = "/var/log/zeek/current",
        log_format: str = "tsv",
        **kwargs: Any,
    ):
        """Initialize ZeekClient."""
        super().__init__(host=host, **kwargs)
        self.log_dir = log_dir
        self.log_format = log_format

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No-op — Zeek has no HTTP API."""

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify the Zeek log directory exists and is readable."""
        path = Path(self.log_dir)
        if not path.is_dir():
            raise GNATClientError(f"Zeek log directory not found: {self.log_dir}")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Retrieve object."""
        raise GNATClientError(
            "Zeek is file-based — individual record lookup by id is not supported."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Read records from Zeek log files.

        Parameters
        ----------
        stix_type : str
            ``"observed-data"`` — reads ``notice.log`` by default.
        filters : dict, optional
            * ``log_name`` — Zeek log name (default: ``"notice"``)
            * ``path``     — explicit log file path override
            * ``limit``    — max records (default: page_size)

        Returns
        -------
        list of dict
            Normalised Zeek record dicts.
        """
        filters = dict(filters or {})
        log_name = filters.pop("log_name", "notice")
        path = filters.pop("path", None)
        limit = filters.pop("limit", page_size)

        records = []
        for i, rec in enumerate(self._iter_records(log_name, path=path)):
            if i >= limit:
                break
            records.append(rec)
        return records

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or update object."""
        raise GNATClientError("Zeek is read-only — no write API available.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete the object."""
        raise GNATClientError("Zeek is read-only — no delete API available.")

    # ── Domain-specific operations ────────────────────────────────────────

    def parse_notices(self, path: str | None = None) -> list[dict[str, Any]]:
        """
        Parse all records from ``notice.log``.

        Returns
        -------
        list of dict
            Normalised notice records.
        """
        return list(self._iter_records("notice", path=path))

    def parse_connections(self, path: str | None = None) -> list[dict[str, Any]]:
        """
        Parse all records from ``conn.log``.

        Returns
        -------
        list of dict
            Normalised connection records.
        """
        return list(self._iter_records("conn", path=path))

    def iter_stix_notices(self, path: str | None = None) -> Iterator[dict[str, Any]]:
        """
        Yield STIX observed-data objects from ``notice.log``.

        Parameters
        ----------
        path : str, optional
            Override the default notice.log path.
        """
        for notice in self._iter_records("notice", path=path):
            yield self.to_stix(notice)

    def iter_stix_connections(self, path: str | None = None) -> Iterator[dict[str, Any]]:
        """
        Yield STIX observed-data objects from ``conn.log``.

        Parameters
        ----------
        path : str, optional
            Override the default conn.log path.
        """
        for conn in self._iter_records("conn", path=path):
            yield self._conn_to_stix(conn)

    def list_available_logs(self) -> list[str]:
        """Return names of Zeek log files present in ``log_dir``."""
        ext = "log" if self.log_format == "tsv" else "json"
        try:
            return [
                f.name.replace(f".{ext}", "")
                for f in sorted(Path(self.log_dir).iterdir(), key=lambda p: p.name)
                if f.name.endswith(f".{ext}") and not f.name.startswith(".")
            ]
        except OSError:
            return []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a normalised Zeek notice record to a STIX 2.1 observed-data SDO.

        Parameters
        ----------
        native : dict
            Normalised notice dict (from ``parse_notices()`` or raw record).

        Returns
        -------
        dict
            STIX ``observed-data`` object.
        """
        notice = self._normalise_notice(native)
        now = _now_ts()
        ts = notice.get("timestamp") or now

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (notice.get("src_ip"), notice.get("dst_ip")):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append(
                        {
                            "type": "ipv4-addr",
                            "id": ip_id,
                            "spec_version": CURRENT_SPEC_VERSION,
                            "value": ip,
                        }
                    )
                refs.append(ip_id)

        src_ip = notice.get("src_ip")
        dst_ip = notice.get("dst_ip")
        src_p = notice.get("src_port")
        dst_p = notice.get("dst_port")
        if src_ip and dst_ip and (src_p or dst_p):
            key = f"{src_ip}:{src_p}-{dst_ip}:{dst_p}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": CURRENT_SPEC_VERSION,
                    "src_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}",
                    "dst_ref": f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}",
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
        obs: dict[str, Any] = {
            "type": "observed-data",
            "id": obs_id,
            "spec_version": CURRENT_SPEC_VERSION,
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
        objects.append(obs)
        return obs

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Zeek is read-only — from_stix returns an informational dict."""
        return {
            "note": "Zeek is file-based and read-only.",
            "stix_id": stix_dict.get("id", ""),
        }

    # ── Private helpers ────────────────────────────────────────────────────

    def _log_path(self, log_name: str) -> Path:
        """Resolve the full path for a given log name."""
        ext = "log" if self.log_format == "tsv" else "json"
        return Path(self.log_dir) / f"{log_name}.{ext}"

    def _iter_records(self, log_name: str, path: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield raw record dicts from a Zeek log file."""
        log_path = Path(path) if path else self._log_path(log_name)
        if not log_path.exists():
            raise GNATClientError(f"Zeek log not found: {log_path}")
        if self.log_format == "json":
            yield from self._iter_json(log_path)
        else:
            yield from self._iter_tsv(log_path)

    @staticmethod
    def _iter_json(path: Path) -> Iterator[dict[str, Any]]:
        """Yield records from a Zeek JSON log."""
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    @staticmethod
    def _iter_tsv(path: Path) -> Iterator[dict[str, Any]]:
        """Yield records from a Zeek TSV log, using the #fields header."""
        fields: list[str] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not line or not fields:
                    continue
                parts = line.split("\t")
                if len(parts) != len(fields):
                    continue
                record: dict[str, Any] = {}
                for k, v in zip(fields, parts):
                    record[k] = None if v == "-" else v
                yield record

    @staticmethod
    def _normalise_notice(record: dict[str, Any]) -> dict[str, Any]:
        """Normalise a Zeek notice.log record."""
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
        }

    def _conn_to_stix(self, conn: dict[str, Any]) -> dict[str, Any]:
        """Translate a Zeek conn.log record to a STIX observed-data SDO."""
        now = _now_ts()
        ts = conn.get("ts") or now
        src = conn.get("id.orig_h")
        dst = conn.get("id.resp_h")
        sp = conn.get("id.orig_p")
        dp = conn.get("id.resp_p")

        objects: list[dict[str, Any]] = []
        refs: list[str] = []
        seen: set = set()

        for ip in (src, dst):
            if ip:
                ip_id = f"ipv4-addr--{_det_uuid('ipv4-addr', ip)}"
                if ip_id not in seen:
                    seen.add(ip_id)
                    objects.append(
                        {
                            "type": "ipv4-addr",
                            "id": ip_id,
                            "spec_version": CURRENT_SPEC_VERSION,
                            "value": ip,
                        }
                    )
                refs.append(ip_id)

        if src and dst:
            key = f"{src}:{sp}-{dst}:{dp}"
            nid = f"network-traffic--{_det_uuid('network-traffic', key)}"
            if nid not in seen:
                seen.add(nid)
                nt: dict[str, Any] = {
                    "type": "network-traffic",
                    "id": nid,
                    "spec_version": CURRENT_SPEC_VERSION,
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
        obs: dict[str, Any] = {
            "type": "observed-data",
            "id": obs_id,
            "spec_version": CURRENT_SPEC_VERSION,
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
        objects.append(obs)
        return obs
