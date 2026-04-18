# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry.schemas
================================

Sensor event schemas — normalise raw honeypot, netflow, and generic
sensor payloads into a common intermediate format the mapper can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SensorType(str, Enum):
    HONEYPOT = "honeypot"
    NETFLOW = "netflow"
    IDS_ALERT = "ids_alert"
    DNS_LOG = "dns_log"
    GENERIC = "generic"


@dataclass
class SensorEvent:
    """Normalised intermediate event produced by a schema extractor."""

    sensor_type: SensorType = SensorType.GENERIC
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    domain: str = ""
    url: str = ""
    file_hash: str = ""
    hash_type: str = ""
    timestamp: str = ""
    sensor_id: str = ""
    severity: str = ""
    signature: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    duration_seconds: float = 0.0
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class SensorSchema:
    """Extracts a SensorEvent from raw dicts based on sensor type."""

    @staticmethod
    def extract(raw: dict[str, Any], sensor_type: SensorType | None = None) -> SensorEvent:
        st = sensor_type or SensorType(raw.get("sensor_type", "generic"))
        if st == SensorType.HONEYPOT:
            return SensorSchema._extract_honeypot(raw)
        if st == SensorType.NETFLOW:
            return SensorSchema._extract_netflow(raw)
        if st == SensorType.IDS_ALERT:
            return SensorSchema._extract_ids_alert(raw)
        if st == SensorType.DNS_LOG:
            return SensorSchema._extract_dns_log(raw)
        return SensorSchema._extract_generic(raw)

    @staticmethod
    def _extract_honeypot(raw: dict[str, Any]) -> SensorEvent:
        return SensorEvent(
            sensor_type=SensorType.HONEYPOT,
            src_ip=raw.get("src_ip") or raw.get("source_ip", ""),
            src_port=int(raw.get("src_port") or raw.get("source_port", 0)),
            dst_ip=raw.get("dst_ip") or raw.get("dest_ip", ""),
            dst_port=int(raw.get("dst_port") or raw.get("dest_port", 0)),
            protocol=raw.get("protocol", ""),
            timestamp=raw.get("timestamp") or raw.get("@timestamp", ""),
            sensor_id=raw.get("sensor_id") or raw.get("honeypot_id", ""),
            signature=raw.get("signature") or raw.get("attack_type", ""),
            tags=list(raw.get("tags") or []),
            raw=raw,
        )

    @staticmethod
    def _extract_netflow(raw: dict[str, Any]) -> SensorEvent:
        return SensorEvent(
            sensor_type=SensorType.NETFLOW,
            src_ip=raw.get("src_ip") or raw.get("IPV4_SRC_ADDR", ""),
            src_port=int(raw.get("src_port") or raw.get("L4_SRC_PORT", 0)),
            dst_ip=raw.get("dst_ip") or raw.get("IPV4_DST_ADDR", ""),
            dst_port=int(raw.get("dst_port") or raw.get("L4_DST_PORT", 0)),
            protocol=raw.get("protocol") or str(raw.get("PROTOCOL", "")),
            bytes_in=int(raw.get("bytes_in") or raw.get("IN_BYTES", 0)),
            bytes_out=int(raw.get("bytes_out") or raw.get("OUT_BYTES", 0)),
            duration_seconds=float(raw.get("duration") or raw.get("DURATION", 0.0)),
            timestamp=raw.get("timestamp") or raw.get("FIRST_SWITCHED", ""),
            sensor_id=raw.get("sensor_id") or raw.get("exporter_id", ""),
            raw=raw,
        )

    @staticmethod
    def _extract_ids_alert(raw: dict[str, Any]) -> SensorEvent:
        return SensorEvent(
            sensor_type=SensorType.IDS_ALERT,
            src_ip=raw.get("src_ip", ""),
            src_port=int(raw.get("src_port", 0)),
            dst_ip=raw.get("dst_ip", ""),
            dst_port=int(raw.get("dst_port", 0)),
            protocol=raw.get("protocol", ""),
            signature=raw.get("signature") or raw.get("alert", ""),
            severity=raw.get("severity", ""),
            timestamp=raw.get("timestamp", ""),
            sensor_id=raw.get("sensor_id", ""),
            raw=raw,
        )

    @staticmethod
    def _extract_dns_log(raw: dict[str, Any]) -> SensorEvent:
        return SensorEvent(
            sensor_type=SensorType.DNS_LOG,
            src_ip=raw.get("src_ip") or raw.get("client_ip", ""),
            domain=raw.get("domain") or raw.get("query", ""),
            dst_ip=raw.get("resolved_ip") or raw.get("answer", ""),
            timestamp=raw.get("timestamp", ""),
            sensor_id=raw.get("sensor_id", ""),
            raw=raw,
        )

    @staticmethod
    def _extract_generic(raw: dict[str, Any]) -> SensorEvent:
        return SensorEvent(
            sensor_type=SensorType.GENERIC,
            src_ip=raw.get("src_ip", ""),
            dst_ip=raw.get("dst_ip", ""),
            domain=raw.get("domain", ""),
            url=raw.get("url", ""),
            file_hash=raw.get("file_hash") or raw.get("hash", ""),
            hash_type=raw.get("hash_type", ""),
            timestamp=raw.get("timestamp", ""),
            sensor_id=raw.get("sensor_id", ""),
            raw=raw,
        )
