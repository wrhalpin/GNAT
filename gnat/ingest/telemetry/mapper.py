# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry.mapper
================================

RecordMapper that converts normalised sensor events into STIX objects.
Produces Indicators for network IOCs (IPs, domains, URLs, hashes)
and Observables for supplementary network data.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from typing import Any

from gnat.ingest.base import RawRecord, RecordMapper
from gnat.ingest.telemetry.schemas import SensorEvent, SensorSchema, SensorType
from gnat.orm.base import STIXBase
from gnat.orm.indicator import Indicator

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


class TelemetryMapper(RecordMapper):
    """
    Maps sensor telemetry records to STIX Indicator objects.

    Extracts IOCs from normalised :class:`SensorEvent` payloads and
    produces one Indicator per distinct network observable (source IP,
    destination IP, domain, URL, or file hash).

    Parameters
    ----------
    sensor_type : SensorType, optional
        Override auto-detection of sensor type from raw record.
    include_dst : bool
        Whether to create indicators for destination IPs.  Defaults
        to False (destination is often internal infrastructure).
    min_severity : str, optional
        For IDS alerts, skip events below this severity level.
    """

    SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(
        self,
        sensor_type: SensorType | None = None,
        include_dst: bool = False,
        min_severity: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._sensor_type = sensor_type
        self._include_dst = include_dst
        self._min_severity = min_severity

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        event = SensorSchema.extract(record, self._sensor_type)

        if self._min_severity and event.severity:
            threshold = self.SEVERITY_ORDER.get(self._min_severity.lower(), 0)
            actual = self.SEVERITY_ORDER.get(event.severity.lower(), 0)
            if actual < threshold:
                return

        yield from self._indicators_from_event(event)

    def _indicators_from_event(self, event: SensorEvent) -> Iterator[Indicator]:
        seen: set[str] = set()

        if event.src_ip and event.src_ip not in seen:
            seen.add(event.src_ip)
            ind = self._ip_indicator(event.src_ip, event, direction="src")
            if ind:
                yield ind

        if self._include_dst and event.dst_ip and event.dst_ip not in seen:
            seen.add(event.dst_ip)
            ind = self._ip_indicator(event.dst_ip, event, direction="dst")
            if ind:
                yield ind

        if event.domain and event.domain not in seen:
            seen.add(event.domain)
            ind = self._domain_indicator(event.domain, event)
            if ind:
                yield ind

        if event.url and event.url not in seen:
            seen.add(event.url)
            yield self._url_indicator(event.url, event)

        if event.file_hash and event.file_hash not in seen:
            seen.add(event.file_hash)
            ind = self._hash_indicator(event.file_hash, event)
            if ind:
                yield ind

    def _ip_indicator(
        self, ip: str, event: SensorEvent, direction: str = "src"
    ) -> Indicator | None:
        if not _IPV4_RE.match(ip):
            return None
        if ip.startswith(("10.", "172.16.", "192.168.", "127.")):
            return None
        pattern = f"[ipv4-addr:value = '{ip}']"
        name = f"{event.sensor_type.value}:{direction}:{ip}"
        return self._build_indicator(
            name=name,
            pattern=pattern,
            event=event,
            indicator_types=["malicious-activity"],
        )

    def _domain_indicator(self, domain: str, event: SensorEvent) -> Indicator | None:
        if not _DOMAIN_RE.match(domain):
            return None
        pattern = f"[domain-name:value = '{domain}']"
        name = f"{event.sensor_type.value}:domain:{domain}"
        return self._build_indicator(
            name=name,
            pattern=pattern,
            event=event,
            indicator_types=["malicious-activity"],
        )

    def _url_indicator(self, url: str, event: SensorEvent) -> Indicator:
        escaped = url.replace("'", "\\'")
        pattern = f"[url:value = '{escaped}']"
        name = f"{event.sensor_type.value}:url:{url[:80]}"
        return self._build_indicator(
            name=name,
            pattern=pattern,
            event=event,
            indicator_types=["malicious-activity"],
        )

    def _hash_indicator(self, file_hash: str, event: SensorEvent) -> Indicator | None:
        hash_type = event.hash_type.upper() if event.hash_type else ""
        if not hash_type:
            hash_type = _HASH_LENGTHS.get(len(file_hash), "")
        if not hash_type:
            return None
        stix_hash_name = hash_type.replace("-", "").upper()
        hash_key_map = {"MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256"}
        stix_key = hash_key_map.get(stix_hash_name, stix_hash_name)
        pattern = f"[file:hashes.'{stix_key}' = '{file_hash}']"
        name = f"{event.sensor_type.value}:hash:{file_hash[:16]}..."
        return self._build_indicator(
            name=name,
            pattern=pattern,
            event=event,
            indicator_types=["malicious-activity"],
        )

    def _build_indicator(
        self,
        name: str,
        pattern: str,
        event: SensorEvent,
        indicator_types: list[str] | None = None,
    ) -> Indicator:
        kwargs: dict[str, Any] = {
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": self.confidence,
            "validate": False,
        }
        if indicator_types:
            kwargs["indicator_types"] = indicator_types
        if event.timestamp:
            kwargs["valid_from"] = event.timestamp

        ind = Indicator(client=self._client, **kwargs)
        ind._properties["x_gnat_sensor_type"] = event.sensor_type.value
        ind._properties["x_gnat_sensor_id"] = event.sensor_id
        if event.signature:
            ind._properties["x_gnat_signature"] = event.signature
        if event.tags:
            ind._properties["x_gnat_tags"] = list(event.tags)
        if self.tlp_marking:
            ind._properties["x_gnat_tlp"] = self.tlp_marking
        return ind
