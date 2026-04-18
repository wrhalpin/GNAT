# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/ingest/test_telemetry.py
======================================

Unit tests for the sensor/telemetry ingestion module.
Covers schemas, mapper, Redis dedup, campaign linker, and Kafka reader.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gnat.ingest.telemetry.campaign_linker import CampaignLinker
from gnat.ingest.telemetry.mapper import TelemetryMapper
from gnat.ingest.telemetry.redis_dedup import RedisDeduplicationCache
from gnat.ingest.telemetry.schemas import SensorSchema, SensorType

# ===========================================================================
# Schemas
# ===========================================================================


class TestSensorSchema:
    def test_extract_honeypot(self):
        raw = {
            "sensor_type": "honeypot",
            "src_ip": "203.0.113.1",
            "src_port": 45678,
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "protocol": "tcp",
            "attack_type": "ssh-brute",
            "timestamp": "2026-04-18T10:00:00Z",
            "honeypot_id": "hp-01",
        }
        event = SensorSchema.extract(raw)
        assert event.sensor_type == SensorType.HONEYPOT
        assert event.src_ip == "203.0.113.1"
        assert event.dst_port == 22
        assert event.signature == "ssh-brute"
        assert event.sensor_id == "hp-01"

    def test_extract_netflow(self):
        raw = {
            "sensor_type": "netflow",
            "IPV4_SRC_ADDR": "198.51.100.5",
            "IPV4_DST_ADDR": "10.0.0.1",
            "L4_SRC_PORT": 12345,
            "L4_DST_PORT": 443,
            "PROTOCOL": "6",
            "IN_BYTES": 50000,
            "OUT_BYTES": 1200,
            "DURATION": 3.5,
        }
        event = SensorSchema.extract(raw)
        assert event.sensor_type == SensorType.NETFLOW
        assert event.src_ip == "198.51.100.5"
        assert event.bytes_in == 50000
        assert event.duration_seconds == 3.5

    def test_extract_ids_alert(self):
        raw = {
            "sensor_type": "ids_alert",
            "src_ip": "203.0.113.50",
            "dst_ip": "10.0.0.1",
            "src_port": 55555,
            "dst_port": 80,
            "protocol": "tcp",
            "alert": "ET MALWARE Win32/Emotet",
            "severity": "high",
            "timestamp": "2026-04-18T12:00:00Z",
            "sensor_id": "suricata-01",
        }
        event = SensorSchema.extract(raw)
        assert event.sensor_type == SensorType.IDS_ALERT
        assert event.signature == "ET MALWARE Win32/Emotet"
        assert event.severity == "high"

    def test_extract_dns_log(self):
        raw = {
            "sensor_type": "dns_log",
            "client_ip": "192.168.1.100",
            "query": "evil.example.com",
            "answer": "203.0.113.99",
            "timestamp": "2026-04-18T11:00:00Z",
        }
        event = SensorSchema.extract(raw)
        assert event.sensor_type == SensorType.DNS_LOG
        assert event.domain == "evil.example.com"
        assert event.dst_ip == "203.0.113.99"

    def test_extract_generic(self):
        raw = {"src_ip": "203.0.113.1", "domain": "bad.example.com"}
        event = SensorSchema.extract(raw)
        assert event.sensor_type == SensorType.GENERIC
        assert event.src_ip == "203.0.113.1"
        assert event.domain == "bad.example.com"

    def test_extract_with_override(self):
        raw = {"src_ip": "1.2.3.4"}
        event = SensorSchema.extract(raw, sensor_type=SensorType.HONEYPOT)
        assert event.sensor_type == SensorType.HONEYPOT

    def test_event_preserves_raw(self):
        raw = {"sensor_type": "generic", "custom_field": "value"}
        event = SensorSchema.extract(raw)
        assert event.raw["custom_field"] == "value"


# ===========================================================================
# Mapper
# ===========================================================================


class TestTelemetryMapper:
    def test_honeypot_produces_src_ip_indicator(self):
        raw = {
            "sensor_type": "honeypot",
            "src_ip": "203.0.113.1",
            "dst_ip": "10.0.0.5",
            "timestamp": "2026-04-18T10:00:00Z",
            "honeypot_id": "hp-01",
        }
        mapper = TelemetryMapper(confidence=70)
        results = list(mapper.map(raw))
        assert len(results) == 1
        ind = results[0]
        assert "[ipv4-addr:value = '203.0.113.1']" in ind.pattern
        assert ind._properties.get("x_gnat_sensor_type") == "honeypot"

    def test_skips_private_ips(self):
        raw = {"sensor_type": "generic", "src_ip": "192.168.1.100"}
        mapper = TelemetryMapper()
        results = list(mapper.map(raw))
        assert len(results) == 0

    def test_include_dst_flag(self):
        raw = {
            "sensor_type": "honeypot",
            "src_ip": "203.0.113.1",
            "dst_ip": "198.51.100.5",
        }
        mapper = TelemetryMapper(include_dst=True)
        results = list(mapper.map(raw))
        patterns = [r.pattern for r in results]
        assert any("203.0.113.1" in p for p in patterns)
        assert any("198.51.100.5" in p for p in patterns)

    def test_dns_produces_domain_indicator(self):
        raw = {
            "sensor_type": "dns_log",
            "client_ip": "192.168.1.100",
            "query": "evil.example.com",
        }
        mapper = TelemetryMapper()
        results = list(mapper.map(raw))
        assert len(results) == 1
        assert "[domain-name:value = 'evil.example.com']" in results[0].pattern

    def test_hash_indicator_sha256(self):
        h = "a" * 64
        raw = {"sensor_type": "generic", "file_hash": h}
        mapper = TelemetryMapper()
        results = list(mapper.map(raw))
        assert len(results) == 1
        assert f"[file:hashes.'SHA-256' = '{h}']" in results[0].pattern

    def test_hash_indicator_md5(self):
        h = "d" * 32
        raw = {"sensor_type": "generic", "file_hash": h}
        mapper = TelemetryMapper()
        results = list(mapper.map(raw))
        assert len(results) == 1
        assert "MD5" in results[0].pattern

    def test_url_indicator(self):
        raw = {"sensor_type": "generic", "url": "http://evil.com/payload.exe"}
        mapper = TelemetryMapper()
        results = list(mapper.map(raw))
        assert len(results) == 1
        assert "url:value" in results[0].pattern

    def test_min_severity_filters_low(self):
        raw = {
            "sensor_type": "ids_alert",
            "src_ip": "203.0.113.1",
            "severity": "low",
        }
        mapper = TelemetryMapper(min_severity="high")
        results = list(mapper.map(raw))
        assert len(results) == 0

    def test_min_severity_passes_high(self):
        raw = {
            "sensor_type": "ids_alert",
            "src_ip": "203.0.113.1",
            "severity": "critical",
        }
        mapper = TelemetryMapper(min_severity="high")
        results = list(mapper.map(raw))
        assert len(results) == 1

    def test_confidence_propagated(self):
        raw = {"sensor_type": "honeypot", "src_ip": "203.0.113.1"}
        mapper = TelemetryMapper(confidence=75)
        results = list(mapper.map(raw))
        assert results[0].confidence == 75

    def test_tlp_marking_stored(self):
        raw = {"sensor_type": "honeypot", "src_ip": "203.0.113.1"}
        mapper = TelemetryMapper(tlp_marking="amber")
        results = list(mapper.map(raw))
        assert results[0]._properties.get("x_gnat_tlp") == "amber"

    def test_no_duplicate_iocs_in_single_event(self):
        raw = {
            "sensor_type": "honeypot",
            "src_ip": "203.0.113.1",
            "dst_ip": "203.0.113.1",
        }
        mapper = TelemetryMapper(include_dst=True)
        results = list(mapper.map(raw))
        assert len(results) == 1

    def test_sensor_type_override(self):
        raw = {"src_ip": "203.0.113.1"}
        mapper = TelemetryMapper(sensor_type=SensorType.IDS_ALERT)
        results = list(mapper.map(raw))
        assert results[0]._properties.get("x_gnat_sensor_type") == "ids_alert"


# ===========================================================================
# Redis Dedup (memory fallback)
# ===========================================================================


class TestRedisDeduplicationCache:
    def test_memory_fallback_when_redis_unavailable(self):
        cache = RedisDeduplicationCache(
            redis_url="redis://nonexistent:9999/0",
            fallback_to_memory=True,
        )
        assert cache._redis is None
        assert cache._memory_set is not None

    def test_memory_dedup_basic(self):
        cache = RedisDeduplicationCache(
            redis_url="redis://nonexistent:9999/0",
            fallback_to_memory=True,
        )
        fp = cache.fingerprint("ipv4-addr", "203.0.113.1")
        assert not cache.is_duplicate(fp)
        assert cache.is_duplicate(fp)

    def test_fingerprint_deterministic(self):
        fp1 = RedisDeduplicationCache.fingerprint("ipv4-addr", "1.2.3.4", "sensor-1")
        fp2 = RedisDeduplicationCache.fingerprint("ipv4-addr", "1.2.3.4", "sensor-1")
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_fingerprint_differs_by_type(self):
        fp1 = RedisDeduplicationCache.fingerprint("ipv4-addr", "1.2.3.4")
        fp2 = RedisDeduplicationCache.fingerprint("domain-name", "1.2.3.4")
        assert fp1 != fp2

    def test_clear_resets(self):
        cache = RedisDeduplicationCache(
            redis_url="redis://nonexistent:9999/0",
            fallback_to_memory=True,
        )
        fp = cache.fingerprint("ipv4-addr", "1.2.3.4")
        cache.is_duplicate(fp)
        assert len(cache) == 1
        cache.clear()
        assert len(cache) == 0
        assert not cache.is_duplicate(fp)

    def test_len_tracks_entries(self):
        cache = RedisDeduplicationCache(
            redis_url="redis://nonexistent:9999/0",
            fallback_to_memory=True,
        )
        assert len(cache) == 0
        cache.is_duplicate(cache.fingerprint("ipv4-addr", "1.1.1.1"))
        cache.is_duplicate(cache.fingerprint("ipv4-addr", "2.2.2.2"))
        assert len(cache) == 2


# ===========================================================================
# Campaign Linker
# ===========================================================================


class TestCampaignLinker:
    def test_extract_ioc_from_pattern(self):
        assert CampaignLinker._extract_ioc_from_pattern(
            "[ipv4-addr:value = '1.2.3.4']"
        ) == "1.2.3.4"

    def test_extract_ioc_empty_pattern(self):
        assert CampaignLinker._extract_ioc_from_pattern("") == ""

    def test_extract_ioc_no_quotes(self):
        assert CampaignLinker._extract_ioc_from_pattern("no quotes") == ""

    def test_linker_calls_service(self):
        svc = MagicMock()
        linker = CampaignLinker(
            campaign_service=svc,
            ioc_index={"1.2.3.4": ["campaign--abc"]},
        )
        obj = MagicMock()
        obj.id = "indicator--123"
        obj.pattern = "[ipv4-addr:value = '1.2.3.4']"
        obj._properties = {}

        result = linker(obj)
        assert result is obj
        svc.link_indicator.assert_called_once_with("campaign--abc", "indicator--123")
        assert linker.link_count == 1

    def test_linker_no_match(self):
        svc = MagicMock()
        linker = CampaignLinker(
            campaign_service=svc,
            ioc_index={"1.2.3.4": ["campaign--abc"]},
        )
        obj = MagicMock()
        obj.id = "indicator--123"
        obj.pattern = "[ipv4-addr:value = '5.6.7.8']"
        obj._properties = {}

        linker(obj)
        svc.link_indicator.assert_not_called()
        assert linker.link_count == 0

    def test_linker_handles_service_error(self):
        svc = MagicMock()
        svc.link_indicator.side_effect = RuntimeError("db error")
        linker = CampaignLinker(
            campaign_service=svc,
            ioc_index={"1.2.3.4": ["campaign--abc"]},
        )
        obj = MagicMock()
        obj.id = "indicator--123"
        obj.pattern = "[ipv4-addr:value = '1.2.3.4']"
        obj._properties = {}

        result = linker(obj)
        assert result is obj
        assert linker.link_count == 0

    def test_linker_builds_index_lazily(self):
        svc = MagicMock()
        svc.list.return_value = []
        linker = CampaignLinker(campaign_service=svc)

        obj = MagicMock()
        obj.id = "indicator--123"
        obj.pattern = "[ipv4-addr:value = '1.2.3.4']"
        obj._properties = {}

        linker(obj)
        assert linker._ioc_index is not None


# ===========================================================================
# Kafka Reader (import guard)
# ===========================================================================


class TestKafkaSourceReader:
    def test_import_check(self):
        from gnat.ingest.telemetry.kafka_reader import KafkaSourceReader

        reader = KafkaSourceReader(
            topics=["honeypot-events"],
            bootstrap_servers="localhost:9092",
        )
        assert reader.source_id == "kafka:honeypot-events"

    def test_open_without_kafka_raises(self):
        from gnat.ingest.telemetry.kafka_reader import KafkaSourceReader

        reader = KafkaSourceReader(topics=["test"])
        with patch.dict("sys.modules", {"kafka": None}), pytest.raises(ImportError, match="kafka-python-ng"):
            reader.open()

    def test_iter_without_open_raises(self):
        from gnat.ingest.telemetry.kafka_reader import KafkaSourceReader

        reader = KafkaSourceReader(topics=["test"])
        reader._open = True
        with pytest.raises(RuntimeError, match="not opened"):
            list(reader._iter_records())

    def test_max_messages_limit(self):
        from gnat.ingest.telemetry.kafka_reader import KafkaSourceReader

        reader = KafkaSourceReader(topics=["test"], max_messages=2)
        msg1 = MagicMock()
        msg1.value = {"src_ip": "1.1.1.1"}
        msg1.topic = "test"
        msg1.partition = 0
        msg1.offset = 0
        msg1.timestamp = 1000
        msg2 = MagicMock()
        msg2.value = {"src_ip": "2.2.2.2"}
        msg2.topic = "test"
        msg2.partition = 0
        msg2.offset = 1
        msg2.timestamp = 1001
        msg3 = MagicMock()
        msg3.value = {"src_ip": "3.3.3.3"}
        msg3.topic = "test"
        msg3.partition = 0
        msg3.offset = 2
        msg3.timestamp = 1002

        reader._consumer = iter([msg1, msg2, msg3])
        records = list(reader._iter_records())
        assert len(records) == 2
        assert records[0]["src_ip"] == "1.1.1.1"
        assert records[1]["_kafka_offset"] == 1
