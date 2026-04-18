# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry
========================

High-volume sensor and telemetry ingestion for honeypot, netflow,
and generic sensor data.  Consumes events from Kafka topics, deduplicates
via Redis (optional), normalises to STIX Indicator/Observable objects,
and auto-links to active campaigns.

Install dependencies::

    pip install "gnat[telemetry]"

Requires ``kafka-python-ng`` and optionally ``redis``.
"""

from gnat.ingest.telemetry.campaign_linker import CampaignLinker
from gnat.ingest.telemetry.kafka_reader import KafkaSourceReader
from gnat.ingest.telemetry.mapper import TelemetryMapper
from gnat.ingest.telemetry.redis_dedup import RedisDeduplicationCache
from gnat.ingest.telemetry.schemas import (
    SensorSchema,
    SensorType,
)

__all__ = [
    "KafkaSourceReader",
    "RedisDeduplicationCache",
    "TelemetryMapper",
    "CampaignLinker",
    "SensorSchema",
    "SensorType",
]
