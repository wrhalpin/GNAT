# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest.telemetry.kafka_reader
======================================

Kafka-based SourceReader for high-volume sensor event ingestion.
Consumes JSON-encoded messages from one or more Kafka topics.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

from gnat.ingest.base import RawRecord, SourceReader

logger = logging.getLogger(__name__)


class KafkaSourceReader(SourceReader):
    """
    Reads sensor events from Apache Kafka topics.

    Parameters
    ----------
    topics : list[str]
        Kafka topic names to subscribe to.
    bootstrap_servers : str or list[str]
        Kafka broker addresses (e.g. ``"localhost:9092"``).
    group_id : str
        Consumer group ID for offset tracking.
    max_messages : int or None
        Stop after consuming this many messages.  ``None`` for unlimited
        (will consume until ``poll_timeout_ms`` returns no messages).
    poll_timeout_ms : int
        Milliseconds to wait for messages per poll cycle.
    consumer_config : dict, optional
        Extra keyword arguments passed to ``KafkaConsumer()``.
    """

    def __init__(
        self,
        topics: list[str],
        bootstrap_servers: str | list[str] = "localhost:9092",
        group_id: str = "gnat-telemetry",
        max_messages: int | None = None,
        poll_timeout_ms: int = 5000,
        consumer_config: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        super().__init__(source_id=f"kafka:{','.join(topics)}", **kwargs)
        self._topics = topics
        self._bootstrap_servers = bootstrap_servers
        self._group_id = group_id
        self._max_messages = max_messages
        self._poll_timeout_ms = poll_timeout_ms
        self._consumer_config = consumer_config or {}
        self._consumer: Any = None

    def open(self) -> None:
        try:
            from kafka import KafkaConsumer
        except ImportError as exc:
            raise ImportError(
                "kafka-python-ng is required for KafkaSourceReader. "
                "Install it with: pip install 'gnat[telemetry]'"
            ) from exc

        self._consumer = KafkaConsumer(
            *self._topics,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._group_id,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            consumer_timeout_ms=self._poll_timeout_ms,
            **self._consumer_config,
        )
        super().open()
        logger.info(
            "KafkaSourceReader: subscribed to %s via %s",
            self._topics,
            self._bootstrap_servers,
        )

    def close(self) -> None:
        if self._consumer is not None:
            self._consumer.close()
            self._consumer = None
        super().close()

    def _iter_records(self) -> Iterator[RawRecord]:
        if self._consumer is None:
            raise RuntimeError("KafkaSourceReader not opened; use as context manager")

        for count, message in enumerate(self._consumer, 1):
            record: RawRecord = message.value if isinstance(message.value, dict) else {}
            record["_kafka_topic"] = message.topic
            record["_kafka_partition"] = message.partition
            record["_kafka_offset"] = message.offset
            record["_kafka_timestamp"] = message.timestamp
            yield record

            if self._max_messages and count >= self._max_messages:
                break
