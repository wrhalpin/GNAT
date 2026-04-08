"""
gnat.metrics.collector
=======================

In-memory ring-buffer metrics collector.

Metric events are stored in a fixed-size deque.  When the buffer is full
the oldest events are discarded (ring-buffer semantics).

Usage::

    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    collector = MetricsCollector(max_size=10_000)

    # Record events throughout the pipeline
    collector.record(MetricType.INVESTIGATION_OPENED, 1.0, investigation_id="inv-1")
    collector.record(MetricType.ENRICHMENT_HIT, 1.0, platform="virustotal")
    collector.record(MetricType.ENRICHMENT_LATENCY, 245.0, platform="virustotal")

    # Snapshot all events for aggregation
    events = collector.snapshot()
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

from gnat.metrics.models import MetricEvent, MetricType

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Thread-safe in-memory ring-buffer metrics collector.

    Parameters
    ----------
    max_size : int
        Maximum number of events to retain (default 10,000).
        When full, the oldest event is discarded.
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._buffer: deque[MetricEvent] = deque(maxlen=max_size)
        self._lock   = threading.Lock()
        self.max_size = max_size

    def record(
        self,
        metric_type: MetricType,
        value:       float,
        **labels: str,
    ) -> MetricEvent:
        """
        Record a metric event.

        Parameters
        ----------
        metric_type : MetricType
        value : float
        **labels : str
            Dimension labels (``investigation_id``, ``platform``, etc.).

        Returns
        -------
        MetricEvent
        """
        event = MetricEvent(
            metric_type = metric_type,
            value       = value,
            labels      = {k: str(v) for k, v in labels.items()},
        )
        with self._lock:
            self._buffer.append(event)
        return event

    def snapshot(self, metric_type: MetricType | None = None) -> list[MetricEvent]:
        """
        Return a snapshot of buffered events (oldest-first).

        Parameters
        ----------
        metric_type : MetricType, optional
            Filter to events of this type.

        Returns
        -------
        list[MetricEvent]
        """
        with self._lock:
            events = list(self._buffer)
        if metric_type is not None:
            events = [e for e in events if e.metric_type == metric_type]
        return events

    def since(
        self,
        cutoff:      datetime,
        metric_type: MetricType | None = None,
    ) -> list[MetricEvent]:
        """
        Return events recorded at or after *cutoff*.

        Parameters
        ----------
        cutoff : datetime
            UTC datetime lower bound (inclusive).
        metric_type : MetricType, optional
            Filter to this type.
        """
        events = self.snapshot(metric_type)
        cutoff_aware = cutoff if cutoff.tzinfo else cutoff.replace(tzinfo=timezone.utc)
        return [e for e in events if e.timestamp >= cutoff_aware]

    def clear(self) -> None:
        """Discard all buffered events."""
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
