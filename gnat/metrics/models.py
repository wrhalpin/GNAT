"""
gnat.metrics.models
====================

Metric event model for GNAT analyst performance tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MetricType(str, Enum):
    """Types of analyst performance metrics."""

    INVESTIGATION_OPENED      = "investigation_opened"
    INVESTIGATION_CLOSED      = "investigation_closed"
    INVESTIGATION_DURATION    = "investigation_duration"   # value = seconds
    ENRICHMENT_HIT            = "enrichment_hit"           # value = 1.0
    ENRICHMENT_MISS           = "enrichment_miss"          # value = 1.0
    ENRICHMENT_LATENCY        = "enrichment_latency"       # value = ms
    REPORT_PUBLISHED          = "report_published"
    FALSE_POSITIVE_FLAGGED    = "false_positive_flagged"
    GAP_DETECTED              = "gap_detected"


@dataclass
class MetricEvent:
    """
    A single metric observation.

    Parameters
    ----------
    metric_type : MetricType
        Type of metric.
    value : float
        Numeric value (count, duration_seconds, hit/miss 0/1, latency_ms).
    labels : dict[str, str]
        Dimension labels (``investigation_id``, ``platform``, ``analyst``…).
    timestamp : datetime
        When the event occurred (UTC, auto-generated).
    """

    metric_type: MetricType
    value:       float
    labels:      dict[str, str] = field(default_factory=dict)
    timestamp:   datetime       = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_type": self.metric_type.value,
            "value":       self.value,
            "labels":      self.labels,
            "timestamp":   self.timestamp.isoformat(),
        }
