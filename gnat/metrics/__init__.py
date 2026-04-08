"""
gnat.metrics
=============

Analyst performance and pipeline effectiveness metrics for GNAT.

Provides an in-memory ring-buffer :class:`MetricsCollector` and a
time-windowed :class:`MetricsAggregator`.

Quick start::

    from gnat.metrics import MetricsCollector, MetricsAggregator, MetricType

    collector  = MetricsCollector(max_size=10_000)
    aggregator = MetricsAggregator(collector)

    # Emit events throughout the pipeline:
    collector.record(MetricType.INVESTIGATION_OPENED, 1.0, investigation_id="inv-1")
    collector.record(MetricType.ENRICHMENT_HIT, 1.0, platform="virustotal")
    collector.record(MetricType.ENRICHMENT_LATENCY, 245.0, platform="virustotal")

    # Query summaries:
    print(aggregator.investigation_summary(days=30))
    print(aggregator.enrichment_effectiveness(platform="virustotal", days=7))
    print(aggregator.gap_frequency(days=30))
"""

from gnat.metrics.aggregator import MetricsAggregator
from gnat.metrics.collector import MetricsCollector
from gnat.metrics.hooks import register_metrics_hooks, unregister_metrics_hooks
from gnat.metrics.models import MetricEvent, MetricType

__all__ = [
    "MetricsAggregator",
    "MetricsCollector",
    "MetricEvent",
    "MetricType",
    "register_metrics_hooks",
    "unregister_metrics_hooks",
]
