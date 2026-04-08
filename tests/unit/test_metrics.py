"""Unit tests for gnat.metrics (analyst metrics)."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta


# ── Models ────────────────────────────────────────────────────────────────────

def test_metric_type_values():
    from gnat.metrics.models import MetricType
    assert MetricType.INVESTIGATION_OPENED == "investigation_opened"
    assert MetricType.ENRICHMENT_HIT       == "enrichment_hit"
    assert MetricType.ENRICHMENT_LATENCY   == "enrichment_latency"
    assert MetricType.REPORT_PUBLISHED     == "report_published"


def test_metric_event_creation():
    from gnat.metrics.models import MetricEvent, MetricType

    e = MetricEvent(
        metric_type = MetricType.ENRICHMENT_HIT,
        value       = 1.0,
        labels      = {"platform": "virustotal"},
    )
    assert e.value                     == 1.0
    assert e.labels["platform"]        == "virustotal"
    assert e.timestamp is not None


def test_metric_event_to_dict():
    from gnat.metrics.models import MetricEvent, MetricType

    e = MetricEvent(MetricType.ENRICHMENT_LATENCY, 245.0, labels={"p": "vt"})
    d = e.to_dict()
    assert d["metric_type"]   == "enrichment_latency"
    assert d["value"]          == 245.0
    assert d["labels"]["p"]    == "vt"


# ── MetricsCollector ──────────────────────────────────────────────────────────

def test_collector_record_and_snapshot():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    col = MetricsCollector(max_size=100)
    col.record(MetricType.INVESTIGATION_OPENED, 1.0, investigation_id="inv-1")
    col.record(MetricType.ENRICHMENT_HIT, 1.0, platform="vt")

    events = col.snapshot()
    assert len(events) == 2


def test_collector_snapshot_filtered():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    col = MetricsCollector()
    col.record(MetricType.ENRICHMENT_HIT,  1.0)
    col.record(MetricType.ENRICHMENT_MISS, 1.0)
    col.record(MetricType.ENRICHMENT_HIT,  1.0)

    hits = col.snapshot(MetricType.ENRICHMENT_HIT)
    assert len(hits) == 2
    misses = col.snapshot(MetricType.ENRICHMENT_MISS)
    assert len(misses) == 1


def test_collector_ring_buffer_evicts_old():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    col = MetricsCollector(max_size=3)
    for i in range(5):
        col.record(MetricType.ENRICHMENT_HIT, float(i))

    events = col.snapshot()
    # Only last 3 retained
    assert len(events) == 3
    values = [e.value for e in events]
    assert values == [2.0, 3.0, 4.0]


def test_collector_since():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType, MetricEvent

    col = MetricsCollector()
    past   = datetime.now(tz=timezone.utc) - timedelta(hours=2)
    recent = datetime.now(tz=timezone.utc) - timedelta(minutes=5)

    old_evt = MetricEvent(MetricType.ENRICHMENT_HIT, 1.0)
    old_evt.timestamp = past
    new_evt = MetricEvent(MetricType.ENRICHMENT_HIT, 2.0)
    new_evt.timestamp = recent

    with col._lock:
        col._buffer.append(old_evt)
        col._buffer.append(new_evt)

    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    result = col.since(cutoff)
    assert len(result) == 1
    assert result[0].value == 2.0


def test_collector_clear():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    col = MetricsCollector()
    col.record(MetricType.ENRICHMENT_HIT, 1.0)
    assert len(col) == 1
    col.clear()
    assert len(col) == 0


def test_collector_thread_safe():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType
    import threading

    col = MetricsCollector(max_size=1000)

    def emit():
        for _ in range(50):
            col.record(MetricType.ENRICHMENT_HIT, 1.0)

    threads = [threading.Thread(target=emit) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(col) == 500


# ── MetricsAggregator ─────────────────────────────────────────────────────────

@pytest.fixture
def populated_collector():
    from gnat.metrics.collector import MetricsCollector
    from gnat.metrics.models import MetricType

    col = MetricsCollector()
    # 3 opened, 2 closed
    for _ in range(3):
        col.record(MetricType.INVESTIGATION_OPENED, 1.0)
    for _ in range(2):
        col.record(MetricType.INVESTIGATION_CLOSED, 1.0)
    # Duration: 2 events, 100s and 200s
    col.record(MetricType.INVESTIGATION_DURATION, 100.0)
    col.record(MetricType.INVESTIGATION_DURATION, 200.0)
    # Enrichment: 4 hits, 1 miss, latency 50ms
    for _ in range(4):
        col.record(MetricType.ENRICHMENT_HIT,  1.0, platform="virustotal")
    col.record(MetricType.ENRICHMENT_MISS, 1.0, platform="virustotal")
    col.record(MetricType.ENRICHMENT_LATENCY, 50.0, platform="virustotal")
    # 1 report published
    col.record(MetricType.REPORT_PUBLISHED, 1.0)
    # 2 gaps detected
    for _ in range(2):
        col.record(MetricType.GAP_DETECTED, 1.0, investigation_id="inv-1")
    return col


def test_investigation_summary(populated_collector):
    from gnat.metrics.aggregator import MetricsAggregator

    agg = MetricsAggregator(populated_collector)
    s   = agg.investigation_summary(days=1)

    assert s["total_opened"] == 3
    assert s["total_closed"] == 2
    assert s["completion_rate"] == pytest.approx(2/3, rel=1e-3)
    assert s["avg_duration_seconds"] == pytest.approx(150.0)


def test_enrichment_effectiveness_all_platforms(populated_collector):
    from gnat.metrics.aggregator import MetricsAggregator

    agg = MetricsAggregator(populated_collector)
    eff = agg.enrichment_effectiveness(days=1)

    assert eff["total_requests"] == 5
    assert eff["hits"]           == 4
    assert eff["misses"]         == 1
    assert eff["hit_rate"]       == pytest.approx(0.8)
    assert eff["avg_latency_ms"] == pytest.approx(50.0)


def test_enrichment_effectiveness_filtered_platform(populated_collector):
    from gnat.metrics.aggregator import MetricsAggregator

    agg = MetricsAggregator(populated_collector)
    eff = agg.enrichment_effectiveness(platform="virustotal", days=1)
    assert eff["hit_rate"] == pytest.approx(0.8)

    # Non-existent platform → 0 requests
    zero = agg.enrichment_effectiveness(platform="nonexistent", days=1)
    assert zero["total_requests"] == 0
    assert zero["hit_rate"]       == 0.0


def test_gap_frequency(populated_collector):
    from gnat.metrics.aggregator import MetricsAggregator

    agg = MetricsAggregator(populated_collector)
    gf  = agg.gap_frequency(days=1)

    assert gf["total_gaps"]                    == 2
    assert gf["by_investigation"]["inv-1"]     == 2


def test_false_positive_rate_empty():
    from gnat.metrics.aggregator import MetricsAggregator
    from gnat.metrics.collector import MetricsCollector

    col = MetricsCollector()
    agg = MetricsAggregator(col)
    fp  = agg.false_positive_rate(days=1)
    assert fp["total_flagged"] == 0
    assert fp["by_platform"]   == {}


# ── gnat.metrics __init__ exports ─────────────────────────────────────────────

def test_metrics_init_exports():
    import gnat.metrics as m
    assert hasattr(m, "MetricsCollector")
    assert hasattr(m, "MetricsAggregator")
    assert hasattr(m, "MetricEvent")
    assert hasattr(m, "MetricType")
