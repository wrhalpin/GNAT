"""
gnat.metrics.aggregator
========================

Time-windowed metric aggregation over a :class:`~.collector.MetricsCollector`.

Usage::

    from gnat.metrics.aggregator import MetricsAggregator
    from gnat.metrics.collector import MetricsCollector

    collector   = MetricsCollector()
    aggregator  = MetricsAggregator(collector)

    summary = aggregator.investigation_summary(days=30)
    # {'total_opened': 42, 'total_closed': 38, ...}

    eff = aggregator.enrichment_effectiveness(platform="virustotal", days=7)
    # {'platform': 'virustotal', 'hit_rate': 0.87, 'total_requests': 100, ...}

    gaps = aggregator.gap_frequency(days=30)
    # [{'count': 15}, ...]
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from gnat.metrics.models import MetricType


class MetricsAggregator:
    """
    Compute time-windowed summaries from a :class:`~.collector.MetricsCollector`.

    Parameters
    ----------
    collector : MetricsCollector
        The source of metric events.
    """

    def __init__(self, collector: Any) -> None:
        self._collector = collector

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _cutoff(self, days: int) -> datetime:
        return datetime.now(tz=timezone.utc) - timedelta(days=days)

    # ── Investigation metrics ─────────────────────────────────────────────────

    def investigation_summary(self, days: int = 30) -> dict[str, Any]:
        """
        Summarise investigation activity for the past *days* days.

        Returns
        -------
        dict with keys:
            ``total_opened``, ``total_closed``,
            ``completion_rate``,
            ``avg_duration_seconds``,
            ``report_rate``
        """
        cutoff = self._cutoff(days)

        opened = self._collector.since(cutoff, MetricType.INVESTIGATION_OPENED)
        closed = self._collector.since(cutoff, MetricType.INVESTIGATION_CLOSED)
        duration = self._collector.since(cutoff, MetricType.INVESTIGATION_DURATION)
        reported = self._collector.since(cutoff, MetricType.REPORT_PUBLISHED)

        n_opened = len(opened)
        n_closed = len(closed)
        completion = n_closed / n_opened if n_opened else 0.0
        avg_dur = sum(e.value for e in duration) / len(duration) if duration else 0.0
        report_rt = n_closed / len(reported) if reported else 0.0

        return {
            "days": days,
            "total_opened": n_opened,
            "total_closed": n_closed,
            "completion_rate": round(completion, 4),
            "avg_duration_seconds": round(avg_dur, 1),
            "report_rate": round(report_rt, 4),
        }

    # ── Enrichment metrics ────────────────────────────────────────────────────

    def enrichment_effectiveness(
        self,
        platform: str | None = None,
        days: int = 7,
    ) -> dict[str, Any]:
        """
        Enrichment hit rate for the past *days* days.

        Parameters
        ----------
        platform : str, optional
            Filter to a specific platform label.
        days : int

        Returns
        -------
        dict with keys:
            ``platform``, ``days``,
            ``total_requests``, ``hits``, ``misses``,
            ``hit_rate``,
            ``avg_latency_ms``
        """
        cutoff = self._cutoff(days)

        def _platform_filter(events: list) -> list:
            if platform is None:
                return events
            return [e for e in events if e.labels.get("platform") == platform]

        hits = _platform_filter(self._collector.since(cutoff, MetricType.ENRICHMENT_HIT))
        misses = _platform_filter(self._collector.since(cutoff, MetricType.ENRICHMENT_MISS))
        latency = _platform_filter(self._collector.since(cutoff, MetricType.ENRICHMENT_LATENCY))

        total = len(hits) + len(misses)
        hit_rt = len(hits) / total if total else 0.0
        avg_lat = sum(e.value for e in latency) / len(latency) if latency else 0.0

        return {
            "platform": platform or "all",
            "days": days,
            "total_requests": total,
            "hits": len(hits),
            "misses": len(misses),
            "hit_rate": round(hit_rt, 4),
            "avg_latency_ms": round(avg_lat, 1),
        }

    # ── Gap frequency ─────────────────────────────────────────────────────────

    def gap_frequency(self, days: int = 30) -> dict[str, Any]:
        """
        Count gap detection events for the past *days* days.

        Returns
        -------
        dict with keys:
            ``days``, ``total_gaps``,
            ``by_investigation``: dict[investigation_id → count]
        """
        cutoff = self._cutoff(days)
        events = self._collector.since(cutoff, MetricType.GAP_DETECTED)

        by_inv: dict[str, int] = {}
        for e in events:
            inv_id = e.labels.get("investigation_id", "unknown")
            by_inv[inv_id] = by_inv.get(inv_id, 0) + 1

        return {
            "days": days,
            "total_gaps": len(events),
            "by_investigation": by_inv,
        }

    # ── False positive rate ───────────────────────────────────────────────────

    def false_positive_rate(self, days: int = 30) -> dict[str, Any]:
        """
        False-positive flag rate for the past *days* days.

        Returns
        -------
        dict with keys: ``days``, ``total_flagged``, ``by_platform``
        """
        cutoff = self._cutoff(days)
        events = self._collector.since(cutoff, MetricType.FALSE_POSITIVE_FLAGGED)

        by_platform: dict[str, int] = {}
        for e in events:
            platform = e.labels.get("platform", "unknown")
            by_platform[platform] = by_platform.get(platform, 0) + 1

        return {
            "days": days,
            "total_flagged": len(events),
            "by_platform": by_platform,
        }
