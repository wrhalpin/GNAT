# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.trends
====================

Trend detection for STIX object volumes over time.

Computes sliding-window spike detection and moving averages across
STIX types and source platforms.  Uses the Solr sidecar histogram
(``facet.range``) as its data source.

Usage::

    from gnat.search import SolrSearchIndex
    from gnat.analysis.trends import TrendDetector

    idx = SolrSearchIndex.from_config(cfg)
    detector = TrendDetector(idx)

    for report in detector.detect_all(window_days=14, baseline_days=90):
        if report.is_spike:
            print(f"SPIKE: {report.stix_type} +{report.delta_pct:.0f}%")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.search.index import SolrSearchIndex

logger = logging.getLogger(__name__)

# Minimum absolute count change to flag as a spike (avoids noise on tiny volumes)
_MIN_SPIKE_DELTA = 5
# Percentage increase threshold to flag as a spike
_SPIKE_PCT_THRESHOLD = 50.0


@dataclass
class TrendReport:
    """
    Trend summary for a single STIX type (and optionally platform).

    Attributes
    ----------
    stix_type : str
        STIX object type (e.g. ``"indicator"``).
    platform : str
        Source platform filter, or ``""`` for all platforms.
    window_days : int
        Recent window length (days).
    baseline : float
        Average daily count over the baseline period.
    current : float
        Average daily count over the recent window.
    delta_pct : float
        Percentage change: ``(current - baseline) / baseline * 100``.
        Positive = increase, negative = decrease.
    is_spike : bool
        ``True`` when the increase exceeds :data:`_SPIKE_PCT_THRESHOLD`
        and the absolute delta exceeds :data:`_MIN_SPIKE_DELTA`.
    histogram : list[tuple[str, int]]
        Raw ``(date_bucket, count)`` histogram for the combined period.
    detected_at : datetime
        UTC timestamp when this report was generated.
    """

    stix_type: str
    platform: str = ""
    window_days: int = 14
    baseline: float = 0.0
    current: float = 0.0
    delta_pct: float = 0.0
    is_spike: bool = False
    histogram: list[tuple[str, int]] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "stix_type": self.stix_type,
            "platform": self.platform,
            "window_days": self.window_days,
            "baseline": round(self.baseline, 2),
            "current": round(self.current, 2),
            "delta_pct": round(self.delta_pct, 1),
            "is_spike": self.is_spike,
            "histogram": self.histogram,
            "detected_at": self.detected_at.isoformat(),
        }


class TrendDetector:
    """
    Detects volume spikes and computes moving averages for STIX types.

    Requires a :class:`~gnat.search.index.SolrSearchIndex` with the
    ``facet()`` and ``histogram()`` methods.  Falls back gracefully when
    Solr is unavailable (returns empty list).

    Parameters
    ----------
    index : SolrSearchIndex
        Solr search index with faceting support.
    baseline_days : int
        Historical window for computing the baseline daily average.
        Default ``90`` days.
    """

    _STIX_TYPES = [
        "indicator",
        "malware",
        "threat-actor",
        "attack-pattern",
        "vulnerability",
        "campaign",
        "intrusion-set",
        "course-of-action",
        "observed-data",
        "report",
    ]

    def __init__(
        self,
        index: SolrSearchIndex,
        baseline_days: int = 90,
    ) -> None:
        """Initialize TrendDetector."""
        self._index = index
        self._baseline_days = baseline_days

    def detect(
        self,
        stix_type: str,
        window_days: int = 14,
        platform: str = "",
    ) -> TrendReport:
        """
        Compute a trend report for a single STIX type.

        Parameters
        ----------
        stix_type : str
            STIX type to analyse.
        window_days : int
            Recent window length.  Default ``14``.
        platform : str
            Restrict to this source platform, or ``""`` for all.

        Returns
        -------
        TrendReport
        """
        total_days = self._baseline_days + window_days
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=total_days)
        end_dt = now + timedelta(days=1)

        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = "*:*"
        if platform:
            query = f'source_platform:"{platform}"'

        histogram = self._index.histogram(
            date_field="created",
            gap="DAY",
            query=query,
            stix_types=[stix_type],
            start=start_iso,
            end=end_iso,
        )

        if not histogram:
            return TrendReport(
                stix_type=stix_type,
                platform=platform,
                window_days=window_days,
                histogram=[],
            )

        # Split into baseline buckets (older) and window buckets (recent)
        cutoff = now - timedelta(days=window_days)
        baseline_counts: list[int] = []
        window_counts: list[int] = []

        for bucket_str, count in histogram:
            try:
                # Solr returns ISO strings like "2025-01-01T00:00:00Z"
                bucket_dt = datetime.strptime(bucket_str, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            if bucket_dt < cutoff:
                baseline_counts.append(count)
            else:
                window_counts.append(count)

        baseline_avg = sum(baseline_counts) / len(baseline_counts) if baseline_counts else 0.0
        window_avg = sum(window_counts) / len(window_counts) if window_counts else 0.0

        if baseline_avg > 0:
            delta_pct = (window_avg - baseline_avg) / baseline_avg * 100.0
        else:
            delta_pct = 100.0 if window_avg > 0 else 0.0

        is_spike = (
            delta_pct >= _SPIKE_PCT_THRESHOLD and (window_avg - baseline_avg) >= _MIN_SPIKE_DELTA
        )

        return TrendReport(
            stix_type=stix_type,
            platform=platform,
            window_days=window_days,
            baseline=baseline_avg,
            current=window_avg,
            delta_pct=delta_pct,
            is_spike=is_spike,
            histogram=histogram,
        )

    def detect_all(
        self,
        window_days: int = 14,
        platform: str = "",
        stix_types: list[str] | None = None,
    ) -> list[TrendReport]:
        """
        Detect trends for all (or specified) STIX types.

        Parameters
        ----------
        window_days : int
            Recent window.
        platform : str
            Platform filter.
        stix_types : list[str], optional
            Override the default type list.

        Returns
        -------
        list[TrendReport]
            Reports sorted by absolute ``delta_pct`` descending (biggest
            spikes first).
        """
        types = stix_types or self._STIX_TYPES
        reports: list[TrendReport] = []
        for t in types:
            try:
                report = self.detect(t, window_days=window_days, platform=platform)
                reports.append(report)
            except Exception as exc:
                logger.warning("TrendDetector: failed for type %r: %s", t, exc)
        reports.sort(key=lambda r: abs(r.delta_pct), reverse=True)
        return reports

    def spikes_only(
        self,
        window_days: int = 14,
        platform: str = "",
    ) -> list[TrendReport]:
        """Return only spiking types (shorthand for alerting use-cases)."""
        return [r for r in self.detect_all(window_days, platform) if r.is_spike]
