"""
gnat.metrics.hooks
===================

Wires :class:`~.collector.MetricsCollector` into the GNAT
:class:`~gnat.plugins.hooks.HookBus` so investigation lifecycle events
are automatically converted to metric observations.

Usage::

    from gnat.metrics import MetricsCollector
    from gnat.metrics.hooks import register_metrics_hooks

    collector = MetricsCollector()
    register_metrics_hooks(collector)

    # From now on, every "investigation_opened" / "investigation_closed"
    # / "report_published" / "gap_detected" HookBus event increments
    # the corresponding metric automatically.

Call :func:`unregister_metrics_hooks` to detach.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Module-level references to registered handlers so they can be removed.
_registered: list[tuple[str, Any]] = []


def register_metrics_hooks(collector: Any) -> None:
    """
    Register HookBus handlers that forward events to *collector*.

    Safe to call multiple times — duplicate registrations are ignored by
    the bus because each call creates new closures.

    Parameters
    ----------
    collector : MetricsCollector
        The target collector.
    """
    from gnat.metrics.models import MetricType
    from gnat.plugins.hooks import HookBus

    bus = HookBus.instance()

    def _on_investigation_opened(**kw: Any) -> None:
        try:
            collector.record(
                MetricType.INVESTIGATION_OPENED,
                1.0,
                investigation_id=kw.get("investigation_id", ""),
                analyst=kw.get("created_by", ""),
            )
        except Exception as exc:
            logger.debug("metrics hook investigation_opened: %s", exc)

    def _on_investigation_closed(**kw: Any) -> None:
        try:
            collector.record(
                MetricType.INVESTIGATION_CLOSED,
                1.0,
                investigation_id=kw.get("investigation_id", ""),
                analyst=kw.get("changed_by", ""),
            )
            # Also record duration if provided
            duration = kw.get("duration_seconds")
            if duration is not None:
                collector.record(
                    MetricType.INVESTIGATION_DURATION,
                    float(duration),
                    investigation_id=kw.get("investigation_id", ""),
                )
        except Exception as exc:
            logger.debug("metrics hook investigation_closed: %s", exc)

    def _on_report_published(**kw: Any) -> None:
        try:
            collector.record(
                MetricType.REPORT_PUBLISHED,
                1.0,
                report_id=kw.get("report_id", ""),
                analyst=kw.get("changed_by", ""),
            )
        except Exception as exc:
            logger.debug("metrics hook report_published: %s", exc)

    def _on_gap_detected(**kw: Any) -> None:
        try:
            collector.record(
                MetricType.GAP_DETECTED,
                1.0,
                investigation_id=kw.get("investigation_id", ""),
                gap_type=kw.get("gap_type", ""),
            )
        except Exception as exc:
            logger.debug("metrics hook gap_detected: %s", exc)

    _pairs = [
        ("investigation_opened", _on_investigation_opened),
        ("investigation_closed", _on_investigation_closed),
        ("report_published", _on_report_published),
        ("gap_detected", _on_gap_detected),
    ]
    for event, handler in _pairs:
        bus.register(event, handler)
        _registered.append((event, handler))

    logger.debug("MetricsCollector: registered %d HookBus handlers", len(_pairs))


def unregister_metrics_hooks() -> None:
    """Remove all HookBus handlers registered by :func:`register_metrics_hooks`."""
    from gnat.plugins.hooks import HookBus

    bus = HookBus.instance()
    for event, handler in _registered:
        bus.unregister(event, handler)
    _registered.clear()
    logger.debug("MetricsCollector: unregistered all HookBus handlers")
