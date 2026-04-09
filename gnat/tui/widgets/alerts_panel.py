# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.widgets.alerts_panel
==============================

Sticky alerts panel displayed at the top of all TUI screens.

Polls :class:`~gnat.review.service.ReviewService` and
:class:`~gnat.analysis.copilot.gap_detector.GapDetector` every
``poll_interval`` seconds and displays a badge count of pending items.

Usage::

    from gnat.tui.widgets.alerts_panel import AlertsPanel

    # Mount above TabbedContent in the app
    yield AlertsPanel(
        review_service = review_service,
        gap_detector   = gap_detector,
        poll_interval  = 30,
    )
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget
from textual.widgets import Label, Static


class AlertsPanel(Widget):
    """
    Compact status bar showing pending review count and critical gap count.

    Parameters
    ----------
    review_service : ReviewService, optional
        Supplies pending HITL review item count.
    gap_detector : GapDetector, optional
        Supplies CRITICAL/HIGH gap count.
    poll_interval : int
        Seconds between polls.  Default ``30``.
    """

    DEFAULT_CSS = """
    AlertsPanel {
        height: 1;
        background: $panel;
        layout: horizontal;
        padding: 0 1;
    }
    AlertsPanel .badge {
        background: $error;
        color: $text;
        padding: 0 1;
        margin-right: 1;
    }
    AlertsPanel .badge-ok {
        background: $success;
        color: $text;
        padding: 0 1;
        margin-right: 1;
    }
    AlertsPanel .label {
        color: $text-muted;
        margin-right: 2;
    }
    """

    pending_reviews: reactive[int] = reactive(0)
    critical_gaps:   reactive[int] = reactive(0)

    def __init__(
        self,
        review_service: Any = None,
        gap_detector:   Any = None,
        poll_interval:  int = 30,
        **kwargs: Any,
    ) -> None:
        """Initialize AlertsPanel."""
        super().__init__(**kwargs)
        self._review_service = review_service
        self._gap_detector   = gap_detector
        self._poll_interval  = poll_interval
        self._timer: Timer | None = None

    def compose(self) -> ComposeResult:
        """Render the alerts panel."""
        yield Label("⚡", classes="label")
        yield Static("", id="review-badge")
        yield Static("", id="gaps-badge")

    def on_mount(self) -> None:
        """Start polling timer."""
        self._refresh_counts()
        self._timer = self.set_interval(self._poll_interval, self._refresh_counts)

    def on_unmount(self) -> None:
        """Stop polling timer."""
        if self._timer:
            self._timer.stop()

    def _refresh_counts(self) -> None:
        """Poll services and update counts."""
        self._update_review_count()
        self._update_gap_count()

    def _update_review_count(self) -> None:
        if self._review_service is None:
            self.pending_reviews = 0
            return
        try:
            items = self._review_service.list(status="pending", page=1, page_size=1)
            # Some implementations return a tuple (items, total) or just a list
            if isinstance(items, tuple):
                self.pending_reviews = items[1]
            else:
                # Try getting total from pagination attribute
                total = getattr(items, "total", None)
                if total is not None:
                    self.pending_reviews = total
                else:
                    self.pending_reviews = len(items)
        except Exception:
            self.pending_reviews = 0

    def _update_gap_count(self) -> None:
        if self._gap_detector is None:
            self.critical_gaps = 0
            return
        try:
            gaps = self._gap_detector.detect()
            if isinstance(gaps, list):
                self.critical_gaps = sum(
                    1 for g in gaps
                    if getattr(g, "severity", "") in ("critical", "high")
                )
            else:
                self.critical_gaps = 0
        except Exception:
            self.critical_gaps = 0

    def watch_pending_reviews(self, count: int) -> None:
        """Update the review badge when count changes."""
        badge = self.query_one("#review-badge", Static)
        if count > 0:
            badge.update(f" {count} pending reviews ")
            badge.set_classes("badge")
        else:
            badge.update(" reviews OK ")
            badge.set_classes("badge-ok")

    def watch_critical_gaps(self, count: int) -> None:
        """Update the gaps badge when count changes."""
        badge = self.query_one("#gaps-badge", Static)
        if count > 0:
            badge.update(f" {count} critical gaps ")
            badge.set_classes("badge")
        else:
            badge.update(" gaps OK ")
            badge.set_classes("badge-ok")
