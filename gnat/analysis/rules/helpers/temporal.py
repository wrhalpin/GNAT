# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Temporal helpers — age, staleness, freshness."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def age_days(h: Any, now: datetime | None = None) -> int:
    """Days since hypothesis was created."""
    now = now or _now()
    created = getattr(h, "created_at", now)
    return max(0, (now - created).days)


def days_since_update(h: Any, now: datetime | None = None) -> int:
    """Days since hypothesis was last updated."""
    now = now or _now()
    updated = getattr(h, "updated_at", now)
    return max(0, (now - updated).days)


def stale(h: Any, days: int = 30, now: datetime | None = None) -> bool:
    """True if hypothesis has not been updated in the given number of days."""
    return days_since_update(h, now) >= days


def fresh(h: Any, days: int = 7, now: datetime | None = None) -> bool:
    """True if hypothesis was updated within the given number of days."""
    return days_since_update(h, now) <= days
