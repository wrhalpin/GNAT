"""
gnat.analysis.query
====================

Structured query model for filtering :class:`~.investigations.models.Investigation`
objects from the persistence layer.

Design
------
``InvestigationQuery`` is a plain dataclass (zero new dependencies) that
compiles to a SQLAlchemy WHERE clause chain inside
:meth:`~.investigations.storage.InvestigationStore.list`.  It replaces the
loose ``**kwargs`` API with a typed, documented, and extensible filter model.

Usage::

    from gnat.analysis.query import InvestigationQuery
    from gnat.analysis.investigations.models import InvestigationStatus
    from gnat.analysis.tlp import TLPLevel

    q = InvestigationQuery(
        status         = [InvestigationStatus.OPEN, InvestigationStatus.IN_PROGRESS],
        created_by     = "alice@example.com",
        tags           = ["ransomware"],
        classification = [TLPLevel.AMBER, TLPLevel.RED],
        text           = "blackcat",
        page           = 1,
        page_size      = 25,
        sort_by        = "updated_at",
        sort_desc      = True,
    )
    results = store.list(q)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class InvestigationQuery:
    """
    Rich filter model for Investigation queries.

    All fields are optional — an empty ``InvestigationQuery()`` returns all
    non-deleted investigations (oldest-first, 50 per page).

    Parameters
    ----------
    status : list of InvestigationStatus, optional
        Include only investigations in one of these states.
    created_by : str, optional
        Filter by the analyst who created the investigation.
    assigned_to : str, optional
        Filter to investigations where *assigned_to* contains this value.
    tags : list of str, optional
        Include investigations that contain **any** of the listed tags.
    classification : list of TLPLevel, optional
        Include only investigations with one of these TLP levels.
    date_from : datetime, optional
        Include only investigations created at or after this timestamp.
    date_to : datetime, optional
        Include only investigations created before or at this timestamp.
    text : str, optional
        Case-insensitive substring search on ``title`` and ``description``.
    has_hypothesis : bool, optional
        If True, include only investigations with at least one hypothesis.
        If False, include only investigations with no hypotheses.
    has_linked_report : bool, optional
        If True, include only investigations that reference at least one report.
        If False, include only investigations with no linked reports.
    page : int
        1-based page number (default 1).
    page_size : int
        Results per page (default 50, max 500).
    sort_by : str
        Column to sort by: ``"created_at"`` | ``"updated_at"`` | ``"title"`` |
        ``"status"`` (default ``"updated_at"``).
    sort_desc : bool
        Sort descending when True (default True — newest first).
    """

    status: list[Any] | None = None
    created_by: str | None = None
    assigned_to: str | None = None
    tags: list[str] | None = None
    classification: list[Any] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    text: str | None = None
    has_hypothesis: bool | None = None
    has_linked_report: bool | None = None
    page: int = 1
    page_size: int = 50
    sort_by: str = "updated_at"
    sort_desc: bool = True

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def offset(self) -> int:
        """SQLAlchemy offset for the current page."""
        return (max(1, self.page) - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Clamped page_size (1–500)."""
        return max(1, min(500, self.page_size))

    @property
    def status_values(self) -> list[str] | None:
        """Status enum values as strings, or None."""
        if self.status is None:
            return None
        return [s.value if hasattr(s, "value") else str(s) for s in self.status]

    @property
    def classification_values(self) -> list[str] | None:
        """TLP level values as strings, or None."""
        if self.classification is None:
            return None
        return [c.value if hasattr(c, "value") else str(c) for c in self.classification]

    _VALID_SORT_COLUMNS: frozenset[str] = frozenset({"created_at", "updated_at", "title", "status"})

    @property
    def safe_sort_by(self) -> str:
        """Validated sort column; falls back to ``updated_at`` on invalid input."""
        return self.sort_by if self.sort_by in self._VALID_SORT_COLUMNS else "updated_at"
