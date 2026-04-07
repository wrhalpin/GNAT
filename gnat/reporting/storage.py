# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting.storage
========================

SQLAlchemy-backed persistence for :class:`~.models.Report` objects.

Follows the same pattern as :class:`~gnat.context.store.WorkspaceStore` and
:class:`~gnat.analysis.investigations.storage.InvestigationStore`:

- Core model (Report) is a pure Python dataclass — zero SQLAlchemy in models
- Repository handles session lifecycle and JSON serialisation
- ``create_all()`` is idempotent — no migration framework required

Usage::

    from gnat.reporting.storage import ReportStore
    from gnat.reporting.models import Report, ReportType

    store = ReportStore("sqlite:///:memory:")
    store.create_all()

    report = Report(title="BLACKCAT Apr 2026", report_type=ReportType.INCIDENT_REPORT)
    store.save(report)
    retrieved = store.get(report.id)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from gnat.reporting.models import Report, ReportStatus, ReportType

logger = logging.getLogger(__name__)

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Integer,
        String,
        Text,
        create_engine,
    )
    from sqlalchemy.orm import DeclarativeBase, sessionmaker

    _SA_AVAILABLE = True
except ImportError:
    _SA_AVAILABLE = False


def _require_sqlalchemy() -> None:
    """Internal helper for require sqlalchemy."""
    if not _SA_AVAILABLE:
        raise ImportError(
            "sqlalchemy is required for report persistence. "
            "Install with: pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    """Internal helper for utcnow."""
    return datetime.now(tz=timezone.utc)


if _SA_AVAILABLE:
    class _Base(DeclarativeBase):
        """_Base implementation."""
        pass

    class ReportModel(_Base):
        """SQLAlchemy model backing :class:`~.models.Report`."""

        __tablename__ = "reports"

        id               = Column(String(36),  primary_key=True)
        title            = Column(String(512), nullable=False, index=True)
        report_type      = Column(String(64),  nullable=False, index=True)
        status           = Column(String(32),  nullable=False, index=True, default="draft")
        classification   = Column(String(32),  nullable=False, default="amber")
        authors_csv      = Column(Text,        nullable=True,  default="")
        tags_csv         = Column(Text,        nullable=True,  default="")
        linked_investigation = Column(String(36), nullable=True, index=True)
        stix_report_ref  = Column(String(255), nullable=True,  index=True)
        parent_report_id = Column(String(36),  nullable=True,  index=True)
        version          = Column(Integer,     nullable=False, default=1)
        report_json      = Column(Text,        nullable=False)
        published_at     = Column(DateTime(timezone=True), nullable=True)
        created_at       = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
        updated_at       = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
        is_deleted       = Column(Boolean,     default=False, nullable=False)

        def to_report(self) -> Report:
            """Convert this object to REPORT format."""
            data = json.loads(self.report_json)
            return Report.from_dict(data)

        @classmethod
        def from_report(cls, report: Report) -> "ReportModel":
            """Create an instance from REPORT data."""
            return cls(
                id                   = report.id,
                title                = report.title,
                report_type          = report.report_type.value,
                status               = report.status.value,
                classification       = report.classification.value,
                authors_csv          = ",".join(report.authors),
                tags_csv             = ",".join(report.tags),
                linked_investigation = report.linked_investigation,
                stix_report_ref      = report.stix_report_ref,
                parent_report_id     = report.parent_report_id,
                version              = report.version,
                report_json          = json.dumps(report.to_dict()),
                published_at         = report.published_at,
                created_at           = report.created_at,
                updated_at           = report.updated_at,
                is_deleted           = False,
            )


class ReportStore:
    """
    Persistence layer for :class:`~.models.Report` objects.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.
    echo : bool
        Enable SQL logging (default False).

    Examples
    --------
    >>> store = ReportStore("sqlite:///:memory:")
    >>> store.create_all()
    >>> from gnat.reporting.models import Report, ReportType
    >>> r = Report(title="Test", report_type=ReportType.INCIDENT_REPORT)
    >>> store.save(r)
    >>> store.get(r.id).title
    'Test'
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        """Initialize ReportStore."""
        _require_sqlalchemy()
        self._url = url
        self._engine = create_engine(url, echo=echo, future=True)
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    @classmethod
    def from_engine(cls, engine: Any) -> "ReportStore":
        """Create a store reusing an existing SQLAlchemy engine."""
        _require_sqlalchemy()
        instance = cls.__new__(cls)
        instance._url     = str(engine.url)
        instance._engine  = engine
        instance._Session = sessionmaker(bind=engine, expire_on_commit=False)
        return instance

    def create_all(self) -> None:
        """Create all report tables (idempotent)."""
        _require_sqlalchemy()
        _Base.metadata.create_all(self._engine)
        logger.debug("ReportStore: tables created/verified")

    def drop_all(self) -> None:
        """Drop all report tables. Use in tests only."""
        _require_sqlalchemy()
        _Base.metadata.drop_all(self._engine)

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def save(self, report: Report) -> Report:
        """
        Persist *report* (insert or update).

        Parameters
        ----------
        report : Report

        Returns
        -------
        Report
            The same object (for chaining).
        """
        _require_sqlalchemy()
        report.updated_at = datetime.now(tz=timezone.utc)

        with self._Session() as session:
            existing = session.get(ReportModel, report.id)
            if existing:
                existing.title                = report.title
                existing.report_type          = report.report_type.value
                existing.status               = report.status.value
                existing.classification       = report.classification.value
                existing.authors_csv          = ",".join(report.authors)
                existing.tags_csv             = ",".join(report.tags)
                existing.linked_investigation = report.linked_investigation
                existing.stix_report_ref      = report.stix_report_ref
                existing.parent_report_id     = report.parent_report_id
                existing.version              = report.version
                existing.report_json          = json.dumps(report.to_dict())
                existing.published_at         = report.published_at
                existing.updated_at           = report.updated_at
            else:
                session.add(ReportModel.from_report(report))
            session.commit()
            logger.debug("ReportStore: saved report %s (%s)", report.id, report.title)
        return report

    def get(self, report_id: str) -> Report | None:
        """Retrieve a Report by ID. Returns ``None`` if not found or deleted."""
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(ReportModel, report_id)
            if row is None or row.is_deleted:
                return None
            return row.to_report()

    def list(
        self,
        status:               ReportStatus | None = None,
        report_type:          ReportType | None = None,
        linked_investigation: str | None = None,
        tag:                  str | None = None,
        limit:                int = 100,
        offset:               int = 0,
    ) -> list[Report]:
        """
        List reports with optional filters.

        Parameters
        ----------
        status : ReportStatus, optional
        report_type : ReportType, optional
        linked_investigation : str, optional
            Filter to reports produced from a specific investigation.
        tag : str, optional
        limit : int
        offset : int

        Returns
        -------
        list of Report
        """
        _require_sqlalchemy()
        with self._Session() as session:
            q = session.query(ReportModel).filter(
                ReportModel.is_deleted == False  # noqa: E712
            )
            if status is not None:
                q = q.filter(ReportModel.status == status.value)
            if report_type is not None:
                q = q.filter(ReportModel.report_type == report_type.value)
            if linked_investigation is not None:
                q = q.filter(ReportModel.linked_investigation == linked_investigation)
            if tag is not None:
                q = q.filter(ReportModel.tags_csv.contains(tag))
            rows = (
                q.order_by(ReportModel.updated_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return [r.to_report() for r in rows]

    def delete(self, report_id: str) -> bool:
        """Soft-delete a Report. Returns True if found."""
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(ReportModel, report_id)
            if row is None:
                return False
            row.is_deleted = True
            session.commit()
            return True

    def count(self, status: ReportStatus | None = None) -> int:
        """Count non-deleted reports, optionally filtered by status."""
        _require_sqlalchemy()
        with self._Session() as session:
            q = session.query(ReportModel).filter(
                ReportModel.is_deleted == False  # noqa: E712
            )
            if status is not None:
                q = q.filter(ReportModel.status == status.value)
            return q.count()
