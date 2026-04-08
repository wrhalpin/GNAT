"""
gnat.analysis.investigations.storage
======================================

SQLAlchemy-backed persistence for :class:`~.models.Investigation` objects.

Follows the same pattern as :class:`~gnat.context.store.WorkspaceStore`:
- Core model objects (Investigation) are pure Python dataclasses
- SQLAlchemy only in this module — zero ORM dependency in models
- Objects serialized as JSON in a text column + indexed metadata columns

Usage::

    from gnat.analysis.investigations.storage import InvestigationStore

    store = InvestigationStore("sqlite:///~/.gnat/investigations.db")
    store.create_all()

    inv = Investigation(title="Ransomware Apr 2026", created_by="analyst@example.com")
    store.save(inv)
    retrieved = store.get(inv.id)

    # Or use an existing engine (e.g. shared with WorkspaceStore):
    store = InvestigationStore.from_engine(existing_engine)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.investigations.models import Investigation, InvestigationStatus
from gnat.analysis.query import InvestigationQuery

logger = logging.getLogger(__name__)

# Guard: SQLAlchemy is optional
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
    if not _SA_AVAILABLE:
        raise ImportError(
            "sqlalchemy is required for investigation persistence. "
            "Install with: pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


if _SA_AVAILABLE:
    class _Base(DeclarativeBase):
        pass

    class InvestigationModel(_Base):
        """SQLAlchemy model backing :class:`~.models.Investigation`."""

        __tablename__ = "investigations"

        id              = Column(String(36),  primary_key=True)
        title           = Column(String(512), nullable=False, index=True)
        status          = Column(String(32),  nullable=False, index=True, default="open")
        classification  = Column(String(32),  nullable=False, default="amber")
        created_by      = Column(String(256), nullable=False, index=True)
        tags_csv        = Column(Text,        nullable=True,  default="")
        investigation_json = Column(Text,     nullable=False)
        created_at      = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
        updated_at      = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
        is_deleted      = Column(Boolean,     default=False, nullable=False)

        def to_investigation(self) -> Investigation:
            data = json.loads(self.investigation_json)
            return Investigation.from_dict(data)

        @classmethod
        def from_investigation(cls, inv: Investigation) -> "InvestigationModel":
            return cls(
                id                 = inv.id,
                title              = inv.title,
                status             = inv.status.value,
                classification     = inv.classification.value,
                created_by         = inv.created_by,
                tags_csv           = ",".join(inv.tags),
                investigation_json = json.dumps(inv.to_dict()),
                created_at         = inv.created_at,
                updated_at         = inv.updated_at,
                is_deleted         = False,
            )


class InvestigationStore:
    """
    Persistence layer for :class:`~.models.Investigation` objects.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.  Use ``"sqlite:///~/.gnat/gnat.db"`` for
        the default local store or ``"sqlite:///:memory:"`` in tests.
    echo : bool
        Pass ``True`` to enable SQLAlchemy SQL logging.

    Examples
    --------
    >>> store = InvestigationStore("sqlite:///:memory:")
    >>> store.create_all()
    >>> inv = Investigation(title="Test", created_by="analyst")
    >>> store.save(inv)
    >>> store.get(inv.id).title
    'Test'
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        _require_sqlalchemy()
        self._url = url
        self._engine = create_engine(url, echo=echo, future=True)
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    @classmethod
    def from_engine(cls, engine: Any) -> "InvestigationStore":
        """Create a store reusing an existing SQLAlchemy engine."""
        _require_sqlalchemy()
        instance = cls.__new__(cls)
        instance._url    = str(engine.url)
        instance._engine = engine
        instance._Session = sessionmaker(bind=engine, expire_on_commit=False)
        return instance

    def create_all(self) -> None:
        """Create all investigation tables (idempotent)."""
        _require_sqlalchemy()
        _Base.metadata.create_all(self._engine)
        logger.debug("InvestigationStore: tables created/verified")

    def drop_all(self) -> None:
        """Drop all investigation tables. Use in tests only."""
        _require_sqlalchemy()
        _Base.metadata.drop_all(self._engine)

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def save(self, investigation: Investigation) -> Investigation:
        """
        Persist *investigation* (insert or update).

        The ``updated_at`` timestamp is refreshed on every call.

        Parameters
        ----------
        investigation : Investigation
            The investigation to persist.

        Returns
        -------
        Investigation
            The same object (for chaining).
        """
        _require_sqlalchemy()
        from datetime import timezone as _tz
        investigation.updated_at = datetime.now(tz=_tz.utc)

        with self._Session() as session:
            existing = session.get(InvestigationModel, investigation.id)
            if existing:
                existing.title              = investigation.title
                existing.status             = investigation.status.value
                existing.classification     = investigation.classification.value
                existing.created_by         = investigation.created_by
                existing.tags_csv           = ",".join(investigation.tags)
                existing.investigation_json = json.dumps(investigation.to_dict())
                existing.updated_at         = investigation.updated_at
            else:
                session.add(InvestigationModel.from_investigation(investigation))
            session.commit()
            logger.debug("InvestigationStore: saved investigation %s", investigation.id)
        return investigation

    def get(self, investigation_id: str) -> Investigation | None:
        """
        Retrieve an Investigation by ID.

        Returns ``None`` if the ID is not found or has been soft-deleted.
        """
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(InvestigationModel, investigation_id)
            if row is None or row.is_deleted:
                return None
            return row.to_investigation()

    def list(
        self,
        query: InvestigationQuery | None = None,
        # Legacy kwargs — kept for backward compatibility; prefer InvestigationQuery
        status: InvestigationStatus | None = None,
        created_by: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Investigation]:
        """
        List investigations with optional filters.

        Pass an :class:`~gnat.analysis.query.InvestigationQuery` for rich
        filtering and pagination.  Legacy keyword arguments are still accepted
        for backward compatibility.

        Parameters
        ----------
        query : InvestigationQuery, optional
            Structured filter + pagination model.
        status : InvestigationStatus, optional
            *(Legacy)* Filter by lifecycle status.
        created_by : str, optional
            *(Legacy)* Filter by analyst identifier.
        tag : str, optional
            *(Legacy)* Filter to investigations containing this tag.
        limit : int
            *(Legacy)* Maximum number of results (default 100).
        offset : int
            *(Legacy)* Skip the first *offset* results.

        Returns
        -------
        list of Investigation
        """
        _require_sqlalchemy()

        # Build an InvestigationQuery from legacy kwargs when no query given
        if query is None:
            from gnat.analysis.query import InvestigationQuery as _IQ
            query = _IQ(
                status     = [status] if status is not None else None,
                created_by = created_by,
                tags       = [tag] if tag is not None else None,
                page_size  = limit,
            )
            # Override offset directly (legacy callers use raw offset, not page)
            _offset = offset
            _limit  = limit
        else:
            _offset = query.offset
            _limit  = query.limit

        with self._Session() as session:
            q = session.query(InvestigationModel).filter(
                InvestigationModel.is_deleted == False  # noqa: E712
            )

            # Status filter
            sv = query.status_values
            if sv:
                q = q.filter(InvestigationModel.status.in_(sv))

            # created_by
            if query.created_by is not None:
                q = q.filter(InvestigationModel.created_by == query.created_by)

            # Tags — ANY match (CSV substring per tag)
            if query.tags:
                from sqlalchemy import or_
                tag_clauses = [
                    InvestigationModel.tags_csv.contains(t)
                    for t in query.tags
                ]
                q = q.filter(or_(*tag_clauses))

            # Classification / TLP
            cv = query.classification_values
            if cv:
                q = q.filter(InvestigationModel.classification.in_(cv))

            # Date range on created_at
            if query.date_from is not None:
                q = q.filter(InvestigationModel.created_at >= query.date_from)
            if query.date_to is not None:
                q = q.filter(InvestigationModel.created_at <= query.date_to)

            # Text search — title substring (description is in the JSON blob)
            if query.text:
                q = q.filter(
                    InvestigationModel.title.ilike(f"%{query.text}%")
                )

            # Sorting
            sort_col = getattr(InvestigationModel, query.safe_sort_by,
                               InvestigationModel.updated_at)
            q = q.order_by(sort_col.desc() if query.sort_desc else sort_col.asc())

            rows = q.offset(_offset).limit(_limit).all()
            investigations = [r.to_investigation() for r in rows]

        # Post-filter: has_hypothesis / has_linked_report (stored in JSON blob)
        if query.has_hypothesis is not None:
            investigations = [
                inv for inv in investigations
                if bool(inv.hypothesis) == query.has_hypothesis
            ]
        if query.has_linked_report is not None:
            investigations = [
                inv for inv in investigations
                if bool(inv.reports) == query.has_linked_report
            ]

        return investigations

    def delete(self, investigation_id: str) -> bool:
        """
        Soft-delete an Investigation.

        Returns ``True`` if the record was found and marked deleted,
        ``False`` if it did not exist.
        """
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(InvestigationModel, investigation_id)
            if row is None:
                return False
            row.is_deleted = True
            session.commit()
            logger.debug("InvestigationStore: deleted investigation %s", investigation_id)
            return True

    def count(self, status: InvestigationStatus | None = None) -> int:
        """Return the count of non-deleted investigations, optionally filtered by status."""
        _require_sqlalchemy()
        with self._Session() as session:
            q = session.query(InvestigationModel).filter(
                InvestigationModel.is_deleted == False  # noqa: E712
            )
            if status is not None:
                q = q.filter(InvestigationModel.status == status.value)
            return q.count()
