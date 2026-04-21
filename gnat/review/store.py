"""
gnat.review.store
==================
SQLAlchemy-backed persistence for the AI-extracted intel review queue.

Schema: single ``review_queue`` table — id, stix_id, status, and a JSON
blob containing the full :class:`~gnat.review.models.ReviewItem`.  This
follows the same JSON-blob pattern used by ``InvestigationStore`` and
``ReportStore`` so no new migration framework is needed.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("gnat.review.store")


class ReviewQueueStore:
    """
    Persist and query :class:`~gnat.review.models.ReviewItem` objects.

    Parameters
    ----------
    db_url : str
        SQLAlchemy database URL (e.g. ``"sqlite:///gnat.db"``).
    """

    def __init__(self, db_url: str) -> None:
        try:
            from sqlalchemy import (
                Column,
                DateTime,
                Index,
                String,
                Text,
                create_engine,
            )
            from sqlalchemy.orm import DeclarativeBase, sessionmaker
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'SQLAlchemy is required for ReviewQueueStore. Run: pip install "gnat[persist]"'
            ) from exc

        self._engine = create_engine(db_url, future=True)
        self._Session = sessionmaker(bind=self._engine, future=True)

        class _Base(DeclarativeBase):
            pass

        class _ReviewModel(_Base):
            __tablename__ = "review_queue"
            __table_args__ = (
                Index("ix_review_queue_status", "status"),
                Index("ix_review_queue_stix_id", "stix_id"),
                Index("ix_review_queue_stix_type", "stix_type"),
            )
            id = Column(String(36), primary_key=True)
            stix_id = Column(String(128), nullable=False)
            stix_type = Column(String(64), nullable=False)
            status = Column(String(16), nullable=False, default="pending")
            submitted_at = Column(DateTime, nullable=False)
            reviewed_at = Column(DateTime, nullable=True)
            data_json = Column(Text, nullable=False)

        self._Base = _Base
        self._Model = _ReviewModel
        self._Session = self._Session

    def create_all(self) -> None:
        """Create the ``review_queue`` table if it does not exist."""
        self._Base.metadata.create_all(self._engine)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def save(self, item: Any) -> None:
        """Insert or update a ReviewItem."""
        from sqlalchemy.orm import Session

        with Session(self._engine) as session:
            existing = session.get(self._Model, item.id)
            blob = json.dumps(item.to_dict(), default=str)
            if existing is None:
                row = self._Model(
                    id=item.id,
                    stix_id=item.stix_id,
                    stix_type=item.stix_type,
                    status=item.status.value,
                    submitted_at=item.submitted_at.replace(tzinfo=None)
                    if item.submitted_at.tzinfo
                    else item.submitted_at,
                    reviewed_at=(
                        item.reviewed_at.replace(tzinfo=None)
                        if item.reviewed_at and item.reviewed_at.tzinfo
                        else item.reviewed_at
                    ),
                    data_json=blob,
                )
                session.add(row)
            else:
                existing.status = item.status.value
                existing.reviewed_at = (
                    item.reviewed_at.replace(tzinfo=None)
                    if item.reviewed_at and item.reviewed_at.tzinfo
                    else item.reviewed_at
                )
                existing.data_json = blob
            session.commit()

    def delete(self, item_id: str) -> bool:
        """Delete a review item by id. Returns True if found and deleted."""
        from sqlalchemy.orm import Session

        with Session(self._engine) as session:
            row = session.get(self._Model, item_id)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(self, item_id: str) -> Any | None:
        """Return a ReviewItem by id, or None."""
        from sqlalchemy.orm import Session

        from gnat.review.models import ReviewItem

        with Session(self._engine) as session:
            row = session.get(self._Model, item_id)
            if row is None:
                return None
            return ReviewItem.from_dict(json.loads(row.data_json))

    def list(
        self,
        status: str | None = None,
        stix_type: str | None = None,
        submitted_by: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[Any]:
        """
        List review items with optional filters.

        Parameters
        ----------
        status : str, optional
            Filter by status (``"pending"``, ``"approved"``, etc.).
        stix_type : str, optional
            Filter by STIX object type.
        submitted_by : str, optional
            Filter by submitter.
        page : int
            1-based page number.
        page_size : int
            Items per page (max 500).
        """
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        from gnat.review.models import ReviewItem

        page_size = max(1, min(500, page_size))
        offset = (max(1, page) - 1) * page_size

        with Session(self._engine) as session:
            stmt = select(self._Model).order_by(self._Model.submitted_at.desc())
            if status:
                stmt = stmt.where(self._Model.status == status)
            if stix_type:
                stmt = stmt.where(self._Model.stix_type == stix_type)
            stmt = stmt.offset(offset).limit(page_size)
            rows = session.execute(stmt).scalars().all()

        items = [ReviewItem.from_dict(json.loads(r.data_json)) for r in rows]
        if submitted_by:
            items = [i for i in items if i.submitted_by == submitted_by]
        return items

    def count(self, status: str | None = None) -> int:
        """Return the total number of items, optionally filtered by status."""
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        with Session(self._engine) as session:
            stmt = select(func.count()).select_from(self._Model)
            if status:
                stmt = stmt.where(self._Model.status == status)
            return session.execute(stmt).scalar_one()

    def stats(self) -> dict[str, int]:
        """Return counts keyed by status value."""
        from gnat.review.models import ReviewStatus

        return {status.value: self.count(status.value) for status in ReviewStatus}
