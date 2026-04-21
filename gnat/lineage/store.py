"""
gnat.lineage.store
===================

Append-only SQLAlchemy persistence for :class:`~.models.LineageEvent` objects.

The ``lineage_events`` table is strictly append-only — no row is ever updated
or hard-deleted.  This matches the Alembic migration in
``alembic/versions/0002_add_lineage_events.py``.

Usage::

    from gnat.lineage.store import LineageStore
    from gnat.lineage.models import LineageEvent, LineageEventType

    store = LineageStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()

    evt = LineageEvent(
        event_type  = LineageEventType.INGESTED,
        object_id   = "indicator--abc",
        object_type = "indicator",
        actor       = "threatq-connector",
        source      = "threatq",
    )
    store.append(evt)

    # Query by object
    events = store.query("indicator--abc")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from gnat.lineage.models import LineageEvent, LineageEventType

logger = logging.getLogger(__name__)

try:
    from sqlalchemy import (
        Column,
        DateTime,
        Index,
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
            "sqlalchemy is required for LineageStore. Install with: pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


if _SA_AVAILABLE:

    class _Base(DeclarativeBase):
        pass

    class LineageEventModel(_Base):
        """SQLAlchemy model for a lineage event."""

        __tablename__ = "lineage_events"

        # Auto-increment integer PK; the UUID 'id' is stored in metadata_json
        pk = Column(Integer, primary_key=True, autoincrement=True)
        id = Column(String(36), nullable=False, unique=True, index=True)
        event_type = Column(String(32), nullable=False, index=True)
        object_id = Column(String(256), nullable=False)
        object_type = Column(String(64), nullable=False)
        actor = Column(String(256), nullable=False)
        source = Column(String(256), nullable=False)
        metadata_json = Column(Text, nullable=False, default="{}")
        timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

        __table_args__ = (Index("ix_lineage_object_timestamp", "object_id", "timestamp"),)

        def to_event(self) -> LineageEvent:
            meta = json.loads(self.metadata_json or "{}")
            return LineageEvent(
                id=self.id,
                event_type=LineageEventType(self.event_type),
                object_id=self.object_id,
                object_type=self.object_type,
                actor=self.actor,
                source=self.source,
                timestamp=self.timestamp,
                metadata=meta,
            )

        @classmethod
        def from_event(cls, evt: LineageEvent) -> LineageEventModel:
            et = evt.event_type
            return cls(
                id=evt.id,
                event_type=et.value if hasattr(et, "value") else str(et),
                object_id=evt.object_id,
                object_type=evt.object_type,
                actor=evt.actor,
                source=evt.source,
                metadata_json=json.dumps(evt.metadata),
                timestamp=evt.timestamp,
            )


class LineageStore:
    """
    Append-only persistence layer for :class:`~.models.LineageEvent` objects.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.
    echo : bool
        Enable SQL echo logging.
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        _require_sqlalchemy()
        self._engine = create_engine(url, echo=echo, future=True)
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    @classmethod
    def from_engine(cls, engine: Any) -> LineageStore:
        _require_sqlalchemy()
        instance = cls.__new__(cls)
        instance._engine = engine
        instance._Session = sessionmaker(bind=engine, expire_on_commit=False)
        return instance

    def create_all(self) -> None:
        """Create the lineage_events table (idempotent — use in tests)."""
        _require_sqlalchemy()
        _Base.metadata.create_all(self._engine)

    def drop_all(self) -> None:
        """Drop lineage_events table. Use in tests only."""
        _require_sqlalchemy()
        _Base.metadata.drop_all(self._engine)

    def append(self, event: LineageEvent) -> None:
        """Persist a lineage event (append-only)."""
        _require_sqlalchemy()
        with self._Session() as session:
            session.add(LineageEventModel.from_event(event))
            session.commit()
        et_name = (
            event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        )
        logger.debug("LineageStore: appended %s for %s", et_name, event.object_id)

    def query(self, object_id: str, limit: int = 500) -> list[LineageEvent]:
        """Return all events for *object_id*, ordered oldest-first."""
        _require_sqlalchemy()
        with self._Session() as session:
            rows = (
                session.query(LineageEventModel)
                .filter(LineageEventModel.object_id == object_id)
                .order_by(LineageEventModel.timestamp.asc())
                .limit(limit)
                .all()
            )
        return [r.to_event() for r in rows]

    def query_by_type(
        self,
        event_type: LineageEventType,
        limit: int = 500,
    ) -> list[LineageEvent]:
        """Return the most recent *limit* events of *event_type*."""
        _require_sqlalchemy()
        with self._Session() as session:
            rows = (
                session.query(LineageEventModel)
                .filter(LineageEventModel.event_type == event_type.value)
                .order_by(LineageEventModel.timestamp.desc())
                .limit(limit)
                .all()
            )
        return [r.to_event() for r in rows]

    def query_by_actor(self, actor: str, limit: int = 500) -> list[LineageEvent]:
        """Return the most recent *limit* events for *actor*."""
        _require_sqlalchemy()
        with self._Session() as session:
            rows = (
                session.query(LineageEventModel)
                .filter(LineageEventModel.actor == actor)
                .order_by(LineageEventModel.timestamp.desc())
                .limit(limit)
                .all()
            )
        return [r.to_event() for r in rows]

    def count(self, event_type: LineageEventType | None = None) -> int:
        """Return total event count, optionally filtered by type."""
        _require_sqlalchemy()
        with self._Session() as session:
            q = session.query(LineageEventModel)
            if event_type is not None:
                q = q.filter(LineageEventModel.event_type == event_type.value)
            return q.count()
