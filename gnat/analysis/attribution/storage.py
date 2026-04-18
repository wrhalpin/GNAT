# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.attribution.storage
=====================================

Persistence layer for :class:`~.models.CampaignProfile` objects.

Follows the same "indexed metadata columns + full JSON blob" pattern
as :class:`~gnat.analysis.investigations.storage.InvestigationStore`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from gnat.analysis.attribution.models import CampaignProfile
from gnat.analysis.attribution.query import CampaignQuery

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional SQLAlchemy imports (gated by gnat[persist])
# ---------------------------------------------------------------------------

try:
    from sqlalchemy import Boolean, Column, DateTime, String, Text, create_engine
    from sqlalchemy.orm import DeclarativeBase, sessionmaker

    _SA_AVAILABLE = True
except ImportError:
    _SA_AVAILABLE = False


def _require_sqlalchemy() -> None:
    if not _SA_AVAILABLE:
        raise ImportError(
            "sqlalchemy is required for campaign persistence. "
            "Install with: pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


if _SA_AVAILABLE:

    class _Base(DeclarativeBase):
        pass

    class CampaignModel(_Base):
        """SQLAlchemy model backing :class:`CampaignProfile`."""

        __tablename__ = "campaigns"

        id = Column(String(64), primary_key=True)
        name = Column(String(512), nullable=False, index=True)
        status = Column(String(32), nullable=False, index=True, default="suspected")
        classification = Column(String(32), nullable=False, default="amber")
        parent_campaign_id = Column(String(64), nullable=True, index=True)
        threat_actor_id = Column(String(64), nullable=True, index=True)
        tags_csv = Column(Text, nullable=True, default="")
        campaign_json = Column(Text, nullable=False)
        created_at = Column(
            DateTime(timezone=True), default=_utcnow, nullable=False, index=True
        )
        updated_at = Column(
            DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
        )
        is_deleted = Column(Boolean, default=False, nullable=False)

        def to_campaign(self) -> CampaignProfile:
            data = json.loads(self.campaign_json)
            return CampaignProfile.from_dict(data)

        @classmethod
        def from_campaign(cls, c: CampaignProfile) -> CampaignModel:
            return cls(
                id=c.id,
                name=c.name,
                status=c.status.value,
                classification=c.classification,
                parent_campaign_id=c.parent_campaign_id,
                threat_actor_id=c.threat_actor_id,
                tags_csv=",".join(c.tags),
                campaign_json=json.dumps(c.to_dict()),
                created_at=c.created_at,
                updated_at=c.updated_at,
                is_deleted=False,
            )


class CampaignStore:
    """
    Persistence layer for :class:`CampaignProfile` objects.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        _require_sqlalchemy()
        self._engine = create_engine(url, echo=echo, future=True)
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    def create_all(self) -> None:
        _require_sqlalchemy()
        _Base.metadata.create_all(self._engine)

    def drop_all(self) -> None:
        _require_sqlalchemy()
        _Base.metadata.drop_all(self._engine)

    # ── CRUD ──────────────────────────────────────────────────────────────

    def save(self, campaign: CampaignProfile) -> CampaignProfile:
        _require_sqlalchemy()
        campaign.updated_at = _utcnow()

        with self._Session() as session:
            existing = session.get(CampaignModel, campaign.id)
            if existing:
                existing.name = campaign.name
                existing.status = campaign.status.value
                existing.classification = campaign.classification
                existing.parent_campaign_id = campaign.parent_campaign_id
                existing.threat_actor_id = campaign.threat_actor_id
                existing.tags_csv = ",".join(campaign.tags)
                existing.campaign_json = json.dumps(campaign.to_dict())
                existing.updated_at = campaign.updated_at
            else:
                session.add(CampaignModel.from_campaign(campaign))
            session.commit()
        return campaign

    def get(self, campaign_id: str) -> CampaignProfile | None:
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(CampaignModel, campaign_id)
            if row is None or row.is_deleted:
                return None
            return row.to_campaign()

    def delete(self, campaign_id: str) -> bool:
        _require_sqlalchemy()
        with self._Session() as session:
            row = session.get(CampaignModel, campaign_id)
            if row is None or row.is_deleted:
                return False
            row.is_deleted = True
            row.updated_at = _utcnow()
            session.commit()
        return True

    def list(
        self,
        query: CampaignQuery | None = None,
    ) -> list[CampaignProfile]:
        _require_sqlalchemy()
        query = query or CampaignQuery()
        with self._Session() as session:
            q = session.query(CampaignModel).filter(
                CampaignModel.is_deleted == False  # noqa: E712
            )
            if query.status:
                q = q.filter(
                    CampaignModel.status.in_([s.value for s in query.status])
                )
            if query.threat_actor_id:
                q = q.filter(CampaignModel.threat_actor_id == query.threat_actor_id)
            if query.parent_campaign_id:
                q = q.filter(
                    CampaignModel.parent_campaign_id == query.parent_campaign_id
                )
            if query.tags:
                for tag in query.tags:
                    q = q.filter(CampaignModel.tags_csv.contains(tag))
            if query.text_search:
                term = f"%{query.text_search}%"
                q = q.filter(
                    CampaignModel.name.ilike(term)
                    | CampaignModel.campaign_json.ilike(term)
                )
            q = q.order_by(CampaignModel.updated_at.desc())
            offset = (query.page - 1) * query.page_size
            rows = q.offset(offset).limit(query.page_size).all()
            return [row.to_campaign() for row in rows]

    def count(self, query: CampaignQuery | None = None) -> int:
        _require_sqlalchemy()
        query = query or CampaignQuery()
        with self._Session() as session:
            q = session.query(CampaignModel).filter(
                CampaignModel.is_deleted == False  # noqa: E712
            )
            if query.status:
                q = q.filter(
                    CampaignModel.status.in_([s.value for s in query.status])
                )
            return q.count()
