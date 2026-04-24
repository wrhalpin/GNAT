# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.dissemination.api.key_store_db
====================================

SQLAlchemy-backed persistent storage for API keys.

Follows the same pattern as
:class:`~gnat.analysis.investigations.storage.InvestigationStore`:

- Core model (:class:`~gnat.dissemination.api.auth.APIKey`) is a pure
  Python dataclass — no ORM coupling.
- SQLAlchemy model (:class:`APIKeyModel`) lives only in this module.
- Guard import with ``try/except ImportError``.
- Key metadata serialized as JSON in a text column.
- Indexed columns for ``token_hash``, ``tenant_id``, ``enabled``.

Usage::

    from gnat.dissemination.api.key_store_db import SQLAlchemyKeyStore
    from gnat.dissemination.api.auth import APIKey
    from gnat.analysis.tlp import TLPLevel

    store = SQLAlchemyKeyStore("sqlite:///~/.gnat/keys.db")
    store.create_all()

    key = APIKey(token="secret", tlp_level=TLPLevel.AMBER, label="SIEM")
    store.save(key)
    retrieved = store.get_key("secret")
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.api.auth import APIKey, APIKeyStore

logger = logging.getLogger(__name__)

# Guard: SQLAlchemy is optional
try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        String,
        Text,
        create_engine,
    )
    from sqlalchemy.orm import DeclarativeBase, sessionmaker

    _SA_AVAILABLE = True
except ImportError:
    _SA_AVAILABLE = False


def _require_sqlalchemy() -> None:
    """Raise ImportError when SQLAlchemy is not installed."""
    if not _SA_AVAILABLE:
        raise ImportError(
            "sqlalchemy is required for persistent API key storage. "
            "Install with: pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(tz=timezone.utc)


def _token_hash(token: str) -> str:
    """Return the full SHA-256 hex digest of *token*."""
    return hashlib.sha256(token.encode()).hexdigest()


if _SA_AVAILABLE:

    class _Base(DeclarativeBase):
        """Declarative base for API key tables."""

    class APIKeyModel(_Base):
        """SQLAlchemy row model for :class:`~gnat.dissemination.api.auth.APIKey`."""

        __tablename__ = "api_keys"

        token_hash = Column(String(64), primary_key=True)
        token = Column(String(512), nullable=False, unique=True)
        tlp_level = Column(String(32), nullable=False)
        label = Column(String(256), nullable=False, default="")
        role = Column(String(64), nullable=False, default="viewer")
        tenant_id = Column(String(128), nullable=True, index=True)
        created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
        expires_at = Column(DateTime(timezone=True), nullable=True)
        enabled = Column(Boolean, default=True, nullable=False, index=True)
        metadata_json = Column(Text, nullable=False, default="{}")

        def to_api_key(self) -> APIKey:
            """Convert to a domain :class:`APIKey`."""
            return APIKey(
                token=self.token,
                tlp_level=TLPLevel(self.tlp_level),
                label=self.label or "",
                role=self.role or "viewer",
                tenant_id=self.tenant_id,
                created_at=self.created_at or _utcnow(),
                expires_at=self.expires_at,
                enabled=bool(self.enabled),
                metadata=json.loads(self.metadata_json) if self.metadata_json else {},
            )

        @classmethod
        def from_api_key(cls, key: APIKey) -> APIKeyModel:
            """Create a row from a domain :class:`APIKey`."""
            return cls(
                token_hash=_token_hash(key.token),
                token=key.token,
                tlp_level=key.tlp_level.value,
                label=key.label,
                role=key.role,
                tenant_id=key.tenant_id,
                created_at=key.created_at,
                expires_at=key.expires_at,
                enabled=key.enabled,
                metadata_json=json.dumps(key.metadata),
            )


class SQLAlchemyKeyStore(APIKeyStore):
    """
    Database-backed API key store.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.  Use ``"sqlite:///:memory:"`` for tests.
    echo : bool
        Pass ``True`` to enable SQL logging.

    Notes
    -----
    This class overrides :class:`APIKeyStore` CRUD methods so that all
    mutations are persisted.  The in-memory ``_keys`` dict is **not**
    used — every call hits the database for consistency.
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        _require_sqlalchemy()
        super().__init__()
        self._url = url
        self._engine = create_engine(url, echo=echo, future=True)
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    def create_all(self) -> None:
        """Create API key tables (idempotent)."""
        _require_sqlalchemy()
        _Base.metadata.create_all(self._engine)
        logger.debug("SQLAlchemyKeyStore: tables created/verified")

    def drop_all(self) -> None:
        """Drop API key tables.  Use in tests only."""
        _require_sqlalchemy()
        _Base.metadata.drop_all(self._engine)

    # -- CRUD --------------------------------------------------------------

    def save(self, key: APIKey) -> APIKey:
        """
        Persist an :class:`APIKey` (insert or update).

        Parameters
        ----------
        key : APIKey
            The key to persist.

        Returns
        -------
        APIKey
            The same object (for chaining).
        """
        _require_sqlalchemy()
        th = _token_hash(key.token)
        with self._Session() as session:
            existing = session.get(APIKeyModel, th)
            if existing is not None:
                existing.token = key.token
                existing.tlp_level = key.tlp_level.value
                existing.label = key.label
                existing.role = key.role
                existing.tenant_id = key.tenant_id
                existing.expires_at = key.expires_at
                existing.enabled = key.enabled
                existing.metadata_json = json.dumps(key.metadata)
            else:
                session.add(APIKeyModel.from_api_key(key))
            session.commit()
        return key

    def add_key(
        self,
        token: str,
        tlp_level: TLPLevel,
        label: str = "",
        role: str = "viewer",
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> APIKey:
        """Register and persist an API key."""
        key = APIKey(
            token=token,
            tlp_level=tlp_level,
            label=label,
            role=role,
            tenant_id=tenant_id,
            expires_at=expires_at,
            metadata=metadata or {},
        )
        return self.save(key)

    def get_key(self, token: str) -> APIKey | None:
        """Return the :class:`APIKey` for *token*, or ``None``."""
        _require_sqlalchemy()
        th = _token_hash(token)
        with self._Session() as session:
            row = session.get(APIKeyModel, th)
            if row is None:
                return None
            return row.to_api_key()

    def list_keys(self) -> list[APIKey]:
        """Return all registered keys."""
        _require_sqlalchemy()
        with self._Session() as session:
            rows = session.query(APIKeyModel).all()
            return [r.to_api_key() for r in rows]

    def revoke_key(self, token: str) -> bool:
        """Disable a key in the database.  Returns ``True`` if found."""
        _require_sqlalchemy()
        th = _token_hash(token)
        with self._Session() as session:
            row = session.get(APIKeyModel, th)
            if row is None:
                return False
            row.enabled = False
            session.commit()
        return True

    def delete_key(self, token: str) -> bool:
        """Remove a key entirely.  Returns ``True`` if found."""
        _require_sqlalchemy()
        th = _token_hash(token)
        with self._Session() as session:
            row = session.get(APIKeyModel, th)
            if row is None:
                return False
            session.delete(row)
            session.commit()
        return True

    def __len__(self) -> int:
        _require_sqlalchemy()
        with self._Session() as session:
            return session.query(APIKeyModel).count()
