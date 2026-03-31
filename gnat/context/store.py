"""
gnat.context.store
======================

SQLAlchemy-backed persistence layer for GNAT contexts and workspaces.

Design
------
The STIX ORM objects (:class:`~gnat.orm.base.STIXBase` and subclasses)
remain pure Python — they are **not** SQLAlchemy models.  Instead, this
module defines a thin set of SQLAlchemy models that store *serialised*
STIX JSON alongside workspace metadata.  The conversion is:

.. code-block:: text

    STIXBase  ──to_dict()──►  JSON blob  ──SQLAlchemy──►  Database row
    Database row  ──json──►  dict  ──STIXBase.from_dict()──►  STIXBase

This keeps the two layers completely decoupled:

* STIX objects can be used without any DB.
* The DB schema never leaks into business logic.
* Swapping storage backends (SQLite → PostgreSQL) requires zero ORM changes.

Supported backends
------------------
* **SQLite** (default) — zero-config, single-file, ideal for local workspaces.
  ``sqlite:///~/.gnat/workspaces.db``
* **PostgreSQL** — for shared team contexts.
  ``postgresql+psycopg2://user:pass@host/dbname``
* **In-memory SQLite** — for tests.
  ``sqlite:///:memory:``
* **Flat-file JSON** — human-readable backup / export, no SQLAlchemy needed.
  Managed by :class:`FlatFileStore`.

Schema overview
---------------
.. code-block:: text

    workspaces
      id, name, description, created_at, updated_at, metadata_json

    workspace_objects
      id, workspace_id (FK), stix_id, stix_type, stix_json,
      source_platform, created_at, updated_at, is_dirty, is_deleted

    enrichment_log
      id, workspace_id (FK), stix_id, source_platform, enrichment_json,
      strategy, created_at

    context_globals
      id, name, target_platform, is_default, created_at
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLAlchemy imports — optional; raise helpful error if not installed
# ---------------------------------------------------------------------------

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        ForeignKey,
        Integer,
        String,
        Text,
        UniqueConstraint,
        create_engine,
        event,
    )
    from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise ImportError(
            "SQLAlchemy is required for workspace persistence: "
            "pip install 'gnat[persist]'"
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# SQLAlchemy declarative base
# ---------------------------------------------------------------------------

if _HAS_SQLALCHEMY:
    class _Base(DeclarativeBase):
        pass

    # ── Workspace ──────────────────────────────────────────────────────────

    class WorkspaceModel(_Base):
        """
        Represents a named analyst workspace (local context).

        Each workspace is an isolated collection of STIX objects loaded
        from one or more global platform contexts.
        """
        __tablename__ = "workspaces"

        id          = Column(Integer, primary_key=True, autoincrement=True)
        name        = Column(String(255), nullable=False, unique=True, index=True)
        description = Column(Text, nullable=True)
        created_at  = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
        updated_at  = Column(DateTime(timezone=True), default=_utcnow,
                             onupdate=_utcnow, nullable=False)
        # Arbitrary JSON metadata (analyst notes, tags, config overrides, etc.)
        metadata_json = Column(Text, nullable=True, default="{}")

        objects      = relationship("WorkspaceObjectModel",
                                    back_populates="workspace",
                                    cascade="all, delete-orphan",
                                    lazy="dynamic")
        enrichments  = relationship("EnrichmentLogModel",
                                    back_populates="workspace",
                                    cascade="all, delete-orphan",
                                    lazy="dynamic")

        def meta(self) -> dict:
            return json.loads(self.metadata_json or "{}")

        def set_meta(self, data: dict) -> None:
            self.metadata_json = json.dumps(data)

        def __repr__(self) -> str:
            return f"<Workspace name={self.name!r} id={self.id}>"

    # ── WorkspaceObject ────────────────────────────────────────────────────

    class WorkspaceObjectModel(_Base):
        """
        A single STIX object stored inside a workspace.

        The full STIX JSON is stored in ``stix_json``.  Key fields are also
        mirrored as indexed columns for efficient querying without full JSON
        deserialisation.
        """
        __tablename__ = "workspace_objects"
        __table_args__ = (
            UniqueConstraint("workspace_id", "stix_id",
                             name="uq_workspace_stix_id"),
        )

        id              = Column(Integer, primary_key=True, autoincrement=True)
        workspace_id    = Column(Integer, ForeignKey("workspaces.id",
                                 ondelete="CASCADE"), nullable=False, index=True)
        stix_id         = Column(String(255), nullable=False, index=True)
        stix_type       = Column(String(64),  nullable=False, index=True)
        stix_name       = Column(String(512), nullable=True,  index=True)
        # The full STIX object as JSON
        stix_json       = Column(Text, nullable=False)
        # Which platform this object was loaded from
        source_platform = Column(String(64), nullable=True)
        created_at      = Column(DateTime(timezone=True), default=_utcnow)
        updated_at      = Column(DateTime(timezone=True), default=_utcnow,
                                 onupdate=_utcnow)
        # True if this object has been modified since loading from the platform
        is_dirty        = Column(Boolean, default=False, nullable=False)
        # Soft-delete — marks objects removed from workspace without DB purge
        is_deleted      = Column(Boolean, default=False, nullable=False)

        workspace = relationship("WorkspaceModel", back_populates="objects")

        def to_stix_dict(self) -> dict:
            return json.loads(self.stix_json)

        def __repr__(self) -> str:
            return (f"<WorkspaceObject stix_id={self.stix_id!r} "
                    f"type={self.stix_type!r} dirty={self.is_dirty}>")

    # ── EnrichmentLog ──────────────────────────────────────────────────────

    class EnrichmentLogModel(_Base):
        """
        Records each enrichment operation applied to a workspace object.

        Stores the full enrichment payload so that enrichment can be
        replayed, audited, or reversed.
        """
        __tablename__ = "enrichment_log"

        id              = Column(Integer, primary_key=True, autoincrement=True)
        workspace_id    = Column(Integer, ForeignKey("workspaces.id",
                                 ondelete="CASCADE"), nullable=False, index=True)
        # The STIX id of the object that was enriched
        stix_id         = Column(String(255), nullable=False, index=True)
        # Platform that provided the enrichment
        source_platform = Column(String(64), nullable=False)
        # Full enrichment result as JSON (STIX dict or extension fields)
        enrichment_json = Column(Text, nullable=False)
        # Merge strategy used ("merge_extensions", "create_relationships", "tag_only")
        strategy        = Column(String(64), nullable=False, default="merge_extensions")
        created_at      = Column(DateTime(timezone=True), default=_utcnow)

        workspace = relationship("WorkspaceModel", back_populates="enrichments")

        def enrichment_data(self) -> dict:
            return json.loads(self.enrichment_json)

        def __repr__(self) -> str:
            return (f"<EnrichmentLog stix_id={self.stix_id!r} "
                    f"source={self.source_platform!r}>")

    # ── GlobalContextModel ─────────────────────────────────────────────────

    class GlobalContextModel(_Base):
        """
        Persists a registered global context (platform + connection alias).

        Multiple global contexts can be registered; one is marked as default.
        """
        __tablename__ = "context_globals"

        id              = Column(Integer, primary_key=True, autoincrement=True)
        name            = Column(String(128), nullable=False, unique=True)
        target_platform = Column(String(64),  nullable=False)
        is_default      = Column(Boolean, default=False, nullable=False)
        config_json     = Column(Text, nullable=True, default="{}")
        created_at      = Column(DateTime(timezone=True), default=_utcnow)

        def config(self) -> dict:
            return json.loads(self.config_json or "{}")

        def __repr__(self) -> str:
            return (f"<GlobalContext name={self.name!r} "
                    f"platform={self.target_platform!r} "
                    f"default={self.is_default}>")


# ---------------------------------------------------------------------------
# WorkspaceStore — session factory and high-level DB operations
# ---------------------------------------------------------------------------

class WorkspaceStore:
    """
    High-level interface to the SQLAlchemy-backed workspace database.

    Handles engine creation, schema initialisation, and provides
    CRUD operations used by :class:`~gnat.context.workspace.Workspace`.

    Parameters
    ----------
    url : str
        SQLAlchemy database URL.  Examples:

        * ``"sqlite:///~/.gnat/workspaces.db"`` — local file
        * ``"sqlite:///:memory:"`` — in-memory (tests)
        * ``"postgresql+psycopg2://user:pass@host/ctmsak"`` — PostgreSQL

    echo : bool
        If ``True``, echo all SQL to stdout (debug).

    Examples
    --------
    >>> store = WorkspaceStore("sqlite:///~/.gnat/workspaces.db")
    >>> store.create_all()
    """

    def __init__(self, url: str, echo: bool = False):
        _require_sqlalchemy()
        # Expand ~ in SQLite paths
        if url.startswith("sqlite:///") and "~" in url:
            path = url[len("sqlite:///"):]
            url = "sqlite:///" + str(Path(path).expanduser())

        self._url = url
        self._engine = create_engine(url, echo=echo, future=True)

        # Enable WAL mode for SQLite — better concurrent read performance
        if url.startswith("sqlite"):
            @event.listens_for(self._engine, "connect")
            def _set_wal(dbapi_conn, _rec):
                dbapi_conn.execute("PRAGMA journal_mode=WAL")
                dbapi_conn.execute("PRAGMA foreign_keys=ON")

        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    def create_all(self) -> None:
        """Create all tables (idempotent — safe to call repeatedly)."""
        _Base.metadata.create_all(self._engine)
        logger.debug("WorkspaceStore: schema initialised at %s", self._url)

    def drop_all(self) -> None:
        """Drop all tables. Destructive — for tests only."""
        _Base.metadata.drop_all(self._engine)

    def session(self) -> Session:
        """Return a new SQLAlchemy session. Caller must close/commit."""
        return self._Session()

    # ── Workspace CRUD ─────────────────────────────────────────────────────

    def create_workspace(self, name: str, description: str = "",
                         metadata: dict | None = None) -> WorkspaceModel:
        """Create and persist a new named workspace."""
        with self.session() as sess:
            ws = WorkspaceModel(
                name=name,
                description=description,
                metadata_json=json.dumps(metadata or {}),
            )
            sess.add(ws)
            sess.commit()
            logger.info("WorkspaceStore: created workspace %r", name)
            return ws

    def get_workspace(self, name: str) -> WorkspaceModel | None:
        """Return the workspace with *name*, or ``None``."""
        with self.session() as sess:
            return sess.query(WorkspaceModel).filter_by(name=name).first()

    def get_or_create_workspace(self, name: str, **kwargs: Any) -> WorkspaceModel:
        """Return an existing workspace or create it."""
        existing = self.get_workspace(name)
        if existing:
            return existing
        return self.create_workspace(name, **kwargs)

    def list_workspaces(self) -> list[WorkspaceModel]:
        """Return all workspaces ordered by name."""
        with self.session() as sess:
            return sess.query(WorkspaceModel).order_by(WorkspaceModel.name).all()

    def delete_workspace(self, name: str) -> bool:
        """Delete a workspace and all its objects. Returns True if found."""
        with self.session() as sess:
            ws = sess.query(WorkspaceModel).filter_by(name=name).first()
            if ws is None:
                return False
            sess.delete(ws)
            sess.commit()
            logger.info("WorkspaceStore: deleted workspace %r", name)
            return True

    # ── Object CRUD ────────────────────────────────────────────────────────

    def upsert_object(self, workspace_id: int, stix_dict: dict,
                      source_platform: str = "", is_dirty: bool = False) -> WorkspaceObjectModel:
        """
        Insert or update a STIX object in a workspace.

        If an object with the same ``workspace_id`` + ``stix_id`` already
        exists it is updated in-place; otherwise a new row is inserted.
        """
        with self.session() as sess:
            existing = (
                sess.query(WorkspaceObjectModel)
                .filter_by(workspace_id=workspace_id, stix_id=stix_dict["id"])
                .first()
            )
            if existing:
                existing.stix_json       = json.dumps(stix_dict)
                existing.stix_name       = stix_dict.get("name", "")
                existing.updated_at      = _utcnow()
                existing.is_dirty        = is_dirty
                existing.is_deleted      = False
                if source_platform:
                    existing.source_platform = source_platform
                sess.commit()
                return existing

            obj = WorkspaceObjectModel(
                workspace_id    = workspace_id,
                stix_id         = stix_dict["id"],
                stix_type       = stix_dict.get("type", ""),
                stix_name       = stix_dict.get("name", ""),
                stix_json       = json.dumps(stix_dict),
                source_platform = source_platform,
                is_dirty        = is_dirty,
            )
            sess.add(obj)
            sess.commit()
            return obj

    def get_objects(self, workspace_id: int,
                    stix_type: str | None = None,
                    include_deleted: bool = False) -> list[dict]:
        """Return STIX dicts for all objects in a workspace."""
        with self.session() as sess:
            q = sess.query(WorkspaceObjectModel).filter_by(workspace_id=workspace_id)
            if not include_deleted:
                q = q.filter_by(is_deleted=False)
            if stix_type:
                q = q.filter_by(stix_type=stix_type)
            return [row.to_stix_dict() for row in q.all()]

    def get_dirty_objects(self, workspace_id: int) -> list[dict]:
        """Return STIX dicts for objects modified since last commit."""
        with self.session() as sess:
            rows = (
                sess.query(WorkspaceObjectModel)
                .filter_by(workspace_id=workspace_id, is_dirty=True, is_deleted=False)
                .all()
            )
            return [r.to_stix_dict() for r in rows]

    def mark_clean(self, workspace_id: int) -> None:
        """Mark all dirty objects as clean after a successful commit."""
        with self.session() as sess:
            (sess.query(WorkspaceObjectModel)
             .filter_by(workspace_id=workspace_id, is_dirty=True)
             .update({"is_dirty": False, "updated_at": _utcnow()}))
            sess.commit()

    def soft_delete_object(self, workspace_id: int, stix_id: str) -> bool:
        """Mark an object deleted without removing it from the DB."""
        with self.session() as sess:
            obj = (sess.query(WorkspaceObjectModel)
                   .filter_by(workspace_id=workspace_id, stix_id=stix_id)
                   .first())
            if obj is None:
                return False
            obj.is_deleted = True
            obj.is_dirty   = True
            obj.updated_at = _utcnow()
            sess.commit()
            return True

    # ── Enrichment log ─────────────────────────────────────────────────────

    def log_enrichment(self, workspace_id: int, stix_id: str,
                       source_platform: str, enrichment_data: dict,
                       strategy: str = "merge_extensions") -> EnrichmentLogModel:
        """Append an enrichment record to the log."""
        with self.session() as sess:
            entry = EnrichmentLogModel(
                workspace_id    = workspace_id,
                stix_id         = stix_id,
                source_platform = source_platform,
                enrichment_json = json.dumps(enrichment_data),
                strategy        = strategy,
            )
            sess.add(entry)
            sess.commit()
            return entry

    def get_enrichment_history(self, workspace_id: int,
                               stix_id: str | None = None) -> list[dict]:
        """Return the enrichment log for a workspace, optionally filtered by object."""
        with self.session() as sess:
            q = sess.query(EnrichmentLogModel).filter_by(workspace_id=workspace_id)
            if stix_id:
                q = q.filter_by(stix_id=stix_id)
            return [
                {
                    "stix_id":         e.stix_id,
                    "source_platform": e.source_platform,
                    "strategy":        e.strategy,
                    "created_at":      e.created_at.isoformat() if e.created_at else "",
                    "data":            e.enrichment_data(),
                }
                for e in q.order_by(EnrichmentLogModel.created_at).all()
            ]

    def object_count(self, workspace_id: int) -> int:
        """Return count of non-deleted objects in the workspace."""
        with self.session() as sess:
            return (sess.query(WorkspaceObjectModel)
                    .filter_by(workspace_id=workspace_id, is_deleted=False)
                    .count())

    def __repr__(self) -> str:  # pragma: no cover
        return f"WorkspaceStore(url={self._url!r})"


# ---------------------------------------------------------------------------
# FlatFileStore — JSON fallback, no SQLAlchemy required
# ---------------------------------------------------------------------------

class FlatFileStore:
    """
    JSON flat-file workspace store — no database required.

    Each workspace is a directory containing:

    .. code-block:: text

        ~/.gnat/workspaces/<name>/
            workspace.json          # metadata
            objects/
                <stix-id>.json      # one file per STIX object
            enrichment_log.jsonl    # append-only enrichment log

    Parameters
    ----------
    base_dir : str or Path
        Root directory for all flat-file workspaces.
        Default: ``~/.gnat/workspaces``

    Examples
    --------
    >>> store = FlatFileStore("~/my-workspaces")
    >>> store.save_object("apt28", indicator.to_dict(), source="threatq")
    """

    def __init__(self, base_dir: str | None = None):
        self._base = Path(base_dir or "~/.gnat/workspaces").expanduser()
        self._base.mkdir(parents=True, exist_ok=True)

    def _ws_dir(self, name: str) -> Path:
        return self._base / name

    def _objects_dir(self, name: str) -> Path:
        d = self._ws_dir(name) / "objects"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _meta_path(self, name: str) -> Path:
        return self._ws_dir(name) / "workspace.json"

    def _log_path(self, name: str) -> Path:
        return self._ws_dir(name) / "enrichment_log.jsonl"

    # ── Workspace lifecycle ────────────────────────────────────────────────

    def create_workspace(self, name: str, description: str = "",
                         metadata: dict | None = None) -> dict:
        """Create a workspace directory and write metadata."""
        ws_dir = self._ws_dir(name)
        ws_dir.mkdir(parents=True, exist_ok=True)
        (ws_dir / "objects").mkdir(exist_ok=True)
        meta = {
            "name":        name,
            "description": description,
            "created_at":  _utcnow().isoformat(),
            "updated_at":  _utcnow().isoformat(),
            "metadata":    metadata or {},
        }
        self._meta_path(name).write_text(json.dumps(meta, indent=2))
        logger.info("FlatFileStore: created workspace %r at %s", name, ws_dir)
        return meta

    def get_workspace(self, name: str) -> dict | None:
        """Return workspace metadata or ``None`` if not found."""
        p = self._meta_path(name)
        if not p.exists():
            return None
        return json.loads(p.read_text())

    def get_or_create_workspace(self, name: str, **kwargs: Any) -> dict:
        return self.get_workspace(name) or self.create_workspace(name, **kwargs)

    def list_workspaces(self) -> list[dict]:
        """List all workspace metadata dicts."""
        result = []
        for ws_dir in sorted(self._base.iterdir()):
            meta_p = ws_dir / "workspace.json"
            if meta_p.exists():
                result.append(json.loads(meta_p.read_text()))
        return result

    def delete_workspace(self, name: str) -> bool:
        """Delete the workspace directory entirely."""
        import shutil
        ws_dir = self._ws_dir(name)
        if not ws_dir.exists():
            return False
        shutil.rmtree(ws_dir)
        logger.info("FlatFileStore: deleted workspace %r", name)
        return True

    # ── Object CRUD ────────────────────────────────────────────────────────

    def save_object(self, workspace_name: str, stix_dict: dict,
                    source_platform: str = "", is_dirty: bool = False) -> None:
        """Write a STIX object to disk as an individual JSON file."""
        stix_id = stix_dict["id"]
        safe_id = stix_id.replace("--", "_").replace("/", "_")
        envelope = {
            "stix":            stix_dict,
            "source_platform": source_platform,
            "is_dirty":        is_dirty,
            "saved_at":        _utcnow().isoformat(),
        }
        path = self._objects_dir(workspace_name) / f"{safe_id}.json"
        path.write_text(json.dumps(envelope, indent=2))

    def get_objects(self, workspace_name: str,
                    stix_type: str | None = None) -> list[dict]:
        """Load all STIX objects from a workspace directory."""
        objs_dir = self._objects_dir(workspace_name)
        result = []
        for f in sorted(objs_dir.glob("*.json")):
            try:
                envelope = json.loads(f.read_text())
                stix = envelope.get("stix", envelope)  # handle plain stix files too
                if stix_type and stix.get("type") != stix_type:
                    continue
                result.append(stix)
            except json.JSONDecodeError:
                logger.warning("FlatFileStore: bad JSON in %s", f)
        return result

    def get_dirty_objects(self, workspace_name: str) -> list[dict]:
        objs_dir = self._objects_dir(workspace_name)
        result = []
        for f in sorted(objs_dir.glob("*.json")):
            try:
                envelope = json.loads(f.read_text())
                if envelope.get("is_dirty"):
                    result.append(envelope["stix"])
            except json.JSONDecodeError:
                pass
        return result

    def delete_object(self, workspace_name: str, stix_id: str) -> bool:
        safe_id = stix_id.replace("--", "_").replace("/", "_")
        p = self._objects_dir(workspace_name) / f"{safe_id}.json"
        if p.exists():
            p.unlink()
            return True
        return False

    def object_count(self, workspace_name: str) -> int:
        return len(list(self._objects_dir(workspace_name).glob("*.json")))

    # ── Enrichment log ─────────────────────────────────────────────────────

    def log_enrichment(self, workspace_name: str, stix_id: str,
                       source_platform: str, enrichment_data: dict,
                       strategy: str = "create_relationships") -> None:
        """Append an enrichment entry to the JSONL log."""
        entry = {
            "stix_id":         stix_id,
            "source_platform": source_platform,
            "strategy":        strategy,
            "created_at":      _utcnow().isoformat(),
            "data":            enrichment_data,
        }
        with self._log_path(workspace_name).open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def get_enrichment_history(self, workspace_name: str,
                               stix_id: str | None = None) -> list[dict]:
        log_path = self._log_path(workspace_name)
        if not log_path.exists():
            return []
        result = []
        for line in log_path.read_text().splitlines():
            try:
                entry = json.loads(line)
                if stix_id is None or entry.get("stix_id") == stix_id:
                    result.append(entry)
            except json.JSONDecodeError:
                pass
        return result

    def export_bundle(self, workspace_name: str) -> dict:
        """Export the entire workspace as a STIX 2.1 bundle."""
        import uuid as _uuid
        objects = self.get_objects(workspace_name)
        return {
            "type":         "bundle",
            "id":           f"bundle--{_uuid.uuid4()}",
            "spec_version": "2.1",
            "objects":      objects,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"FlatFileStore(base_dir={self._base!r})"
