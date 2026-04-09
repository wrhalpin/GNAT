# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.workflow_store
===========================

Persistence layer for workflow run results.

Stores :class:`~gnat.agents.workflow.WorkflowResult` objects in the
``workflow_runs`` database table so that workflow history can be queried,
replayed, and displayed in the TUI/API.

Usage::

    from gnat.agents.workflow_store import WorkflowStore
    from gnat.agents.workflow import WorkflowContext, WorkflowResult

    store = WorkflowStore(db_url="sqlite:///gnat.db")
    run_id = store.save(result, workflow_name="phishing-triage")

    # Retrieve later
    record = store.get(run_id)
    history = store.list(workflow_name="phishing-triage", limit=20)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Status constants (mirrors WorkflowResult.success)
STATUS_SUCCESS = "success"
STATUS_FAILED  = "failed"
STATUS_RUNNING = "running"


class WorkflowRunRecord:
    """
    A single row from the ``workflow_runs`` table.

    Parameters
    ----------
    run_id : str
        UUID run identifier.
    workflow_name : str
        Name of the workflow that produced this run.
    status : str
        ``"success"`` | ``"failed"`` | ``"running"``
    context_json : str
        JSON-serialised :class:`~gnat.agents.workflow.WorkflowContext` shared dict.
    steps_completed : list[str]
        Step names that completed successfully.
    steps_failed : list[str]
        Step names that failed.
    errors : list[str]
        Human-readable error messages.
    elapsed_seconds : float
        Total wall-clock time.
    investigation_id : str | None
        Optional investigation associated with this run.
    created_at : datetime
        UTC timestamp of run start.
    updated_at : datetime
        UTC timestamp of last update.
    """

    def __init__(
        self,
        run_id: str,
        workflow_name: str,
        status: str,
        context_json: str,
        steps_completed: list[str],
        steps_failed: list[str],
        errors: list[str],
        elapsed_seconds: float,
        investigation_id: str | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.run_id          = run_id
        self.workflow_name   = workflow_name
        self.status          = status
        self.context_json    = context_json
        self.steps_completed = steps_completed
        self.steps_failed    = steps_failed
        self.errors          = errors
        self.elapsed_seconds = elapsed_seconds
        self.investigation_id = investigation_id
        self.created_at      = created_at or datetime.now(timezone.utc)
        self.updated_at      = updated_at or datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "run_id":           self.run_id,
            "workflow_name":    self.workflow_name,
            "status":           self.status,
            "steps_completed":  self.steps_completed,
            "steps_failed":     self.steps_failed,
            "errors":           self.errors,
            "elapsed_seconds":  round(self.elapsed_seconds, 3),
            "investigation_id": self.investigation_id,
            "created_at":       self.created_at.isoformat(),
            "updated_at":       self.updated_at.isoformat(),
        }

    @classmethod
    def _from_row(cls, row: Any) -> "WorkflowRunRecord":
        """Build from a DB row (dict-like)."""
        def _parse_json_list(val: Any) -> list[str]:
            if isinstance(val, list):
                return val
            if isinstance(val, str):
                try:
                    return json.loads(val)
                except Exception:
                    return []
            return []

        return cls(
            run_id           = row["run_id"],
            workflow_name    = row["workflow_name"],
            status           = row["status"],
            context_json     = row.get("context_json", "{}"),
            steps_completed  = _parse_json_list(row.get("steps_completed", "[]")),
            steps_failed     = _parse_json_list(row.get("steps_failed", "[]")),
            errors           = _parse_json_list(row.get("errors", "[]")),
            elapsed_seconds  = float(row.get("elapsed_seconds", 0.0)),
            investigation_id = row.get("investigation_id"),
            created_at       = _parse_dt(row.get("created_at")),
            updated_at       = _parse_dt(row.get("updated_at")),
        )


def _parse_dt(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            pass
    return datetime.now(timezone.utc)


class WorkflowStore:
    """
    Persist and retrieve workflow run records.

    Uses SQLAlchemy Core (no ORM models) via the existing GNAT persist layer.
    Degrades gracefully when the DB is unavailable — operations log warnings
    and return ``None`` / empty lists rather than raising.

    Parameters
    ----------
    db_url : str | None
        SQLAlchemy connection URL.  When ``None`` the store operates in-memory
        (useful for testing).
    """

    def __init__(self, db_url: str | None = None) -> None:
        self._db_url = db_url
        self._engine: Any = None
        self._in_memory: dict[str, WorkflowRunRecord] = {}  # fallback when no DB

        if db_url:
            try:
                import sqlalchemy as sa
                self._engine = sa.create_engine(db_url, future=True)
                self._ensure_table()
            except Exception as exc:
                logger.warning(
                    "WorkflowStore: could not connect to DB (%s) — using in-memory store",
                    exc,
                )
                self._engine = None

    # ── Public API ──────────────────────────────────────────────────────────────

    def save(
        self,
        result: Any,              # WorkflowResult
        workflow_name: str,
        investigation_id: str | None = None,
    ) -> str:
        """
        Persist a :class:`~gnat.agents.workflow.WorkflowResult`.

        Parameters
        ----------
        result : WorkflowResult
        workflow_name : str
        investigation_id : str, optional

        Returns
        -------
        str
            The generated ``run_id`` (UUID).
        """
        run_id = str(uuid.uuid4())
        now    = datetime.now(timezone.utc)
        status = STATUS_SUCCESS if result.success else STATUS_FAILED

        ctx_shared = {}
        if hasattr(result, "context") and result.context is not None:
            try:
                ctx_shared = dict(result.context.shared or {})
            except Exception:
                pass

        record = WorkflowRunRecord(
            run_id           = run_id,
            workflow_name    = workflow_name,
            status           = status,
            context_json     = json.dumps(ctx_shared, default=str),
            steps_completed  = list(result.steps_completed),
            steps_failed     = list(result.steps_failed),
            errors           = list(result.errors),
            elapsed_seconds  = float(result.elapsed_seconds),
            investigation_id = investigation_id,
            created_at       = now,
            updated_at       = now,
        )

        if self._engine is not None:
            self._db_insert(record)
        else:
            self._in_memory[run_id] = record

        logger.debug(
            "WorkflowStore.save: run_id=%s workflow=%s status=%s",
            run_id, workflow_name, status,
        )
        return run_id

    def get(self, run_id: str) -> WorkflowRunRecord | None:
        """Retrieve a single run record by ID."""
        if self._engine is None:
            return self._in_memory.get(run_id)
        try:
            import sqlalchemy as sa
            with self._engine.connect() as conn:
                tbl = self._table()
                row = conn.execute(
                    sa.select(tbl).where(tbl.c.run_id == run_id)
                ).mappings().first()
                return WorkflowRunRecord._from_row(dict(row)) if row else None
        except Exception as exc:
            logger.warning("WorkflowStore.get failed: %s", exc)
            return None

    def list(
        self,
        workflow_name: str | None = None,
        investigation_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorkflowRunRecord]:
        """
        Return a list of run records, newest first.

        Parameters
        ----------
        workflow_name : str, optional
            Filter by workflow name.
        investigation_id : str, optional
            Filter by investigation ID.
        status : str, optional
            Filter by status (``"success"`` | ``"failed"`` | ``"running"``).
        limit : int
            Maximum number of records to return.
        offset : int
            Pagination offset.
        """
        if self._engine is None:
            records = list(self._in_memory.values())
            if workflow_name:
                records = [r for r in records if r.workflow_name == workflow_name]
            if investigation_id:
                records = [r for r in records if r.investigation_id == investigation_id]
            if status:
                records = [r for r in records if r.status == status]
            records.sort(key=lambda r: r.created_at, reverse=True)
            return records[offset: offset + limit]

        try:
            import sqlalchemy as sa
            tbl = self._table()
            q   = sa.select(tbl)
            if workflow_name:
                q = q.where(tbl.c.workflow_name == workflow_name)
            if investigation_id:
                q = q.where(tbl.c.investigation_id == investigation_id)
            if status:
                q = q.where(tbl.c.status == status)
            q = q.order_by(tbl.c.created_at.desc()).offset(offset).limit(limit)
            with self._engine.connect() as conn:
                rows = conn.execute(q).mappings().all()
                return [WorkflowRunRecord._from_row(dict(r)) for r in rows]
        except Exception as exc:
            logger.warning("WorkflowStore.list failed: %s", exc)
            return []

    def delete(self, run_id: str) -> bool:
        """Delete a run record.  Returns True on success."""
        if self._engine is None:
            return bool(self._in_memory.pop(run_id, None))
        try:
            import sqlalchemy as sa
            tbl = self._table()
            with self._engine.begin() as conn:
                result = conn.execute(
                    sa.delete(tbl).where(tbl.c.run_id == run_id)
                )
                return result.rowcount > 0
        except Exception as exc:
            logger.warning("WorkflowStore.delete failed: %s", exc)
            return False

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _table(self) -> Any:
        import sqlalchemy as sa
        meta = sa.MetaData()
        return sa.Table(
            "workflow_runs", meta,
            sa.Column("run_id",           sa.String(36),   primary_key=True),
            sa.Column("workflow_name",    sa.String(128),  nullable=False, index=True),
            sa.Column("status",           sa.String(32),   nullable=False),
            sa.Column("context_json",     sa.Text,         nullable=False, default="{}"),
            sa.Column("steps_completed",  sa.Text,         nullable=False, default="[]"),
            sa.Column("steps_failed",     sa.Text,         nullable=False, default="[]"),
            sa.Column("errors",           sa.Text,         nullable=False, default="[]"),
            sa.Column("elapsed_seconds",  sa.Float,        nullable=False, default=0.0),
            sa.Column("investigation_id", sa.String(128),  nullable=True,  index=True),
            sa.Column("created_at",       sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at",       sa.DateTime(timezone=True), nullable=False),
        )

    def _ensure_table(self) -> None:
        if self._engine is None:
            return
        try:
            self._table().metadata.create_all(self._engine, checkfirst=True)
        except Exception as exc:
            logger.warning("WorkflowStore._ensure_table: %s", exc)

    def _db_insert(self, record: WorkflowRunRecord) -> None:
        try:
            import sqlalchemy as sa
            tbl = self._table()
            with self._engine.begin() as conn:
                conn.execute(tbl.insert().values(
                    run_id           = record.run_id,
                    workflow_name    = record.workflow_name,
                    status           = record.status,
                    context_json     = record.context_json,
                    steps_completed  = json.dumps(record.steps_completed),
                    steps_failed     = json.dumps(record.steps_failed),
                    errors           = json.dumps(record.errors),
                    elapsed_seconds  = record.elapsed_seconds,
                    investigation_id = record.investigation_id,
                    created_at       = record.created_at,
                    updated_at       = record.updated_at,
                ))
        except Exception as exc:
            logger.warning("WorkflowStore._db_insert: %s — falling back to in-memory", exc)
            self._in_memory[record.run_id] = record
