# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.workflows
=============================

Workflow catalog and run-history API endpoints.

Endpoints
---------
``GET  /api/workflows``
    List the workflow catalog.
``POST /api/workflows/{name}/run``
    Trigger an immediate workflow run.
``GET  /api/workflows/runs``
    List workflow run history.
``GET  /api/workflows/runs/{run_id}``
    Retrieve a single run record.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/workflows", tags=["workflows"])


# ── Request / response models ─────────────────────────────────────────────────

class WorkflowRunRequest(BaseModel):
    """Request body for POST /api/workflows/{name}/run."""

    shared: dict[str, Any] = {}
    investigation_id: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_workflow_store(request: Request) -> Any:
    store = getattr(request.app.state, "workflow_store", None)
    return store  # may be None — store is optional


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_catalog(
    tag: list[str] = Query([], description="Filter by tag(s)"),
) -> dict[str, Any]:
    """
    Return the workflow catalog.

    Each entry includes the workflow name, description, tags, and required
    dependency names.  Use ``tag=`` query param to filter by tag.
    """
    try:
        from gnat.agents.catalog import WorkflowCatalog
        entries = WorkflowCatalog.list(tags=tag if tag else None)
        return {
            "workflows": [e.to_dict() for e in entries],
            "total":     len(entries),
        }
    except Exception as exc:
        logger.error("workflows/catalog failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{name}/run")
def run_workflow(
    name:    str,
    body:    WorkflowRunRequest,
    request: Request,
) -> dict[str, Any]:
    """
    Trigger an immediate workflow run.

    Parameters
    ----------
    name : str
        Registered workflow name (e.g. ``"phishing-triage"``).

    Body
    ----
    shared : dict
        Values merged into :class:`~gnat.agents.workflow.WorkflowContext`.shared.
    investigation_id : str, optional
        Pre-existing investigation to attach this run to.

    Returns
    -------
    dict
        Run result including success, steps completed/failed, elapsed time.
    """
    try:
        from gnat.agents.catalog import WorkflowCatalog
        from gnat.agents.workflow import WorkflowContext
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"Workflow engine unavailable: {exc}") from exc

    entry = WorkflowCatalog.get(name)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"Workflow {name!r} not found. "
                   f"Available: {[e.name for e in WorkflowCatalog.list()]}",
        )

    try:
        wf  = entry.factory()
        ctx = WorkflowContext(
            investigation_id = body.investigation_id,
            shared           = dict(body.shared),
        )
        result = wf.run(ctx)

        store = _get_workflow_store(request)
        run_id: str | None = None
        if store is not None:
            try:
                run_id = store.save(
                    result,
                    workflow_name    = name,
                    investigation_id = body.investigation_id,
                )
            except Exception as exc:
                logger.warning("workflows/%s/run: failed to persist: %s", name, exc)

        return {
            "run_id":          run_id,
            "workflow_name":   name,
            "success":         result.success,
            "steps_completed": result.steps_completed,
            "steps_failed":    result.steps_failed,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "errors":          result.errors,
        }

    except Exception as exc:
        logger.error("workflows/%s/run failed: %s", name, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/runs")
def list_runs(
    request:          Request,
    workflow_name:    str | None   = Query(None, description="Filter by workflow name"),
    investigation_id: str | None   = Query(None),
    status:           str | None   = Query(None, description="success | failed | running"),
    limit:            int          = Query(50, ge=1, le=500),
    offset:           int          = Query(0, ge=0),
) -> dict[str, Any]:
    """
    Return workflow run history, newest first.
    """
    store = _get_workflow_store(request)
    if store is None:
        return {"runs": [], "total": 0, "message": "No workflow store configured"}

    try:
        records = store.list(
            workflow_name    = workflow_name,
            investigation_id = investigation_id,
            status           = status,
            limit            = limit,
            offset           = offset,
        )
        return {
            "runs":   [r.to_dict() for r in records],
            "total":  len(records),
            "offset": offset,
            "limit":  limit,
        }
    except Exception as exc:
        logger.error("workflows/runs failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request) -> dict[str, Any]:
    """Retrieve a single workflow run record by ID."""
    store = _get_workflow_store(request)
    if store is None:
        raise HTTPException(status_code=503, detail="No workflow store configured")

    try:
        record = store.get(run_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
        return record.to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("workflows/runs/%s failed: %s", run_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
