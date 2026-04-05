"""
gnat.serve.routers.scheduler
=============================
FastAPI router for the Scheduler API.

Endpoints
---------
GET  /api/scheduler/jobs                  — List all registered feed jobs
POST /api/scheduler/jobs/{job_id}/trigger — Trigger a job immediately (async)
"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


def _get_scheduler(request: Request):
    sched = getattr(request.app.state, "scheduler", None)
    if sched is None:
        raise HTTPException(503, "Scheduler not configured on this server")
    return sched


def _job_to_dict(job: Any) -> dict[str, Any]:
    """Normalize a FeedJob to a JSON-safe dict."""
    if isinstance(job, dict):
        d = job
    else:
        d = getattr(job, "__dict__", {})
    return {
        "job_id": str(d.get("job_id", "")),
        "enabled": bool(d.get("enabled", False)),
        "last_run": (str(d.get("last_run") or ""))[:19],
        "next_run": (str(d.get("next_run") or ""))[:19],
        "run_count": int(d.get("run_count", 0)),
        "status": str(d.get("status", "")),
    }


@router.get("/jobs")
def list_jobs(request: Request) -> dict[str, Any]:
    """Return the status of all registered feed jobs."""
    sched = _get_scheduler(request)
    try:
        if hasattr(sched, "list_jobs"):
            jobs = sched.list_jobs()
        else:
            jobs = list(getattr(sched, "jobs", {}).values())
    except Exception as exc:
        raise HTTPException(500, str(exc))
    rows = [_job_to_dict(j) for j in jobs]
    return {"jobs": rows, "count": len(rows)}


@router.post("/jobs/{job_id}/trigger")
def trigger_job(job_id: str, request: Request) -> dict[str, Any]:
    """Trigger a specific feed job immediately in a background thread."""
    sched = _get_scheduler(request)
    try:
        if hasattr(sched, "get_job"):
            job = sched.get_job(job_id)
        else:
            job = getattr(sched, "jobs", {}).get(job_id)
    except Exception as exc:
        raise HTTPException(500, str(exc))
    if job is None:
        raise HTTPException(404, f"Job '{job_id}' not found")
    if not hasattr(job, "execute"):
        raise HTTPException(500, f"Job '{job_id}' does not support manual execution")
    threading.Thread(target=job.execute, daemon=True, name=f"gnat-trigger-{job_id}").start()
    return {"status": "triggered", "job_id": job_id}
