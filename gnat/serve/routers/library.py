"""
gnat.serve.routers.library
==========================
FastAPI router for the Research Library API.

Endpoints
---------
GET  /api/library                 — Search / list library entries
GET  /api/library/{entry_id}      — Fetch a single entry by id
POST /api/library/{entry_id}/promote  — Promote a staging entry
POST /api/library/{entry_id}/reject   — Reject a staging entry
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/library", tags=["library"])


def _get_library(request: Request):
    lib = getattr(request.app.state, "library", None)
    if lib is None:
        raise HTTPException(503, "Research library not configured on this server")
    return lib


@router.get("")
def search_library(
    request: Request,
    q: str | None = Query(None, max_length=200, description="Free-text search"),
    topic: str | None = Query(None, max_length=100),
    tlp: str | None = Query(None, max_length=10),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """Search or list research library entries."""
    lib = _get_library(request)
    try:
        results = lib.search(q or "", topic=topic, tlp=tlp, limit=limit)
    except TypeError:
        # Some implementations don't accept keyword arguments
        results = lib.search(q or "")
    except Exception as exc:
        raise HTTPException(500, str(exc))
    serialized = [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in (results or [])]
    return {"results": serialized, "count": len(serialized)}


@router.get("/{entry_id}")
def get_entry(entry_id: str, request: Request) -> dict[str, Any]:
    """Fetch a single library entry by id."""
    lib = _get_library(request)
    try:
        entry = lib.get(entry_id)
    except Exception as exc:
        raise HTTPException(404, str(exc))
    if entry is None:
        raise HTTPException(404, f"Entry '{entry_id}' not found")
    return entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)


@router.post("/{entry_id}/promote")
def promote_entry(entry_id: str, request: Request) -> dict[str, Any]:
    """Promote a staging library entry to the main collection."""
    lib = _get_library(request)
    try:
        lib.promote(entry_id)
    except Exception as exc:
        raise HTTPException(500, str(exc))
    return {"status": "promoted", "entry_id": entry_id}


@router.post("/{entry_id}/reject")
def reject_entry(entry_id: str, request: Request) -> dict[str, Any]:
    """Reject and remove a staging library entry."""
    lib = _get_library(request)
    try:
        lib.reject(entry_id)
    except Exception as exc:
        raise HTTPException(500, str(exc))
    return {"status": "rejected", "entry_id": entry_id}
