"""
gnat.serve.routers.review
==========================

FastAPI router for the AI-extracted intel review queue.

Endpoints
---------
GET  /api/review                          — list items (filterable by status/type)
POST /api/review                          — submit a STIX object for review
GET  /api/review/stats                    — queue statistics
GET  /api/review/{id}                     — get item by ID
POST /api/review/{id}/approve             — approve item
POST /api/review/{id}/reject              — reject item
POST /api/review/{id}/modify              — record analyst modifications
POST /api/review/{id}/promote             — promote approved item to target workspace

Registration
------------
Attach a :class:`~gnat.review.service.ReviewService` instance via
``app.state.review_service``::

    from gnat.review.store import ReviewQueueStore
    from gnat.review.service import ReviewService
    from gnat.serve.app import create_app

    store = ReviewQueueStore("sqlite:///gnat.db")
    store.create_all()
    app = create_app(api_key="secret")
    app.state.review_service = ReviewService(store)
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Request
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover
    raise ImportError('FastAPI is required. Run: pip install "gnat[serve]"')


router = APIRouter(prefix="/api/review", tags=["review"])


def _svc(request: Request) -> Any:
    svc = getattr(request.app.state, "review_service", None)
    if svc is None:
        raise HTTPException(
            status_code=503,
            detail="Review service not configured on this server.",
        )
    return svc


# ---------------------------------------------------------------------------
# List / stats
# ---------------------------------------------------------------------------


@router.get("")
def list_review_items(
    request: Request,
    status: str | None = "pending",
    stix_type: str | None = None,
    submitted_by: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> Any:
    """List review queue items with optional filters."""
    svc = _svc(request)
    items = svc.list(
        status=status or None,
        stix_type=stix_type,
        submitted_by=submitted_by,
        page=page,
        page_size=min(page_size, 500),
    )
    return {"items": [i.to_dict() for i in items], "count": len(items)}


@router.get("/stats")
def get_stats(request: Request) -> Any:
    """Return pending/approved/rejected/modified/total counts."""
    return _svc(request).stats()


# ---------------------------------------------------------------------------
# Single item
# ---------------------------------------------------------------------------


@router.get("/{item_id}")
def get_item(item_id: str, request: Request) -> Any:
    """Get a review item by ID."""
    from gnat.review.service import ReviewError

    try:
        return _svc(request).get(item_id).to_dict()
    except ReviewError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------


@router.post("")
def submit_item(request: Request, body: dict[str, Any]) -> Any:
    """
    Submit a STIX object for analyst review.

    Body fields:
    - ``stix_data``        (dict, required) — full STIX object
    - ``source_workspace`` (str, required)
    - ``submitted_by``     (str, required)
    - ``target_workspace`` (str, optional, default ``"_ctmsak_staging"``)
    """
    from gnat.review.service import ReviewError

    try:
        item = _svc(request).submit(
            stix_data=body.get("stix_data", {}),
            source_workspace=body.get("source_workspace", ""),
            submitted_by=body.get("submitted_by", "api"),
            target_workspace=body.get("target_workspace", "_ctmsak_staging"),
        )
        return JSONResponse(status_code=201, content=item.to_dict())
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Review actions
# ---------------------------------------------------------------------------


@router.post("/{item_id}/approve")
def approve_item(item_id: str, request: Request, body: dict[str, Any] | None = None) -> Any:
    """
    Approve a PENDING or MODIFIED item.

    Body fields (all optional):
    - ``reviewed_by``       (str)
    - ``notes``             (str)
    - ``confidence_override`` (int, 0-100)
    """
    from gnat.review.service import ReviewError

    body = body or {}
    try:
        item = _svc(request).approve(
            item_id,
            reviewed_by=body.get("reviewed_by", "api-analyst"),
            notes=body.get("notes"),
            confidence_override=body.get("confidence_override"),
        )
        return item.to_dict()
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{item_id}/reject")
def reject_item(item_id: str, request: Request, body: dict[str, Any] | None = None) -> Any:
    """
    Reject a PENDING or MODIFIED item.

    Body fields (all optional):
    - ``reviewed_by`` (str)
    - ``reason``      (str)
    """
    from gnat.review.service import ReviewError

    body = body or {}
    try:
        item = _svc(request).reject(
            item_id,
            reviewed_by=body.get("reviewed_by", "api-analyst"),
            reason=body.get("reason"),
        )
        return item.to_dict()
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{item_id}/modify")
def modify_item(item_id: str, request: Request, body: dict[str, Any] | None = None) -> Any:
    """
    Record analyst modifications on a PENDING item (transitions to MODIFIED).

    Body fields:
    - ``modified_by``          (str, required)
    - ``modified_properties``  (dict, required) — properties to overlay on STIX object
    - ``notes``                (str, optional)
    - ``confidence_override``  (int, optional)
    """
    from gnat.review.service import ReviewError

    body = body or {}
    try:
        item = _svc(request).modify(
            item_id,
            modified_by=body.get("modified_by", "api-analyst"),
            modified_properties=body.get("modified_properties", {}),
            notes=body.get("notes"),
            confidence_override=body.get("confidence_override"),
        )
        return item.to_dict()
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{item_id}/promote")
def promote_item(item_id: str, request: Request) -> Any:
    """
    Promote an APPROVED item to its target workspace.

    Requires a workspace manager attached to ``app.state.workspace_manager``.
    """
    from gnat.review.service import ReviewError

    workspace_manager = getattr(request.app.state, "workspace_manager", None)
    try:
        promoted = _svc(request).promote(item_id, workspace_manager=workspace_manager)
        return {"promoted": promoted}
    except ReviewError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
