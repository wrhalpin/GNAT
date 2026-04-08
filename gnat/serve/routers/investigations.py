"""
gnat.serve.routers.investigations
==================================

FastAPI router exposing :class:`~gnat.analysis.investigations.service.InvestigationService`
over HTTP.

Endpoints
---------
GET  /api/investigations                     — list (with InvestigationQuery filters)
POST /api/investigations                     — create
GET  /api/investigations/{id}                — get by ID
PUT  /api/investigations/{id}                — update title/description/tags
POST /api/investigations/{id}/transition     — state machine transition
POST /api/investigations/{id}/notes          — add analyst note
POST /api/investigations/{id}/tasks          — add task
PUT  /api/investigations/{id}/tasks/{tid}    — update task status
POST /api/investigations/{id}/hypotheses     — add hypothesis
POST /api/investigations/{id}/link           — link indicators / reports / actors
GET  /api/investigations/{id}/summary        — lightweight summary dict

Registration
------------
Pass an :class:`~gnat.analysis.investigations.service.InvestigationService`
instance via ``app.state.investigation_service``::

    from gnat.analysis.investigations.storage import InvestigationStore
    from gnat.analysis.investigations.service import InvestigationService
    from gnat.serve.app import create_app

    store   = InvestigationStore("sqlite:///~/.gnat/gnat.db")
    service = InvestigationService(store)

    app = create_app(api_key="secret")
    app.state.investigation_service = service
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


def _get_service(request: Request):
    svc = getattr(request.app.state, "investigation_service", None)
    if svc is None:
        raise HTTPException(503, "Investigation service not configured on this server")
    return svc


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("")
def list_investigations(
    request:    Request,
    status:     str | None = Query(None, description="Comma-separated status values"),
    created_by: str | None = Query(None),
    tags:       str | None = Query(None, description="Comma-separated tags (ANY match)"),
    tlp:        str | None = Query(None, description="Comma-separated TLP levels"),
    text:       str | None = Query(None, max_length=200),
    date_from:  str | None = Query(None, description="ISO 8601 datetime"),
    date_to:    str | None = Query(None, description="ISO 8601 datetime"),
    sort_by:    str        = Query("updated_at"),
    sort_desc:  bool       = Query(True),
    page:       int        = Query(1, ge=1),
    page_size:  int        = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """List investigations with optional rich filters."""
    from datetime import datetime as _dt
    from gnat.analysis.investigations.models import InvestigationStatus
    from gnat.analysis.tlp import TLPLevel
    from gnat.analysis.query import InvestigationQuery

    def _parse_status(s: str | None):
        if not s:
            return None
        result = []
        for v in s.split(","):
            try:
                result.append(InvestigationStatus(v.strip()))
            except ValueError:
                raise HTTPException(400, f"Unknown status: {v.strip()!r}")
        return result or None

    def _parse_tlp(s: str | None):
        if not s:
            return None
        result = []
        for v in s.split(","):
            try:
                result.append(TLPLevel(v.strip().lower()))
            except ValueError:
                raise HTTPException(400, f"Unknown TLP level: {v.strip()!r}")
        return result or None

    def _parse_dt(s: str | None):
        if not s:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                return _dt.strptime(s, fmt)
            except ValueError:
                continue
        raise HTTPException(400, f"Cannot parse datetime: {s!r}")

    q = InvestigationQuery(
        status         = _parse_status(status),
        created_by     = created_by,
        tags           = [t.strip() for t in tags.split(",")] if tags else None,
        classification = _parse_tlp(tlp),
        text           = text,
        date_from      = _parse_dt(date_from),
        date_to        = _parse_dt(date_to),
        sort_by        = sort_by,
        sort_desc      = sort_desc,
        page           = page,
        page_size      = page_size,
    )

    svc = _get_service(request)
    try:
        investigations = svc.list(query=q)
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return {
        "page":            page,
        "page_size":       page_size,
        "count":           len(investigations),
        "investigations":  [inv.to_dict() for inv in investigations],
    }


# ── Create ────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
def create_investigation(
    request: Request,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Create a new Investigation.

    Request body
    ------------
    ``title``       : str (required)
    ``created_by``  : str (required)
    ``description`` : str (optional)
    ``classification`` : str TLP level (default "amber")
    ``tags``        : list[str] (optional)
    ``assigned_to`` : list[str] (optional)
    """
    from gnat.analysis.tlp import TLPLevel

    title      = body.get("title", "").strip()
    created_by = body.get("created_by", "").strip()
    if not title:
        raise HTTPException(400, "Field 'title' is required.")
    if not created_by:
        raise HTTPException(400, "Field 'created_by' is required.")

    try:
        tlp = TLPLevel(body.get("classification", "amber").lower())
    except ValueError:
        raise HTTPException(400, "Invalid 'classification' value.")

    svc = _get_service(request)
    try:
        inv = svc.create(
            title          = title,
            created_by     = created_by,
            description    = body.get("description", ""),
            classification = tlp,
            tags           = body.get("tags", []),
            assigned_to    = body.get("assigned_to", []),
        )
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return inv.to_dict()


# ── Get ───────────────────────────────────────────────────────────────────────

@router.get("/{inv_id}")
def get_investigation(request: Request, inv_id: str) -> dict[str, Any]:
    """Retrieve a single Investigation by ID."""
    svc = _get_service(request)
    try:
        inv = svc.get(inv_id)
    except Exception as exc:
        raise HTTPException(404, str(exc))
    return inv.to_dict()


# ── Update ────────────────────────────────────────────────────────────────────

@router.put("/{inv_id}")
def update_investigation(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Update Investigation fields (title, description, tags).

    Only the fields present in the request body are updated.
    """
    svc = _get_service(request)
    try:
        inv = svc.get(inv_id)
    except Exception as exc:
        raise HTTPException(404, str(exc))

    if "title" in body:
        inv.title = body["title"].strip() or inv.title
    if "description" in body:
        inv.description = body["description"]
    if "tags" in body and isinstance(body["tags"], list):
        inv.tags = body["tags"]

    svc.save(inv)
    return inv.to_dict()


# ── Transition ────────────────────────────────────────────────────────────────

@router.post("/{inv_id}/transition")
def transition_investigation(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Transition an Investigation to a new lifecycle state.

    Request body
    ------------
    ``status`` : str (required) — target status value
    ``note``   : str (optional)
    ``author`` : str (optional)
    """
    from gnat.analysis.investigations.models import InvestigationStatus
    new_status_str = body.get("status", "")
    try:
        new_status = InvestigationStatus(new_status_str)
    except ValueError:
        raise HTTPException(400, f"Unknown status: {new_status_str!r}")

    svc = _get_service(request)
    try:
        inv = svc.transition(
            inv_id,
            new_status,
            note   = body.get("note"),
            author = body.get("author"),
        )
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return inv.to_dict()


# ── Notes ─────────────────────────────────────────────────────────────────────

@router.post("/{inv_id}/notes", status_code=201)
def add_note(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Add an analyst note to an Investigation.

    Request body
    ------------
    ``content`` : str (required)
    ``author``  : str (required)
    ``linked_artifacts`` : list[str] (optional)
    """
    content = body.get("content", "").strip()
    author  = body.get("author",  "").strip()
    if not content:
        raise HTTPException(400, "Field 'content' is required.")
    if not author:
        raise HTTPException(400, "Field 'author' is required.")

    svc = _get_service(request)
    try:
        note = svc.add_note(
            inv_id,
            content          = content,
            author           = author,
            linked_artifacts = body.get("linked_artifacts"),
        )
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return {"id": note.id, "content": note.content, "author": note.author,
            "created_at": note.created_at.isoformat()}


# ── Tasks ─────────────────────────────────────────────────────────────────────

@router.post("/{inv_id}/tasks", status_code=201)
def add_task(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Add a task to an Investigation.

    Request body
    ------------
    ``title``       : str (required)
    ``description`` : str (optional)
    ``priority``    : str (optional) — "low" | "medium" | "high" | "critical"
    ``assigned_to`` : str (optional)
    """
    from gnat.analysis.investigations.models import TaskPriority

    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(400, "Field 'title' is required.")

    priority_str = body.get("priority", "medium")
    try:
        priority = TaskPriority(priority_str)
    except ValueError:
        raise HTTPException(400, f"Unknown priority: {priority_str!r}")

    svc = _get_service(request)
    try:
        task = svc.add_task(
            inv_id,
            title       = title,
            description = body.get("description", ""),
            priority    = priority,
            assigned_to = body.get("assigned_to"),
        )
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return {"id": task.id, "title": task.title, "status": task.status.value,
            "priority": task.priority.value}


@router.put("/{inv_id}/tasks/{task_id}")
def update_task(
    request: Request,
    inv_id:  str,
    task_id: str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Update the status of a task.

    Request body
    ------------
    ``status`` : str (required) — "todo" | "in_progress" | "done" | "blocked"
    """
    from gnat.analysis.investigations.models import TaskStatus
    status_str = body.get("status", "")
    try:
        new_status = TaskStatus(status_str)
    except ValueError:
        raise HTTPException(400, f"Unknown task status: {status_str!r}")

    svc = _get_service(request)
    try:
        task = svc.update_task_status(inv_id, task_id, new_status)
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return {"id": task.id, "status": task.status.value}


# ── Hypotheses ────────────────────────────────────────────────────────────────

@router.post("/{inv_id}/hypotheses", status_code=201)
def add_hypothesis(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Add a hypothesis to an Investigation.

    Request body
    ------------
    ``statement`` : str (required)
    """
    statement = body.get("statement", "").strip()
    if not statement:
        raise HTTPException(400, "Field 'statement' is required.")

    svc = _get_service(request)
    try:
        hyp = svc.add_hypothesis(inv_id, statement=statement)
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return {"id": hyp.id, "statement": hyp.statement, "status": hyp.status.value}


# ── Artifact linking ──────────────────────────────────────────────────────────

@router.post("/{inv_id}/link")
def link_artifacts(
    request: Request,
    inv_id:  str,
    body:    dict[str, Any],
) -> dict[str, Any]:
    """
    Link artifacts to an Investigation.

    Request body (all fields optional; at least one required)
    ----------------------------------------------------------
    ``indicators``    : list[str]
    ``observables``   : list[str]
    ``threat_actors`` : list[str]
    ``reports``       : list[str]
    """
    svc = _get_service(request)
    inv = None
    try:
        if body.get("indicators"):
            inv = svc.link_indicators(inv_id, body["indicators"])
        if body.get("observables"):
            inv = svc.link_observables(inv_id, body["observables"])
        if body.get("threat_actors"):
            inv = svc.link_threat_actors(inv_id, body["threat_actors"])
        if body.get("reports"):
            for rid in body["reports"]:
                inv = svc.link_report(inv_id, rid)
    except Exception as exc:
        raise HTTPException(400, str(exc))

    if inv is None:
        try:
            inv = svc.get(inv_id)
        except Exception as exc:
            raise HTTPException(404, str(exc))

    return {
        "id":            inv.id,
        "indicators":    inv.indicators,
        "observables":   inv.observables,
        "threat_actors": inv.threat_actors,
        "reports":       inv.reports,
    }


# ── Summary ───────────────────────────────────────────────────────────────────

@router.get("/{inv_id}/summary")
def get_summary(request: Request, inv_id: str) -> dict[str, Any]:
    """Return a lightweight summary dict for an Investigation."""
    svc = _get_service(request)
    try:
        return svc.summary(inv_id)
    except Exception as exc:
        raise HTTPException(404, str(exc))
