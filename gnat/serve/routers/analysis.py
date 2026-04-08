"""
gnat.serve.routers.analysis
============================

FastAPI router for graph analysis, copilot, and export endpoints.

Endpoints
---------
POST /api/graph/pivot              — pivot from a node N hops
POST /api/graph/filter             — filter a graph context
POST /api/graph/shortest-path      — shortest path between two nodes
POST /api/copilot/gaps             — detect analytical gaps
POST /api/copilot/draft            — draft a report
GET  /api/reports/{id}/export/stix — export a report as a STIX bundle
GET  /api/metrics/investigations    — investigation completion metrics
GET  /api/metrics/enrichment        — enrichment effectiveness metrics

Registration
------------
Backends are pulled from ``app.state``:

- ``app.state.graph_query``             — :class:`~gnat.analysis.graph.query.GraphQuery`
- ``app.state.gap_detector``            — :class:`~gnat.analysis.copilot.GapDetector`
- ``app.state.report_drafting_assistant`` — :class:`~gnat.analysis.copilot.ReportDraftingAssistant`
- ``app.state.export_service``          — :class:`~gnat.dissemination.export.ExportService`
- ``app.state.metrics_aggregator``      — :class:`~gnat.metrics.aggregator.MetricsAggregator`
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api", tags=["analysis"])


# ── Graph ─────────────────────────────────────────────────────────────────────

@router.post("/graph/pivot")
def graph_pivot(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """
    Pivot from a node outward N hops.

    Request body
    ------------
    ``node_id`` : str  (required)
    ``hops``    : int  (default 2)
    ``filters`` : dict (optional)
    """
    gq = getattr(request.app.state, "graph_query", None)
    if gq is None:
        raise HTTPException(503, "GraphQuery not configured on this server")

    node_id = body.get("node_id", "").strip()
    if not node_id:
        raise HTTPException(400, "Field 'node_id' is required.")

    hops    = int(body.get("hops", 2))
    filters = body.get("filters", {})

    try:
        result = gq.pivot(node_id, hops=hops, filters=filters)
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return result if isinstance(result, dict) else {"nodes": list(result)}


@router.post("/graph/filter")
def graph_filter(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """
    Apply filters to a graph context.

    Request body
    ------------
    ``filters`` : dict (required) — key/value filter criteria
    ``context_id`` : str (optional)
    """
    gq = getattr(request.app.state, "graph_query", None)
    if gq is None:
        raise HTTPException(503, "GraphQuery not configured on this server")

    filters = body.get("filters", {})
    try:
        result = gq.filter(filters, context_id=body.get("context_id"))
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return result if isinstance(result, dict) else {"results": list(result)}


@router.post("/graph/shortest-path")
def graph_shortest_path(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """
    Find the shortest path between two graph nodes.

    Request body
    ------------
    ``source`` : str (required)
    ``target`` : str (required)
    """
    gq = getattr(request.app.state, "graph_query", None)
    if gq is None:
        raise HTTPException(503, "GraphQuery not configured on this server")

    source = body.get("source", "").strip()
    target = body.get("target", "").strip()
    if not source or not target:
        raise HTTPException(400, "Fields 'source' and 'target' are required.")

    try:
        path = gq.shortest_path(source, target)
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return {"source": source, "target": target, "path": path}


# ── Copilot ───────────────────────────────────────────────────────────────────

@router.post("/copilot/gaps")
def detect_gaps(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """
    Detect analytical gaps in an investigation.

    Request body
    ------------
    ``investigation_id`` : str (required)
    """
    gd = getattr(request.app.state, "gap_detector", None)
    if gd is None:
        raise HTTPException(503, "GapDetector not configured on this server")

    inv_id = body.get("investigation_id", "").strip()
    if not inv_id:
        raise HTTPException(400, "Field 'investigation_id' is required.")

    try:
        gaps = gd.detect_all(inv_id)
    except Exception as exc:
        raise HTTPException(500, str(exc))

    if isinstance(gaps, list):
        return {"investigation_id": inv_id, "gaps": gaps, "count": len(gaps)}
    return {"investigation_id": inv_id, "result": gaps}


@router.post("/copilot/draft")
def draft_report(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a report draft using the drafting assistant.

    Request body
    ------------
    ``investigation_id`` : str (required)
    ``title``            : str (optional)
    ``style``            : str (optional)
    """
    rda = getattr(request.app.state, "report_drafting_assistant", None)
    if rda is None:
        raise HTTPException(503, "ReportDraftingAssistant not configured on this server")

    inv_id = body.get("investigation_id", "").strip()
    if not inv_id:
        raise HTTPException(400, "Field 'investigation_id' is required.")

    kwargs: dict[str, Any] = {}
    if "title" in body:
        kwargs["title"] = body["title"]
    if "style" in body:
        kwargs["style"] = body["style"]

    try:
        draft = rda.draft_full(inv_id, **kwargs)
    except Exception as exc:
        raise HTTPException(500, str(exc))

    if isinstance(draft, dict):
        return draft
    return {"investigation_id": inv_id, "draft": str(draft)}


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/reports/{report_id}/export/stix")
def export_stix(request: Request, report_id: str) -> dict[str, Any]:
    """Export a report as a STIX 2.1 bundle."""
    es = getattr(request.app.state, "export_service", None)
    if es is None:
        raise HTTPException(503, "ExportService not configured on this server")

    try:
        bundle = es.export_stix_bundle(report_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except Exception as exc:
        raise HTTPException(500, str(exc))

    return bundle


# ── Metrics ───────────────────────────────────────────────────────────────────

@router.get("/metrics/investigations")
def metrics_investigations(
    request: Request,
    days:    int = 30,
) -> dict[str, Any]:
    """
    Investigation completion metrics for the past *days* days.

    Returns avg open time, completion rate, and report rate.
    """
    ma = getattr(request.app.state, "metrics_aggregator", None)
    if ma is None:
        raise HTTPException(503, "MetricsAggregator not configured on this server")

    try:
        return ma.investigation_summary(days=days)
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.get("/metrics/enrichment")
def metrics_enrichment(
    request:  Request,
    platform: str | None = None,
    days:     int = 7,
) -> dict[str, Any]:
    """
    Enrichment effectiveness metrics (hit rate per platform).

    Parameters
    ----------
    platform : str, optional
        Filter to a specific platform name.
    days : int
        Number of past days to include (default 7).
    """
    ma = getattr(request.app.state, "metrics_aggregator", None)
    if ma is None:
        raise HTTPException(503, "MetricsAggregator not configured on this server")

    try:
        return ma.enrichment_effectiveness(platform=platform, days=days)
    except Exception as exc:
        raise HTTPException(500, str(exc))
