# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.analytics
=============================

Analytics API endpoints for trend detection and Solr faceting.

Endpoints
---------
``GET  /api/analytics/trends``
    Detect volume spikes across STIX types.
``GET  /api/analytics/facets``
    Return Solr facet counts for a field.
``GET  /api/analytics/histogram``
    Return date histogram for a STIX type.
``GET  /api/analytics/summary``
    Return workspace-level summary stats.
``GET  /api/analytics/attack-coverage``
    Return MITRE ATT&CK tactic coverage counts.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def _get_trend_detector(request: Request) -> Any:
    td = getattr(request.app.state, "trend_detector", None)
    if td is None:
        raise HTTPException(status_code=503, detail="Trend detection not configured")
    return td


def _get_workspace_stats(request: Request) -> Any:
    ws = getattr(request.app.state, "workspace_stats", None)
    if ws is None:
        raise HTTPException(status_code=503, detail="Workspace stats not configured")
    return ws


def _get_search_index(request: Request) -> Any:
    idx = getattr(request.app.state, "search_index", None)
    if idx is None:
        raise HTTPException(status_code=503, detail="Search index not configured")
    return idx


@router.get("/trends")
def get_trends(
    request: Request,
    window_days: int = Query(14, ge=1, le=365),
    platform: str = Query("", description="Filter by source platform"),
    stix_type: list[str] = Query([], description="Restrict to these STIX types"),
    spikes_only: bool = Query(False, description="Return only spiking types"),
) -> dict[str, Any]:
    """
    Detect volume trends across STIX types.

    Returns TrendReport dicts sorted by absolute delta percentage.
    Set ``spikes_only=true`` to receive only types with detected spikes.
    """
    detector = _get_trend_detector(request)
    types = stix_type if stix_type else None
    try:
        if spikes_only:
            reports = detector.spikes_only(window_days=window_days, platform=platform)
        else:
            reports = detector.detect_all(
                window_days=window_days,
                platform=platform,
                stix_types=types,
            )
        return {
            "trends": [r.to_dict() for r in reports],
            "total": len(reports),
            "spikes": sum(1 for r in reports if r.is_spike),
        }
    except Exception as exc:
        logger.error("analytics/trends failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/facets")
def get_facets(
    request: Request,
    field: str = Query("stix_type", description="Solr field to facet on"),
    q: str = Query("*:*", description="Base Solr query"),
    stix_type: list[str] = Query([], description="Type filter"),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """
    Return Solr facet counts for a field.

    Useful for populating dashboard breakdown charts.

    Common fields: ``stix_type``, ``source_platform``, ``x_tlp``.
    """
    idx = _get_search_index(request)
    try:
        counts = idx.facet(
            field=field,
            query=q,
            stix_types=stix_type if stix_type else None,
            limit=limit,
        )
        return {"field": field, "counts": counts, "total_values": len(counts)}
    except Exception as exc:
        logger.error("analytics/facets failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/histogram")
def get_histogram(
    request: Request,
    date_field: str = Query("created", description="Date field: created or modified"),
    gap: str = Query("DAY", description="Bucket size: DAY, WEEK, MONTH, YEAR"),
    stix_type: list[str] = Query([], description="Type filter"),
    q: str = Query("*:*"),
) -> dict[str, Any]:
    """
    Return a date histogram for document creation/modification over time.

    Use ``gap=MONTH`` for trend charts, ``gap=DAY`` for recent activity feeds.
    """
    if gap not in {"DAY", "WEEK", "MONTH", "YEAR"}:
        raise HTTPException(status_code=400, detail="gap must be DAY, WEEK, MONTH, or YEAR")
    idx = _get_search_index(request)
    try:
        hist = idx.histogram(
            date_field=date_field,
            gap=gap,
            query=q,
            stix_types=stix_type if stix_type else None,
        )
        return {
            "date_field": date_field,
            "gap": gap,
            "buckets": hist,
            "total_buckets": len(hist),
        }
    except Exception as exc:
        logger.error("analytics/histogram failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/summary")
def get_summary(request: Request) -> dict[str, Any]:
    """
    Return a workspace-level summary (type counts, platform counts,
    confidence distribution).
    """
    ws = _get_workspace_stats(request)
    try:
        return ws.summary()
    except Exception as exc:
        logger.error("analytics/summary failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/attack-coverage")
def get_attack_coverage(request: Request) -> dict[str, Any]:
    """
    Return MITRE ATT&CK tactic coverage statistics.

    Coverage is measured by the number of indexed ``attack-pattern`` objects
    per tactic.
    """
    ws = _get_workspace_stats(request)
    try:
        coverages = ws.attack_coverage_report()
        return {
            "tactics": [c.to_dict() for c in coverages],
            "covered_tactics": sum(1 for c in coverages if c.object_count > 0),
            "total_tactics": len(coverages),
        }
    except Exception as exc:
        logger.error("analytics/attack-coverage failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
