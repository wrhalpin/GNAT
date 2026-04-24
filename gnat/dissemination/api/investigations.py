# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.dissemination.api.investigations
=======================================

FastAPI REST endpoints for cross-tool investigation access.

Addons (SandGNAT, SenseGNAT, RedGNAT) use these endpoints to list
investigations, retrieve hypotheses, and attach evidence bundles
stamped with ``x_gnat_investigation_*`` properties.

Mount alongside the gateway router::

    from gnat.dissemination.api.investigations import build_investigation_router

    inv_router = build_investigation_router(investigation_service, key_store)
    app.include_router(inv_router, prefix="/api")
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.analysis.investigations.models import InvestigationStatus
from gnat.analysis.investigations.service import InvestigationError
from gnat.dissemination.api.auth import APIKey, APIKeyStore

logger = logging.getLogger(__name__)


def build_investigation_router(
    investigation_service: Any,
    key_store: APIKeyStore,
) -> Any:
    """
    Build a FastAPI router for investigation cross-tool endpoints.

    Parameters
    ----------
    investigation_service : InvestigationService
        Business logic layer for investigations.
    key_store : APIKeyStore
        API key store for authentication.

    Returns
    -------
    fastapi.APIRouter
    """
    try:
        from fastapi import APIRouter, Depends, Header, HTTPException, Query
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "FastAPI is required for the investigation API. "
            "Install with: pip install 'gnat[serve]'"
        ) from exc

    router = APIRouter(tags=["investigations"])

    def _require_api_key(authorization: str = Header(default="")) -> APIKey:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer token.")
        token = authorization.removeprefix("Bearer ").strip()
        key = key_store.get_key(token)
        if key is None or not key.is_valid():
            raise HTTPException(status_code=401, detail="Invalid or expired API key.")
        return key

    @router.get("/investigations")
    def list_investigations(
        status: str | None = Query(default=None),
        created_since: str | None = Query(default=None),
        tag: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=500),
        api_key: APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """List investigations visible to the authenticated tenant."""
        inv_status = None
        if status:
            try:
                inv_status = InvestigationStatus(status.lower())
            except ValueError:
                raise HTTPException(
                    status_code=400, detail=f"Invalid status: {status!r}"
                )

        investigations = investigation_service.list(
            status=inv_status,
            tag=tag,
            limit=page_size,
            offset=(page - 1) * page_size,
        )

        result = []
        for inv in investigations:
            result.append({
                "id": inv.id,
                "title": inv.title,
                "status": inv.status.value,
                "created_by": inv.created_by,
                "created_at": inv.created_at.isoformat(),
                "updated_at": inv.updated_at.isoformat(),
                "hypothesis_count": len(inv.hypothesis),
                "indicator_count": len(inv.indicators),
                "observable_count": len(inv.observables),
                "tags": inv.tags,
            })

        return JSONResponse({
            "page": page,
            "page_size": page_size,
            "count": len(result),
            "investigations": result,
        })

    @router.get("/investigations/{investigation_id}")
    def get_investigation(
        investigation_id: str,
        api_key: APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """Fetch a single investigation with hypotheses and linked object counts."""
        try:
            inv = investigation_service.get(investigation_id)
        except InvestigationError:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation not found: {investigation_id}",
            )

        return JSONResponse({
            "id": inv.id,
            "title": inv.title,
            "status": inv.status.value,
            "description": inv.description,
            "classification": inv.classification.value
            if hasattr(inv.classification, "value")
            else str(inv.classification),
            "created_by": inv.created_by,
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
            "hypothesis_count": len(inv.hypothesis),
            "indicator_count": len(inv.indicators),
            "observable_count": len(inv.observables),
            "source_connectors": inv.source_connectors,
            "tags": inv.tags,
        })

    @router.get("/investigations/{investigation_id}/hypotheses")
    def list_hypotheses(
        investigation_id: str,
        api_key: APIKey = Depends(_require_api_key),
    ) -> JSONResponse:
        """List hypotheses for an investigation."""
        try:
            inv = investigation_service.get(investigation_id)
        except InvestigationError:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation not found: {investigation_id}",
            )

        hypotheses = []
        for hyp in inv.hypothesis:
            hypotheses.append({
                "id": hyp.id,
                "statement": hyp.statement,
                "status": hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
                "confidence": hyp.confidence.to_dict() if hasattr(hyp.confidence, "to_dict") and hyp.confidence else None,
                "created_at": hyp.created_at.isoformat(),
            })

        return JSONResponse({
            "investigation_id": investigation_id,
            "hypotheses": hypotheses,
        })

    @router.post("/investigations/{investigation_id}/evidence")
    def post_evidence(
        investigation_id: str,
        body: dict[str, Any],
        api_key: APIKey = Depends(_require_api_key),
        x_reopen_investigation: str | None = Header(default=None),
    ) -> JSONResponse:
        """
        Accept a STIX bundle or Grouping stamped with this investigation's ID.

        Validates tenant, validates investigation exists and is not CLOSED,
        validates all contained objects carry a matching
        ``x_gnat_investigation_id``, then routes into existing ingest.
        """
        origin = body.get("x_gnat_investigation_origin", "external")
        tenant_id = api_key.tenant_id if hasattr(api_key, "tenant_id") else None

        if x_reopen_investigation:
            try:
                inv = investigation_service.get(investigation_id)
                if inv.status == InvestigationStatus.CLOSED:
                    investigation_service.transition(
                        investigation_id,
                        InvestigationStatus.IN_PROGRESS,
                        note=f"Reopened via evidence POST from {origin}",
                        author=f"api:{origin}",
                    )
            except InvestigationError:
                raise HTTPException(
                    status_code=404,
                    detail=f"Investigation not found: {investigation_id}",
                )

        try:
            result = investigation_service.attach_evidence_bundle(
                investigation_id=investigation_id,
                bundle=body,
                origin=origin,
                tenant_id=tenant_id,
            )
        except InvestigationError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

        status_code = 200 if result.accepted_count > 0 else 400
        return JSONResponse(
            {
                "accepted_count": result.accepted_count,
                "rejected_count": result.rejected_count,
                "rejection_reasons": result.rejection_reasons,
            },
            status_code=status_code,
        )

    return router
