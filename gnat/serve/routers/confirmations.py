# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.confirmations
===================================

FastAPI routes for pending ConfirmationBroker requests.

These routes talk to the process-wide :class:`DashboardBackend` instance.
They only do anything useful when the broker is configured with
``backend = dashboard`` in the ``[confirmation]`` INI section; otherwise
the pending list is simply always empty.

Auth is applied at router registration in :mod:`gnat.serve.app` via
``Depends(APIKeyAuth)``, matching the other routers.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from gnat.agents.confirmation.backends.dashboard import DashboardBackend
from gnat.agents.confirmation.models import ConfirmationOutcome

router = APIRouter(prefix="/api/confirmations", tags=["confirmations"])


@router.get("/pending")
async def list_pending_confirmations(
    workspace: Optional[str] = Query(None),
):
    """List confirmation requests waiting for an analyst decision."""
    backend = DashboardBackend.shared()
    pending = backend.get_pending(workspace=workspace)
    return {
        "pending": [
            {
                "request_id": str(req.request_id),
                "created_at": req.created_at.isoformat(),
                "workspace": req.workspace,
                "scope": req.scope,
                "action": req.action,
                "agent": req.agent,
                "risk": req.risk,
                "reason": req.reason,
                "subject": req.subject,
                "timeout_seconds": req.timeout_seconds,
            }
            for req in pending
        ],
        "count": len(pending),
    }


@router.post("/{request_id}/decide")
async def decide_confirmation(
    request_id: str,
    outcome: str = Query(..., pattern="^(approved|denied)$"),
    note: Optional[str] = Query(None),
    decided_by: str = Query("analyst"),
):
    """Approve or deny a pending confirmation request."""
    try:
        request_uuid = UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="request_id is not a valid UUID")

    outcome_enum = (
        ConfirmationOutcome.APPROVED if outcome == "approved" else ConfirmationOutcome.DENIED
    )

    backend = DashboardBackend.shared()
    try:
        backend.decide(
            request_uuid,
            outcome_enum,
            note=note,
            decided_by=decided_by,
        )
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="No pending confirmation with that id (already decided or timed out)",
        )

    return {"request_id": request_id, "outcome": outcome, "note": note}
