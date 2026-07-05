# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.dashboard
==============================================

DashboardBackend for web-based confirmation.

``prompt()`` parks the calling thread on a ``threading.Event`` (safe to
call whether or not an asyncio loop is running elsewhere in the process).
The FastAPI routes in :mod:`gnat.serve.routers.confirmations` list pending
requests and resolve them via :meth:`DashboardBackend.decide`.

Pending requests live in memory only. A process restart while a prompt is
pending surfaces as a timeout, and the broker fails closed — which is the
intended behaviour.
"""

import threading
from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    ConfirmationTimeout,
    PromptResult,
)


@dataclass
class _PendingPrompt:
    """A prompt waiting for an analyst decision."""

    request: ConfirmationRequest
    event: threading.Event = field(default_factory=threading.Event)
    outcome: Optional[ConfirmationOutcome] = None
    note: Optional[str] = None
    decided_by: Optional[str] = None


_shared_lock = threading.Lock()
_shared_instance: Optional["DashboardBackend"] = None


class DashboardBackend(ConfirmationBackend):
    """Backend that queues confirmation requests for the web dashboard."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: dict[UUID, _PendingPrompt] = {}

    @classmethod
    def shared(cls) -> "DashboardBackend":
        """Process-wide instance shared by the broker and the serve routes."""
        global _shared_instance
        with _shared_lock:
            if _shared_instance is None:
                _shared_instance = cls()
            return _shared_instance

    # ── Broker-facing API ──────────────────────────────────────────────

    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """
        Queue the request and block until an analyst decides or the
        request times out.
        """
        pending = _PendingPrompt(request=request)
        with self._lock:
            self._pending[request.request_id] = pending

        try:
            if not pending.event.wait(timeout=request.timeout_seconds):
                raise ConfirmationTimeout(request)
            return PromptResult(pending.outcome, note=pending.note)
        finally:
            with self._lock:
                self._pending.pop(request.request_id, None)

    # ── Dashboard-facing API ───────────────────────────────────────────

    def get_pending(self, workspace: Optional[str] = None) -> list[ConfirmationRequest]:
        """List pending requests, optionally filtered by workspace."""
        with self._lock:
            requests = [p.request for p in self._pending.values()]
        if workspace is not None:
            requests = [r for r in requests if r.workspace == workspace]
        return sorted(requests, key=lambda r: r.created_at)

    def decide(
        self,
        request_id: UUID,
        outcome: ConfirmationOutcome,
        note: Optional[str] = None,
        decided_by: str = "analyst",
    ) -> None:
        """
        Resolve a pending prompt (called by the web endpoint).

        Raises
        ------
        KeyError
            If ``request_id`` is not pending (already decided or timed out).
        """
        if outcome not in (ConfirmationOutcome.APPROVED, ConfirmationOutcome.DENIED):
            raise ValueError(
                f"Dashboard decisions must be APPROVED or DENIED, got {outcome.value!r}"
            )
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None:
                raise KeyError(f"No pending confirmation with id {request_id}")
            pending.outcome = outcome
            pending.note = note
            pending.decided_by = decided_by
            pending.event.set()
