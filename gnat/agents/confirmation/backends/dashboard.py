# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.dashboard
==============================================

DashboardBackend for web-based confirmation via REST + WebSocket.
"""

import asyncio
from typing import Optional, Dict
from uuid import UUID

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
    ConfirmationTimeout,
)


class DashboardBackend(ConfirmationBackend):
    """
    Backend that dispatches confirmation requests to a web dashboard.

    Stores pending requests in memory; web handlers resolve them via
    /api/confirmations/{request_id}/decide endpoint.

    Synchronous prompt() blocks on a Future until the analyst decides
    or timeout elapses.

    Design:
    - pending_requests: dict[workspace][request_id] -> request
    - decision_futures: dict[request_id] -> asyncio.Future[ConfirmationOutcome]
    - Web handler: resolution of future via REST endpoint
    """

    def __init__(self):
        """Initialize dashboard backend."""
        self.pending_requests: Dict[str, Dict[UUID, ConfirmationRequest]] = {}
        self.decision_futures: Dict[UUID, asyncio.Future] = {}

    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """
        Queue request for dashboard and wait for decision.

        Blocks the calling thread until the analyst decides or timeout elapses.

        Args:
            request: The confirmation request

        Returns:
            ConfirmationOutcome (APPROVED or DENIED)

        Raises:
            ConfirmationTimeout: If timeout elapses
        """
        # Store request in pending
        if request.workspace not in self.pending_requests:
            self.pending_requests[request.workspace] = {}
        self.pending_requests[request.workspace][request.request_id] = request

        # Create future and wait
        loop = self._get_or_create_event_loop()
        future: asyncio.Future = loop.create_future()
        self.decision_futures[request.request_id] = future

        try:
            # Block with timeout
            outcome = loop.run_until_complete(
                asyncio.wait_for(future, timeout=request.timeout_seconds)
            )
            return outcome
        except asyncio.TimeoutError:
            raise ConfirmationTimeout(request)
        finally:
            # Clean up
            if request.request_id in self.decision_futures:
                del self.decision_futures[request.request_id]
            if request.workspace in self.pending_requests:
                self.pending_requests[request.workspace].pop(request.request_id, None)
                if not self.pending_requests[request.workspace]:
                    del self.pending_requests[request.workspace]

    def get_pending_for_workspace(self, workspace: str) -> list[ConfirmationRequest]:
        """Get all pending requests for a workspace."""
        if workspace not in self.pending_requests:
            return []
        return list(self.pending_requests[workspace].values())

    def decide(
        self,
        request_id: UUID,
        outcome: ConfirmationOutcome,
        decided_by: str = "analyst",
    ) -> None:
        """
        Resolve a pending decision (called by web endpoint).

        Args:
            request_id: The request UUID
            outcome: The decision outcome
            decided_by: Who made the decision

        Raises:
            KeyError: If request_id is not pending
        """
        if request_id not in self.decision_futures:
            raise KeyError(f"No pending request with id {request_id}")

        future = self.decision_futures[request_id]
        if not future.done():
            future.set_result(outcome)

    def _get_or_create_event_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create the current event loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError("Event loop is closed")
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        return loop
