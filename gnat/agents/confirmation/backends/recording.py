# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.recording
===============================================

RecordingBackend for testing — records all prompts without actually prompting.
"""

from typing import List, Dict, Any
from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
)


class RecordingBackend(ConfirmationBackend):
    """
    Backend that records all prompts but doesn't actually prompt.

    Returns a configurable outcome (APPROVED or DENIED).
    Useful for testing to assert "this scope was requested" without
    actually prompting.
    """

    def __init__(self, outcome: ConfirmationOutcome = ConfirmationOutcome.APPROVED):
        """
        Initialize recording backend.

        Args:
            outcome: The outcome to return for all prompts (APPROVED or DENIED)
        """
        self.outcome = outcome
        self.recorded_requests: List[ConfirmationRequest] = []

    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """Record the request and return the configured outcome."""
        self.recorded_requests.append(request)
        return self.outcome

    def get_recorded_requests(self) -> List[ConfirmationRequest]:
        """Get all recorded requests."""
        return self.recorded_requests

    def clear(self) -> None:
        """Clear the recorded requests."""
        self.recorded_requests.clear()

    def find_by_scope(self, scope: str) -> List[ConfirmationRequest]:
        """Find all recorded requests matching a scope."""
        return [req for req in self.recorded_requests if req.scope == scope]

    def find_by_action(self, action: str) -> List[ConfirmationRequest]:
        """Find all recorded requests matching an action."""
        return [req for req in self.recorded_requests if req.action == action]

    def find_by_agent(self, agent: str) -> List[ConfirmationRequest]:
        """Find all recorded requests matching an agent."""
        return [req for req in self.recorded_requests if req.agent == agent]

    def assert_requested(self, scope: str, action: str | None = None) -> None:
        """
        Assert that a request was recorded.

        Args:
            scope: The scope that should have been requested
            action: Optional specific action

        Raises:
            AssertionError: If no matching request was found
        """
        matches = self.find_by_scope(scope)
        if action:
            matches = [m for m in matches if m.action == action]

        if not matches:
            raise AssertionError(
                f"No confirmation request found for scope '{scope}'"
                + (f" action '{action}'" if action else "")
            )

    def assert_not_requested(self, scope: str, action: str | None = None) -> None:
        """
        Assert that a request was NOT recorded.

        Args:
            scope: The scope that should not have been requested
            action: Optional specific action

        Raises:
            AssertionError: If a matching request was found
        """
        matches = self.find_by_scope(scope)
        if action:
            matches = [m for m in matches if m.action == action]

        if matches:
            raise AssertionError(
                f"Unexpected confirmation request for scope '{scope}'"
                + (f" action '{action}'" if action else "")
            )
