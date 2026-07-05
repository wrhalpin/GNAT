# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.recording
===============================================

RecordingBackend for testing — records all prompts without actually prompting.
"""

from __future__ import annotations

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    PromptResult,
)


class RecordingBackend(ConfirmationBackend):
    """
    Backend that records all prompts but doesn't actually prompt.

    Returns a configurable outcome (APPROVED or DENIED). Useful for tests
    that need to assert "this scope was requested" without prompting.
    """

    def __init__(self, outcome: ConfirmationOutcome = ConfirmationOutcome.APPROVED):
        """
        Parameters
        ----------
        outcome : ConfirmationOutcome
            The outcome returned for every prompt.
        """
        self.outcome = outcome
        self.recorded_requests: list[ConfirmationRequest] = []

    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """Record the request and return the configured outcome."""
        self.recorded_requests.append(request)
        return PromptResult(self.outcome)

    def get_recorded_requests(self) -> list[ConfirmationRequest]:
        """Get all recorded requests."""
        return self.recorded_requests

    def clear(self) -> None:
        """Clear the recorded requests."""
        self.recorded_requests.clear()

    def find_by_scope(self, scope: str) -> list[ConfirmationRequest]:
        """Find all recorded requests matching a scope."""
        return [req for req in self.recorded_requests if req.scope == scope]

    def find_by_action(self, action: str) -> list[ConfirmationRequest]:
        """Find all recorded requests matching an action."""
        return [req for req in self.recorded_requests if req.action == action]

    def find_by_agent(self, agent: str) -> list[ConfirmationRequest]:
        """Find all recorded requests matching an agent."""
        return [req for req in self.recorded_requests if req.agent == agent]

    def assert_requested(self, scope: str, action: str | None = None) -> None:
        """
        Assert that a matching request was recorded.

        Raises
        ------
        AssertionError
            If no matching request was found.
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
        Assert that no matching request was recorded.

        Raises
        ------
        AssertionError
            If a matching request was found.
        """
        matches = self.find_by_scope(scope)
        if action:
            matches = [m for m in matches if m.action == action]

        if matches:
            raise AssertionError(
                f"Unexpected confirmation request for scope '{scope}'"
                + (f" action '{action}'" if action else "")
            )
