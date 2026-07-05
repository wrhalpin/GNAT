# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.base
=========================================

Abstract base class for confirmation backends.
"""

from abc import ABC, abstractmethod

from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    PromptResult,
)


class ConfirmationBackend(ABC):
    """Abstract base class for confirmation backends."""

    @abstractmethod
    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """
        Prompt for confirmation and return the result.

        Implementations must respect ``request.timeout_seconds``.

        Parameters
        ----------
        request : ConfirmationRequest
            The confirmation request.

        Returns
        -------
        PromptResult
            The outcome (APPROVED or DENIED) plus an optional analyst note.

        Raises
        ------
        ConfirmationTimeout
            If no decision arrives within ``request.timeout_seconds``.
        """
        ...

    def notify_decided(  # noqa: B027 — optional hook, deliberately non-abstract
        self,
        request: ConfirmationRequest,
        outcome: ConfirmationOutcome,
    ) -> None:
        """
        Optional hook called after a decision is made (by policy or backend).

        Backends can use this to update UI state or clean up.
        """
