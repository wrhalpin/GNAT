# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.base
=========================================

Abstract base class for confirmation backends.
"""

from abc import ABC, abstractmethod
from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
    ConfirmationTimeout,
)


class ConfirmationBackend(ABC):
    """Abstract base class for confirmation backends."""

    @abstractmethod
    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """
        Prompt for confirmation and return the outcome.

        Args:
            request: The confirmation request

        Returns:
            ConfirmationOutcome (APPROVED or DENIED)

        Raises:
            ConfirmationTimeout: If the prompt times out
        """
        pass

    def notify_decided(
        self,
        request: ConfirmationRequest,
        outcome: ConfirmationOutcome,
    ) -> None:
        """
        Optional hook called after a decision is made (by policy or backend).

        Backends can use this to update UI state or clean up.

        Args:
            request: The confirmation request
            outcome: The decision outcome
        """
        pass
