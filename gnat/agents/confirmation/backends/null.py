# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.null
=========================================

NullBackend that denies everything (safe default).
"""

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    PromptResult,
)


class NullBackend(ConfirmationBackend):
    """
    Backend that denies all requests.

    Used as the fail-closed fallback when the configured backend cannot
    be loaded on an *enabled* broker.
    """

    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """Always deny."""
        return PromptResult(
            ConfirmationOutcome.DENIED,
            note="null backend: no confirmation backend available",
        )
