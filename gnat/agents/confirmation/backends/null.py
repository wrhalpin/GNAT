# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.null
=========================================

NullBackend that denies everything (safe default).
"""

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
)


class NullBackend(ConfirmationBackend):
    """
    Backend that denies all requests.

    Used as a safe default if no backend can be loaded.
    """

    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """Always return DENIED."""
        return ConfirmationOutcome.DENIED
