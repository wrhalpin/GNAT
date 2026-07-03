# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.auto
=========================================

AutoApproveBackend for testing and CI environments.
"""

import os

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    PromptResult,
)


class AutoApproveBackend(ConfirmationBackend):
    """
    Backend that approves all requests without prompting.

    Intended for testing and CI environments only. Refuses to load
    if GNAT_ENV is not "test", "ci", or "dev". Requests still flow
    through the broker and are audited.
    """

    def __init__(self):
        env = os.environ.get("GNAT_ENV", "").lower()
        if env not in ("test", "ci", "dev"):
            raise RuntimeError(
                f"AutoApproveBackend is only allowed in test/ci/dev environments. GNAT_ENV={env!r}"
            )

    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """Always approve."""
        return PromptResult(ConfirmationOutcome.APPROVED, note="auto-approve backend")
