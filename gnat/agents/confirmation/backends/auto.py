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
    ConfirmationRequest,
    ConfirmationOutcome,
)


class AutoApproveBackend(ConfirmationBackend):
    """
    Backend that auto-approves all requests.

    Intended for testing and CI environments only. Refuses to load
    if GNAT_ENV is not "test" or "ci".
    """

    def __init__(self):
        env = os.environ.get("GNAT_ENV", "").lower()
        if env not in ("test", "ci", "dev"):
            raise RuntimeError(
                "AutoApproveBackend is only allowed in test/ci/dev environments. "
                f"GNAT_ENV={env}"
            )

    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """Always return APPROVED."""
        return ConfirmationOutcome.APPROVED
