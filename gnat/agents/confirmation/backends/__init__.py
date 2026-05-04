# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends
====================================

Backend implementations for confirmation broker.
"""

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.backends.auto import AutoApproveBackend
from gnat.agents.confirmation.backends.null import NullBackend
from gnat.agents.confirmation.backends.cli import CLIBackend
from gnat.agents.confirmation.backends.recording import RecordingBackend
from gnat.agents.confirmation.backends.dashboard import DashboardBackend

__all__ = [
    "ConfirmationBackend",
    "AutoApproveBackend",
    "NullBackend",
    "CLIBackend",
    "RecordingBackend",
    "DashboardBackend",
]
