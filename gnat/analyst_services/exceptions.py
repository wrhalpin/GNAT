# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services.exceptions
==================================

Exception hierarchy for the analyst services layer.

All service-level errors inherit from :class:`AnalystServiceError` so
callers can catch a single base class when they do not care about the
specific failure mode.
"""

from __future__ import annotations


class AnalystServiceError(Exception):
    """Base exception for all analyst service operations."""


class InvestigationNotFound(AnalystServiceError):
    """Raised when a requested investigation does not exist."""


class ReportNotFound(AnalystServiceError):
    """Raised when a requested report does not exist."""


class RuleNotFound(AnalystServiceError):
    """Raised when a requested rule does not exist."""


class TransitionError(AnalystServiceError):
    """Raised when a lifecycle state transition is invalid."""
