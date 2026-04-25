# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analyst_services
========================

Thin service wrappers that coordinate existing domain services and
return Pydantic schemas.  These are the public entry points for the
GNAT GUI / API layer.

Re-exports
----------
- :class:`AnalystContext` — per-request identity and metadata
- :class:`AnalysisService` — investigation analysis orchestration
- :class:`InvestigationsService` — evidence graph construction
- :class:`RulesService` — rule evaluation and audit
- :class:`ReportingService` — report lifecycle management
"""

from gnat.analyst_services.analysis import AnalysisService
from gnat.analyst_services.context import AnalystContext
from gnat.analyst_services.exceptions import (
    AnalystServiceError,
    InvestigationNotFound,
    ReportNotFound,
    RuleNotFound,
    TransitionError,
)
from gnat.analyst_services.investigations import InvestigationsService
from gnat.analyst_services.reporting import ReportingService
from gnat.analyst_services.rules import RulesService

__all__ = [
    "AnalysisService",
    "AnalystContext",
    "AnalystServiceError",
    "InvestigationNotFound",
    "InvestigationsService",
    "ReportNotFound",
    "ReportingService",
    "RuleNotFound",
    "RulesService",
    "TransitionError",
]
