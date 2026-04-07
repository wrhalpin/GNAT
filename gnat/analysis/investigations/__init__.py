"""
gnat.analysis.investigations
==============================

First-class Investigation objects for analyst lifecycle management.

An :class:`Investigation` tracks the full analyst workflow: scoping,
hypothesis development, evidence collection (linked indicators/observables),
task management, and closure.

Quick start::

    from gnat.analysis.investigations import (
        Investigation,
        InvestigationService,
        InvestigationStore,
        InvestigationStatus,
    )

    store   = InvestigationStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()
    service = InvestigationService(store)

    inv = service.create(
        title      = "Ransomware Apr 2026",
        created_by = "analyst@example.com",
        tags       = ["ransomware", "blackcat"],
    )

    service.add_hypothesis(inv.id, "BLACKCAT operator reused April 2026 C2 infra.")
    service.add_task(inv.id, "Collect memory dump from workstation-42")
    service.link_indicators(inv.id, ["indicator--abc", "indicator--def"])
    service.transition(inv.id, InvestigationStatus.IN_PROGRESS)
"""

from gnat.analysis.investigations.models import (
    AnalystNote,
    Hypothesis,
    HypothesisStatus,
    Investigation,
    InvestigationScope,
    InvestigationStatus,
    InvestigationTask,
    TaskPriority,
    TaskStatus,
)
from gnat.analysis.investigations.service import InvestigationError, InvestigationService
from gnat.analysis.investigations.storage import InvestigationStore

__all__ = [
    # Models
    "Investigation",
    "InvestigationScope",
    "Hypothesis",
    "AnalystNote",
    "InvestigationTask",
    # Enums
    "InvestigationStatus",
    "HypothesisStatus",
    "TaskStatus",
    "TaskPriority",
    # Service + Store
    "InvestigationService",
    "InvestigationStore",
    "InvestigationError",
]
