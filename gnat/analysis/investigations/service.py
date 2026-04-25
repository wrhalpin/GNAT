# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.investigations.service
======================================

:class:`InvestigationService` provides the business logic layer for
Investigation lifecycle management.

It enforces state machine transitions, owns all mutation operations, and
delegates persistence to :class:`~.storage.InvestigationStore`.

Usage::

    from gnat.analysis.investigations.storage import InvestigationStore
    from gnat.analysis.investigations.service import InvestigationService

    store   = InvestigationStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()
    service = InvestigationService(store)

    # Create
    inv = service.create(
        title      = "Ransomware Apr 2026",
        created_by = "analyst@example.com",
        tags       = ["ransomware", "blackcat"],
    )

    # Transition
    service.transition(inv.id, InvestigationStatus.IN_PROGRESS)

    # Add a note
    service.add_note(inv.id, content="Initial triage complete.", author="analyst@example.com")

    # Add a hypothesis
    service.add_hypothesis(inv.id, statement="BLACKCAT operator reused C2 from March campaign.")

    # Link indicators
    service.link_indicators(inv.id, ["indicator--abc", "indicator--def"])
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.confidence import ConfidenceScore
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
from gnat.analysis.investigations.storage import InvestigationStore
from gnat.analysis.tlp import TLPLevel

logger = logging.getLogger(__name__)


VALID_ORIGINS = frozenset({"sandgnat", "sensegnat", "redgnat", "gnat", "external"})


class InvestigationError(Exception):
    """Raised for invalid Investigation operations."""


@dataclass
class AttachResult:
    """Result of attaching an evidence bundle to an investigation."""

    accepted_count: int = 0
    rejected_count: int = 0
    rejection_reasons: list[str] = field(default_factory=list)


class InvestigationService:
    """
    Business logic layer for Investigation lifecycle management.

    Parameters
    ----------
    store : InvestigationStore
        Persistence backend.

    Notes
    -----
    All mutating methods call ``store.save()`` before returning.  Callers
    that need to batch updates should manipulate the Investigation object
    directly and call ``service.save(inv)`` once.
    """

    def __init__(self, store: InvestigationStore) -> None:
        """Initialize InvestigationService."""
        self._store = store

    # ── Factory / CRUD ────────────────────────────────────────────────────────

    def create(
        self,
        title: str,
        created_by: str,
        description: str = "",
        classification: TLPLevel = TLPLevel.AMBER,
        assigned_to: list[str] | None = None,
        scope: InvestigationScope | None = None,
        tags: list[str] | None = None,
        source_connectors: list[str] | None = None,
    ) -> Investigation:
        """
        Create and persist a new Investigation in OPEN status.

        Parameters
        ----------
        title : str
            Short investigation title.
        created_by : str
            Analyst identifier (username or email).
        description : str
            Markdown-formatted background.
        classification : TLPLevel
            TLP classification (default AMBER).
        assigned_to : list of str, optional
            Initially assigned analysts.
        scope : InvestigationScope, optional
            Scope constraints.
        tags : list of str, optional
            Free-text tags.
        source_connectors : list of str, optional
            Platform names contributing data.

        Returns
        -------
        Investigation
        """
        inv = Investigation(
            title=title,
            created_by=created_by,
            description=description,
            classification=classification,
            assigned_to=list(assigned_to or []),
            scope=scope or InvestigationScope(),
            tags=list(tags or []),
            source_connectors=list(source_connectors or []),
        )
        self._store.save(inv)
        logger.info("InvestigationService: created investigation %s (%s)", inv.id, title)
        return inv

    def get(self, investigation_id: str) -> Investigation:
        """
        Retrieve an Investigation by ID.

        Raises
        ------
        InvestigationError
            If the investigation does not exist.
        """
        inv = self._store.get(investigation_id)
        if inv is None:
            raise InvestigationError(f"Investigation not found: {investigation_id}")
        return inv

    def save(self, investigation: Investigation) -> Investigation:
        """Persist an Investigation that has been modified externally."""
        return self._store.save(investigation)

    def list(
        self,
        query: Any | None = None,
        status: InvestigationStatus | None = None,
        created_by: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Investigation]:
        """
        List investigations with optional filters.

        Pass an :class:`~gnat.analysis.query.InvestigationQuery` as *query*
        for rich filtering and pagination.  Legacy keyword arguments are still
        accepted for backward compatibility.
        """
        from gnat.analysis.query import InvestigationQuery

        if isinstance(query, InvestigationQuery):
            return self._store.list(query=query)
        return self._store.list(
            status=status, created_by=created_by, tag=tag, limit=limit, offset=offset
        )

    def delete(self, investigation_id: str) -> None:
        """Soft-delete an Investigation."""
        if not self._store.delete(investigation_id):
            raise InvestigationError(f"Investigation not found: {investigation_id}")
        logger.info("InvestigationService: deleted investigation %s", investigation_id)

    # ── State machine ─────────────────────────────────────────────────────────

    def transition(
        self,
        investigation_id: str,
        new_status: InvestigationStatus,
        note: str | None = None,
        author: str | None = None,
    ) -> Investigation:
        """
        Transition an Investigation to a new lifecycle state.

        Parameters
        ----------
        investigation_id : str
            ID of the investigation to transition.
        new_status : InvestigationStatus
            Target state.
        note : str, optional
            Optional analyst note to attach describing the reason.
        author : str, optional
            Analyst performing the transition (required if *note* is provided).

        Returns
        -------
        Investigation
            The updated investigation.

        Raises
        ------
        InvestigationError
            If the transition is not valid from the current state.
        """
        inv = self.get(investigation_id)
        if not inv.can_transition_to(new_status):
            raise InvestigationError(
                f"Cannot transition investigation from {inv.status.value!r} "
                f"to {new_status.value!r}."
            )
        old_status = inv.status
        inv.status = new_status
        inv.updated_at = datetime.now(tz=timezone.utc)

        if note and author:
            inv.notes.append(
                AnalystNote(
                    content=f"**Status changed:** `{old_status.value}` → `{new_status.value}`\n\n{note}",
                    author=author,
                )
            )

        self._store.save(inv)
        logger.info(
            "InvestigationService: %s transitioned %s → %s",
            investigation_id,
            old_status.value,
            new_status.value,
        )
        return inv

    # ── Notes ─────────────────────────────────────────────────────────────────

    def add_note(
        self,
        investigation_id: str,
        content: str,
        author: str,
        linked_artifacts: list[str] | None = None,
    ) -> AnalystNote:
        """
        Add a markdown note to an Investigation.

        Parameters
        ----------
        investigation_id : str
        content : str
            Markdown-formatted note body.
        author : str
        linked_artifacts : list of str, optional
            Artifact IDs this note annotates.

        Returns
        -------
        AnalystNote
            The newly created note.
        """
        inv = self.get(investigation_id)
        note = AnalystNote(
            content=content,
            author=author,
            linked_artifacts=list(linked_artifacts or []),
        )
        inv.notes.append(note)
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return note

    # ── Tasks ─────────────────────────────────────────────────────────────────

    def add_task(
        self,
        investigation_id: str,
        title: str,
        description: str = "",
        priority: TaskPriority = TaskPriority.MEDIUM,
        assigned_to: str | None = None,
        due_date: datetime | None = None,
    ) -> InvestigationTask:
        """
        Add an actionable task to an Investigation.

        Returns
        -------
        InvestigationTask
            The newly created task.
        """
        inv = self.get(investigation_id)
        task = InvestigationTask(
            title=title,
            description=description,
            priority=priority,
            assigned_to=assigned_to,
            due_date=due_date,
        )
        inv.tasks.append(task)
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return task

    def update_task_status(
        self,
        investigation_id: str,
        task_id: str,
        new_status: TaskStatus,
    ) -> InvestigationTask:
        """
        Update the status of a task within an Investigation.

        Raises
        ------
        InvestigationError
            If the task is not found.
        """
        inv = self.get(investigation_id)
        for task in inv.tasks:
            if task.id == task_id:
                task.status = new_status
                task.updated_at = datetime.now(tz=timezone.utc)
                inv.updated_at = datetime.now(tz=timezone.utc)
                self._store.save(inv)
                return task
        raise InvestigationError(
            f"Task {task_id!r} not found in investigation {investigation_id!r}"
        )

    # ── Hypotheses ────────────────────────────────────────────────────────────

    def add_hypothesis(
        self,
        investigation_id: str,
        statement: str,
        confidence: ConfidenceScore | None = None,
    ) -> Hypothesis:
        """
        Add an analytical hypothesis to an Investigation.

        Returns
        -------
        Hypothesis
            The newly created hypothesis.
        """
        inv = self.get(investigation_id)
        hyp = Hypothesis(
            statement=statement,
            confidence=confidence,
        )
        inv.hypothesis.append(hyp)
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return hyp

    def update_hypothesis_status(
        self,
        investigation_id: str,
        hypothesis_id: str,
        new_status: HypothesisStatus,
        confidence: ConfidenceScore | None = None,
    ) -> Hypothesis:
        """
        Update the evaluation status (and optionally confidence) of a hypothesis.

        Raises
        ------
        InvestigationError
            If the hypothesis is not found.
        """
        inv = self.get(investigation_id)
        for hyp in inv.hypothesis:
            if hyp.id == hypothesis_id:
                hyp.status = new_status
                hyp.updated_at = datetime.now(tz=timezone.utc)
                if confidence is not None:
                    hyp.confidence = confidence
                inv.updated_at = datetime.now(tz=timezone.utc)
                self._store.save(inv)
                return hyp
        raise InvestigationError(
            f"Hypothesis {hypothesis_id!r} not found in investigation {investigation_id!r}"
        )

    # ── Artifact linking ──────────────────────────────────────────────────────

    def link_indicators(self, investigation_id: str, indicator_ids: list[str]) -> Investigation:
        """Attach indicator IDs to an Investigation (deduplicates)."""
        inv = self.get(investigation_id)
        existing = set(inv.indicators)
        inv.indicators = sorted(existing | set(indicator_ids))
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return inv

    def link_observables(self, investigation_id: str, observable_ids: list[str]) -> Investigation:
        """Attach observable IDs to an Investigation (deduplicates)."""
        inv = self.get(investigation_id)
        existing = set(inv.observables)
        inv.observables = sorted(existing | set(observable_ids))
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return inv

    def link_threat_actors(
        self, investigation_id: str, threat_actor_ids: list[str]
    ) -> Investigation:
        """Attach STIX ThreatActor IDs to an Investigation (deduplicates)."""
        inv = self.get(investigation_id)
        existing = set(inv.threat_actors)
        inv.threat_actors = sorted(existing | set(threat_actor_ids))
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return inv

    def link_report(self, investigation_id: str, report_id: str) -> Investigation:
        """Attach a Report ID to an Investigation."""
        inv = self.get(investigation_id)
        if report_id not in inv.reports:
            inv.reports.append(report_id)
            inv.updated_at = datetime.now(tz=timezone.utc)
            self._store.save(inv)
        return inv

    # ── Tagging ───────────────────────────────────────────────────────────────

    def add_tags(self, investigation_id: str, tags: list[str]) -> Investigation:
        """Add tags to an Investigation (deduplicates, case-preserving)."""
        inv = self.get(investigation_id)
        existing = set(inv.tags)
        inv.tags = sorted(existing | set(tags))
        inv.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(inv)
        return inv

    # ── Cross-tool evidence ─────────────────────────────────────────────────

    def attach_evidence_bundle(
        self,
        investigation_id: str,
        bundle: dict[str, Any],
        origin: str,
        tenant_id: str | None = None,
    ) -> AttachResult:
        """
        Validate and ingest a STIX bundle stamped for an investigation.

        Parameters
        ----------
        investigation_id : str
            Target investigation.
        bundle : dict
            STIX 2.1 bundle (or Grouping envelope).
        origin : str
            Addon origin label (``"sandgnat"``, ``"sensegnat"``, etc.).
        tenant_id : str or None
            Tenant scope.  When set, the investigation must belong to this
            tenant; cross-tenant references are rejected.

        Returns
        -------
        AttachResult
        """
        result = AttachResult()

        if origin not in VALID_ORIGINS:
            result.rejected_count = 1
            result.rejection_reasons.append(f"Invalid origin: {origin!r}")
            return result

        inv = self._store.get(investigation_id)
        if inv is None:
            result.rejected_count = 1
            result.rejection_reasons.append(f"Investigation not found: {investigation_id}")
            return result

        inv_tenant = getattr(inv, "tenant_id", None)
        if tenant_id and inv_tenant and inv_tenant != tenant_id:
            result.rejected_count = 1
            result.rejection_reasons.append(
                f"Cross-tenant reference denied: investigation belongs to "
                f"tenant {inv_tenant!r}, request authenticated as {tenant_id!r}"
            )
            return result

        if inv.status == InvestigationStatus.CLOSED:
            raise InvestigationError(
                f"Investigation {investigation_id} is CLOSED. "
                f"Set X-Reopen-Investigation header to reopen."
            )

        objects = bundle.get("objects", [])
        if not objects:
            objects_from_grouping = bundle.get("object_refs", [])
            if not objects_from_grouping:
                result.rejection_reasons.append("Bundle contains no objects")
                return result

        for obj in objects:
            obj_inv_id = obj.get("x_gnat_investigation_id")
            if obj_inv_id and obj_inv_id != investigation_id:
                result.rejected_count += 1
                result.rejection_reasons.append(
                    f"Object {obj.get('id', '?')} stamped with "
                    f"investigation_id={obj_inv_id!r}, expected {investigation_id!r}"
                )
                continue

            obj_type = obj.get("type", "")
            obj_id = obj.get("id", "")
            if obj_type == "indicator" and obj_id:
                if obj_id not in inv.indicators:
                    inv.indicators.append(obj_id)
            elif obj_id and obj_id not in inv.observables:
                inv.observables.append(obj_id)
            result.accepted_count += 1

        if result.accepted_count > 0:
            if origin not in inv.source_connectors:
                inv.source_connectors.append(origin)
            inv.updated_at = datetime.now(tz=timezone.utc)
            self._store.save(inv)
            logger.info(
                "InvestigationService: attached %d objects from %s to %s",
                result.accepted_count,
                origin,
                investigation_id,
            )
        return result

    def find_by_subject(
        self,
        subject_ref: str,
        tenant_id: str | None = None,
    ) -> list[Investigation]:
        """
        Find investigations whose evidence already contains *subject_ref*.

        Parameters
        ----------
        subject_ref : str
            STIX object ID or IOC value to search for.
        tenant_id : str or None
            Restrict to a specific tenant.

        Returns
        -------
        list of Investigation
        """
        all_investigations = self._store.list(limit=10000)
        matches: list[Investigation] = []
        for inv in all_investigations:
            if tenant_id:
                inv_tenant = getattr(inv, "tenant_id", None)
                if inv_tenant and inv_tenant != tenant_id:
                    continue
            if subject_ref in inv.indicators or subject_ref in inv.observables:
                matches.append(inv)
        return matches

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self, investigation_id: str) -> dict[str, Any]:
        """
        Return a lightweight summary dict for an Investigation.

        Suitable for display in list views without loading full nested objects.

        Returns
        -------
        dict
            Keys: id, title, status, classification, created_by,
            hypothesis_count, note_count, task_count, indicator_count,
            observable_count, tags, created_at, updated_at.
        """
        inv = self.get(investigation_id)
        open_tasks = sum(1 for t in inv.tasks if t.status != TaskStatus.DONE)
        return {
            "id": inv.id,
            "title": inv.title,
            "status": inv.status.value,
            "classification": inv.classification.label,
            "created_by": inv.created_by,
            "hypothesis_count": len(inv.hypothesis),
            "note_count": len(inv.notes),
            "task_count": len(inv.tasks),
            "open_task_count": open_tasks,
            "indicator_count": len(inv.indicators),
            "observable_count": len(inv.observables),
            "tags": inv.tags,
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
        }
