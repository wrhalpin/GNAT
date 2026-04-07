# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting.service
========================

:class:`ReportService` provides the business logic layer for Report lifecycle
management.

It enforces the five-state machine (DRAFT → REVIEW → APPROVED → PUBLISHED →
ARCHIVED, with REVIEW → DRAFT reject path), generates STIX bundles on
publish, and delegates persistence to :class:`~.storage.ReportStore`.

Usage::

    from gnat.reporting.service import ReportService
    from gnat.reporting.storage import ReportStore
    from gnat.reporting.models import ReportType

    store   = ReportStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()
    service = ReportService(store)

    report = service.create(
        title       = "BLACKCAT Ransomware — April 2026",
        report_type = ReportType.INCIDENT_REPORT,
        authors     = ["analyst@example.com"],
    )

    service.add_finding(report.id, "Threat actor reused C2 from March 2026 campaign.")
    service.add_section(report.id, title="Technical Analysis", content="...")
    service.submit_for_review(report.id)
    service.approve(report.id, reviewer="manager@example.com")
    published = service.publish(report.id, changed_by="manager@example.com")

    print(published.stix_report_ref)   # STIX Report SDO ID
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.confidence import ConfidenceScore
from gnat.analysis.tlp import TLPLevel
from gnat.reporting.models import (
    Attribution,
    ChangelogEntry,
    EvidenceLink,
    EvidenceLinkType,
    Finding,
    Report,
    ReportSection,
    ReportStatus,
    ReportType,
)
from gnat.reporting.storage import ReportStore

logger = logging.getLogger(__name__)


class ReportError(Exception):
    """Raised for invalid Report operations."""


class ReportService:
    """
    Business logic layer for Report lifecycle management.

    Parameters
    ----------
    store : ReportStore
        Persistence backend.
    """

    def __init__(self, store: ReportStore) -> None:
        """Initialize ReportService."""
        self._store = store

    # ── Factory / CRUD ────────────────────────────────────────────────────────

    def create(
        self,
        title:                str,
        report_type:          ReportType,
        authors:              list[str] | None = None,
        classification:       TLPLevel = TLPLevel.AMBER,
        linked_investigation: str | None = None,
        tags:                 list[str] | None = None,
    ) -> Report:
        """
        Create and persist a new Report in DRAFT status.

        Parameters
        ----------
        title : str
        report_type : ReportType
        authors : list of str, optional
        classification : TLPLevel
        linked_investigation : str, optional
            ID of the Investigation this report is derived from.
        tags : list of str, optional

        Returns
        -------
        Report
        """
        report = Report(
            title                = title,
            report_type          = report_type,
            authors              = list(authors or []),
            classification       = classification,
            linked_investigation = linked_investigation,
            tags                 = list(tags or []),
        )
        self._store.save(report)
        logger.info("ReportService: created report %s (%s)", report.id, title)
        return report

    def get(self, report_id: str) -> Report:
        """
        Retrieve a Report by ID.

        Raises
        ------
        ReportError
            If the report does not exist.
        """
        report = self._store.get(report_id)
        if report is None:
            raise ReportError(f"Report not found: {report_id}")
        return report

    def save(self, report: Report) -> Report:
        """Persist a Report that has been modified externally."""
        return self._store.save(report)

    def list(
        self,
        status:               ReportStatus | None = None,
        report_type:          ReportType | None = None,
        linked_investigation: str | None = None,
        tag:                  str | None = None,
        limit:                int = 100,
        offset:               int = 0,
    ) -> list[Report]:
        """List reports with optional filters."""
        return self._store.list(
            status=status, report_type=report_type,
            linked_investigation=linked_investigation,
            tag=tag, limit=limit, offset=offset,
        )

    def delete(self, report_id: str) -> None:
        """Soft-delete a Report."""
        if not self._store.delete(report_id):
            raise ReportError(f"Report not found: {report_id}")

    # ── State machine ─────────────────────────────────────────────────────────

    def submit_for_review(self, report_id: str, submitter: str | None = None) -> Report:
        """Transition a DRAFT report to REVIEW."""
        return self._transition(report_id, ReportStatus.REVIEW, submitter,
                                "Submitted for review.")

    def reject_to_draft(self, report_id: str, reviewer: str, reason: str = "") -> Report:
        """Reject a REVIEW report back to DRAFT with an optional reason."""
        note = f"Review rejected: {reason}" if reason else "Review rejected."
        return self._transition(report_id, ReportStatus.DRAFT, reviewer, note)

    def approve(self, report_id: str, reviewer: str) -> Report:
        """
        Transition a REVIEW report to APPROVED and record the reviewer.

        Parameters
        ----------
        report_id : str
        reviewer : str
            Analyst who approved the report.

        Returns
        -------
        Report
        """
        report = self.get(report_id)
        if not report.can_transition_to(ReportStatus.APPROVED):
            raise ReportError(
                f"Cannot approve report in status {report.status.value!r}."
            )
        if reviewer not in report.reviewers:
            report.reviewers.append(reviewer)
            self._store.save(report)  # persist reviewer before _transition reloads
        return self._transition(report_id, ReportStatus.APPROVED, reviewer, "Approved.")

    def publish(self, report_id: str, changed_by: str) -> Report:
        """
        Publish a report: APPROVED → PUBLISHED.

        On publish:
        - Sets ``published_at``
        - Generates STIX bundle via :mod:`.export.stix`
        - Stores ``stix_report_ref`` and ``stix_bundle_json``
        - Increments ``version`` and adds a changelog entry
        - Marks content as effectively immutable (enforced by service)

        Parameters
        ----------
        report_id : str
        changed_by : str

        Returns
        -------
        Report
            The published report.
        """
        from gnat.reporting.export.stix import report_to_stix_bundle

        report = self.get(report_id)
        if not report.can_transition_to(ReportStatus.PUBLISHED):
            raise ReportError(
                f"Cannot publish report in status {report.status.value!r}. "
                "Report must be APPROVED first."
            )

        report.status       = ReportStatus.PUBLISHED
        report.published_at = datetime.now(tz=timezone.utc)
        report.updated_at   = report.published_at

        # Generate STIX bundle
        bundle = report_to_stix_bundle(report)
        import json as _json
        report.stix_bundle_json = _json.dumps(bundle)
        # Extract the STIX Report SDO ID
        for obj in bundle.get("objects", []):
            if obj.get("type") == "report":
                report.stix_report_ref = obj["id"]
                break

        report.changelog.append(ChangelogEntry(
            version    = report.version,
            changed_by = changed_by,
            summary    = f"Published version {report.version}.",
        ))

        self._store.save(report)
        logger.info("ReportService: published report %s (v%d)", report.id, report.version)
        return report

    def archive(self, report_id: str, changed_by: str, reason: str = "") -> Report:
        """Transition any non-ARCHIVED report to ARCHIVED."""
        note = f"Archived: {reason}" if reason else "Archived."
        return self._transition(report_id, ReportStatus.ARCHIVED, changed_by, note)

    def _transition(
        self,
        report_id:  str,
        new_status: ReportStatus,
        changed_by: str | None,
        note:       str,
    ) -> Report:
        """Internal helper for transition."""
        report = self.get(report_id)
        if not report.can_transition_to(new_status):
            raise ReportError(
                f"Cannot transition report from {report.status.value!r} "
                f"to {new_status.value!r}."
            )
        old_status  = report.status
        report.status     = new_status
        report.updated_at = datetime.now(tz=timezone.utc)
        report.changelog.append(ChangelogEntry(
            version    = report.version,
            changed_by = changed_by or "system",
            summary    = f"{old_status.value} → {new_status.value}: {note}",
        ))
        self._store.save(report)
        logger.info("ReportService: %s %s → %s", report_id, old_status.value, new_status.value)
        return report

    # ── Content mutations ─────────────────────────────────────────────────────

    def _check_mutable(self, report: Report) -> None:
        """Raise ReportError if the report is published (immutable content)."""
        if report.is_published:
            raise ReportError(
                f"Report {report.id!r} is PUBLISHED and its content is immutable. "
                "Create a new version to make changes."
            )

    def update_summary(self, report_id: str, executive_summary: str) -> Report:
        """Update the executive summary of a DRAFT or REVIEW report."""
        report = self.get(report_id)
        self._check_mutable(report)
        report.executive_summary = executive_summary
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return report

    def add_section(
        self,
        report_id: str,
        title:     str,
        content:   str = "",
        order:     int | None = None,
    ) -> ReportSection:
        """
        Add a body section to a report.

        Parameters
        ----------
        report_id : str
        title : str
        content : str
        order : int, optional
            Display order. Defaults to ``max(existing orders) + 10``.

        Returns
        -------
        ReportSection
        """
        report = self.get(report_id)
        self._check_mutable(report)
        if order is None:
            existing_orders = [s.order for s in report.body_sections]
            order = (max(existing_orders) + 10) if existing_orders else 10
        section = ReportSection(title=title, content=content, order=order)
        report.body_sections.append(section)
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return section

    def add_finding(
        self,
        report_id:           str,
        statement:           str,
        confidence:          ConfidenceScore | None = None,
        mitre_techniques:    list[str] | None = None,
    ) -> Finding:
        """
        Add a key finding to a report.

        Returns
        -------
        Finding
        """
        report = self.get(report_id)
        self._check_mutable(report)
        finding = Finding(
            statement        = statement,
            confidence       = confidence,
            mitre_techniques = list(mitre_techniques or []),
        )
        report.key_findings.append(finding)
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return finding

    def add_evidence_link(
        self,
        report_id:       str,
        statement:       str,
        artifact_type:   str,
        artifact_id:     str,
        artifact_source: str,
        link_type:       EvidenceLinkType = EvidenceLinkType.SUPPORTS,
        confidence:      ConfidenceScore | None = None,
    ) -> EvidenceLink:
        """
        Add a statement-to-artifact evidence binding to a report.

        Returns
        -------
        EvidenceLink
        """
        report = self.get(report_id)
        self._check_mutable(report)
        link = EvidenceLink(
            statement       = statement,
            artifact_type   = artifact_type,
            artifact_id     = artifact_id,
            artifact_source = artifact_source,
            link_type       = link_type,
            confidence      = confidence,
        )
        report.evidence_links.append(link)
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return link

    def set_attribution(
        self,
        report_id:         str,
        threat_actor_name: str,
        confidence:        ConfidenceScore,
        rationale:         str,
        threat_actor_id:   str | None = None,
        mitre_group_id:    str | None = None,
    ) -> Report:
        """Set or replace the attribution on a report."""
        report = self.get(report_id)
        self._check_mutable(report)
        report.attribution = Attribution(
            threat_actor_name = threat_actor_name,
            confidence        = confidence,
            rationale         = rationale,
            threat_actor_id   = threat_actor_id,
            mitre_group_id    = mitre_group_id,
        )
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return report

    def add_recommendation(self, report_id: str, recommendation: str) -> Report:
        """Append a recommendation to a report."""
        report = self.get(report_id)
        self._check_mutable(report)
        report.recommendations.append(recommendation)
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return report

    def add_tags(self, report_id: str, tags: list[str]) -> Report:
        """Add tags to a report (deduplicates)."""
        report = self.get(report_id)
        existing = set(report.tags)
        report.tags = sorted(existing | set(tags))
        report.updated_at = datetime.now(tz=timezone.utc)
        self._store.save(report)
        return report

    # ── Versioning ────────────────────────────────────────────────────────────

    def create_revision(self, published_report_id: str, author: str) -> Report:
        """
        Create a new DRAFT revision of a PUBLISHED report.

        The new report has:
        - ``parent_report_id`` pointing to the published version
        - ``version`` incremented by 1
        - All content copied from the published version
        - Status reset to DRAFT

        Parameters
        ----------
        published_report_id : str
            ID of the published report to revise.
        author : str

        Returns
        -------
        Report
            The new draft revision.

        Raises
        ------
        ReportError
            If the source report is not PUBLISHED.
        """
        source = self.get(published_report_id)
        if source.status != ReportStatus.PUBLISHED:
            raise ReportError(
                f"Can only create a revision of a PUBLISHED report; "
                f"current status is {source.status.value!r}."
            )
        data = source.to_dict()
        import uuid as _uuid
        data["id"]               = str(_uuid.uuid4())
        data["status"]           = ReportStatus.DRAFT.value
        data["version"]          = source.version + 1
        data["parent_report_id"] = published_report_id
        data["stix_report_ref"]  = None
        data["stix_bundle_json"] = None
        data["published_at"]     = None
        data["authors"]          = [author]
        data["reviewers"]        = []
        from datetime import datetime, timezone as _tz
        now = datetime.now(tz=_tz.utc).isoformat()
        data["created_at"] = now
        data["updated_at"] = now
        data["changelog"]  = []

        new_report = Report.from_dict(data)
        self._store.save(new_report)
        logger.info(
            "ReportService: created revision %s (v%d) from %s",
            new_report.id, new_report.version, published_report_id,
        )
        return new_report

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self, report_id: str) -> dict[str, Any]:
        """
        Return a lightweight summary dict for a Report.

        Returns
        -------
        dict
            Keys: id, title, report_type, status, classification, authors,
            finding_count, evidence_link_count, section_count, tags,
            version, published_at, created_at, updated_at.
        """
        report = self.get(report_id)
        return {
            "id":                  report.id,
            "title":               report.title,
            "report_type":         report.report_type.value,
            "status":              report.status.value,
            "classification":      report.classification.label,
            "authors":             report.authors,
            "finding_count":       len(report.key_findings),
            "evidence_link_count": len(report.evidence_links),
            "section_count":       len(report.body_sections),
            "has_attribution":     report.attribution is not None,
            "tags":                report.tags,
            "version":             report.version,
            "parent_report_id":    report.parent_report_id,
            "stix_report_ref":     report.stix_report_ref,
            "published_at":        report.published_at.isoformat() if report.published_at else None,
            "created_at":          report.created_at.isoformat(),
            "updated_at":          report.updated_at.isoformat(),
        }
