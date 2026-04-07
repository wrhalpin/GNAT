# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting
==============

First-class intelligence report objects with a formal lifecycle and STIX export.

A :class:`~.models.Report` is a structured intelligence product produced from
one or more :class:`~gnat.analysis.investigations.Investigation` objects.  It
follows a five-state lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED →
ARCHIVED) enforced by :class:`~.service.ReportService`.

On publish, the report is serialised to a STIX 2.1 ``report`` SDO bundle
via :func:`~.export.stix.report_to_stix_bundle`.

Note: This module provides the *analyst intelligence product* layer.  It is
distinct from :mod:`gnat.reports`, which provides the PDF/DOCX report
generation pipeline for operational dashboards.

Quick start::

    from gnat.reporting import Report, ReportService, ReportStore, ReportType

    store   = ReportStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()
    service = ReportService(store)

    report = service.create(
        title       = "BLACKCAT Ransomware — April 2026",
        report_type = ReportType.INCIDENT_REPORT,
        authors     = ["analyst@example.com"],
    )

    service.add_finding(
        report.id,
        "Threat actor reused C2 infrastructure from the March 2026 BLACKCAT campaign.",
    )
    service.add_section(report.id, title="Technical Analysis", content="...")
    service.submit_for_review(report.id)
    service.approve(report.id, reviewer="manager@example.com")
    published = service.publish(report.id, changed_by="manager@example.com")

    print(published.stix_report_ref)   # STIX Report SDO ID
"""

from gnat.reporting.export.stix import report_to_stix_bundle
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
from gnat.reporting.service import ReportError, ReportService
from gnat.reporting.storage import ReportStore

__all__ = [
    # Models
    "Report",
    "Finding",
    "EvidenceLink",
    "Attribution",
    "ReportSection",
    "ChangelogEntry",
    # Enums
    "ReportType",
    "ReportStatus",
    "EvidenceLinkType",
    # Service + Store
    "ReportService",
    "ReportStore",
    "ReportError",
    # Export
    "report_to_stix_bundle",
]
