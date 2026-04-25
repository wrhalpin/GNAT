# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for reporting domain schemas — round-trip from domain dataclasses."""

from __future__ import annotations

from datetime import datetime, timezone

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
from gnat.schemas.reporting.report import (
    AttributionSchema,
    ChangelogEntrySchema,
    EvidenceLinkSchema,
    FindingSchema,
    ReportSchema,
    ReportSectionSchema,
)


class TestFindingSchema:
    def test_round_trip(self) -> None:
        conf = ConfidenceScore.high("Strong IOC correlation.")
        domain = Finding(
            statement="Adversary used T1059.003 for execution.",
            confidence=conf,
            supporting_evidence=["ev-001", "ev-002"],
            mitre_techniques=["T1059.003"],
        )
        schema = FindingSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["statement"] == "Adversary used T1059.003 for execution."
        assert dumped["confidence"]["stix_confidence"] == 75
        assert dumped["supporting_evidence"] == ["ev-001", "ev-002"]
        assert dumped["mitre_techniques"] == ["T1059.003"]
        assert len(dumped["id"]) > 0

    def test_no_confidence(self) -> None:
        domain = Finding(statement="Minimal finding.")
        schema = FindingSchema.from_domain(domain)
        assert schema.confidence is None
        assert schema.supporting_evidence == []
        assert schema.mitre_techniques == []


class TestEvidenceLinkSchema:
    def test_round_trip(self) -> None:
        conf = ConfidenceScore.medium()
        domain = EvidenceLink(
            statement="C2 traffic observed to 185.220.101.5.",
            artifact_type="indicator",
            artifact_id="indicator--abc",
            artifact_source="threatq",
            link_type=EvidenceLinkType.SUPPORTS,
            confidence=conf,
        )
        schema = EvidenceLinkSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["statement"] == "C2 traffic observed to 185.220.101.5."
        assert dumped["artifact_type"] == "indicator"
        assert dumped["artifact_id"] == "indicator--abc"
        assert dumped["artifact_source"] == "threatq"
        assert dumped["link_type"] == "supports"
        assert dumped["confidence"]["stix_confidence"] == 50


class TestAttributionSchema:
    def test_round_trip(self) -> None:
        conf = ConfidenceScore.high("TTP overlap with known group.")
        domain = Attribution(
            threat_actor_name="APT28",
            confidence=conf,
            rationale="Shared infrastructure and tooling.",
            threat_actor_id="threat-actor--xyz",
            mitre_group_id="G0007",
        )
        schema = AttributionSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["threat_actor_name"] == "APT28"
        assert dumped["rationale"] == "Shared infrastructure and tooling."
        assert dumped["threat_actor_id"] == "threat-actor--xyz"
        assert dumped["mitre_group_id"] == "G0007"
        assert dumped["confidence"]["source_reliability"] == "B"


class TestReportSectionSchema:
    def test_round_trip(self) -> None:
        domain = ReportSection(
            title="Executive Summary",
            content="The investigation revealed...",
            order=1,
        )
        schema = ReportSectionSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["title"] == "Executive Summary"
        assert dumped["content"] == "The investigation revealed..."
        assert dumped["order"] == 1


class TestChangelogEntrySchema:
    def test_round_trip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        domain = ChangelogEntry(
            version=2,
            changed_by="reviewer@corp.com",
            summary="Updated attribution section.",
            changed_at=now,
        )
        schema = ChangelogEntrySchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["version"] == 2
        assert dumped["changed_by"] == "reviewer@corp.com"
        assert dumped["summary"] == "Updated attribution section."
        assert dumped["changed_at"] == now


class TestReportSchema:
    def test_round_trip(self) -> None:
        conf = ConfidenceScore.high("Multiple sources.")
        finding = Finding(
            statement="Ransomware deployed via RDP.",
            confidence=conf,
            mitre_techniques=["T1021.001"],
        )
        section = ReportSection(title="Background", content="...", order=0)
        evidence = EvidenceLink(
            statement="RDP logs show lateral movement.",
            artifact_type="observed-data",
            artifact_id="od-001",
            artifact_source="elastic",
        )
        attribution = Attribution(
            threat_actor_name="BLACKCAT",
            confidence=conf,
            rationale="Tooling matches.",
        )
        changelog = ChangelogEntry(
            version=1,
            changed_by="analyst@corp.com",
            summary="Initial draft.",
        )

        domain = Report(
            title="BLACKCAT Ransomware - April 2026",
            report_type=ReportType.INCIDENT_REPORT,
            status=ReportStatus.REVIEW,
            classification=TLPLevel.RED,
            authors=["analyst@corp.com"],
            reviewers=["reviewer@corp.com"],
            executive_summary="Summary of the incident.",
            key_findings=[finding],
            body_sections=[section],
            recommendations=["Patch RDP.", "Enable MFA."],
            attribution=attribution,
            overall_confidence=conf,
            evidence_links=[evidence],
            linked_investigation="inv-001",
            version=1,
            changelog=[changelog],
            tags=["ransomware", "blackcat"],
            distribution_list=["ciso@corp.com"],
        )

        schema = ReportSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["title"] == "BLACKCAT Ransomware - April 2026"
        assert dumped["report_type"] == "incident_report"
        assert dumped["status"] == "review"
        assert dumped["classification"] == "red"
        assert dumped["authors"] == ["analyst@corp.com"]
        assert dumped["reviewers"] == ["reviewer@corp.com"]
        assert dumped["executive_summary"] == "Summary of the incident."
        assert len(dumped["key_findings"]) == 1
        assert dumped["key_findings"][0]["mitre_techniques"] == ["T1021.001"]
        assert len(dumped["body_sections"]) == 1
        assert dumped["recommendations"] == ["Patch RDP.", "Enable MFA."]
        assert dumped["attribution"]["threat_actor_name"] == "BLACKCAT"
        assert dumped["overall_confidence"]["stix_confidence"] == 75
        assert len(dumped["evidence_links"]) == 1
        assert dumped["linked_investigation"] == "inv-001"
        assert dumped["version"] == 1
        assert len(dumped["changelog"]) == 1
        assert dumped["tags"] == ["ransomware", "blackcat"]
        assert dumped["distribution_list"] == ["ciso@corp.com"]
        assert dumped["stix_report_ref"] is None
        assert dumped["stix_bundle_json"] is None
        assert dumped["published_at"] is None
        assert dumped["parent_report_id"] is None

    def test_minimal_report(self) -> None:
        domain = Report(
            title="Minimal",
            report_type=ReportType.DAILY_BRIEF,
        )
        schema = ReportSchema.from_domain(domain)
        assert schema.status == "draft"
        assert schema.classification == "amber"
        assert schema.attribution is None
        assert schema.overall_confidence is None
        assert schema.key_findings == []
