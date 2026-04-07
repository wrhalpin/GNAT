# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for gnat.reporting."""

import json

import pytest

from gnat.analysis.confidence import ConfidenceScore
from gnat.analysis.tlp import TLPLevel
from gnat.reporting import (
    Attribution,
    EvidenceLink,
    EvidenceLinkType,
    Finding,
    Report,
    ReportError,
    ReportSection,
    ReportService,
    ReportStatus,
    ReportStore,
    ReportType,
    report_to_stix_bundle,
)


@pytest.fixture
def store():
    s = ReportStore("sqlite:///:memory:")
    s.create_all()
    return s


@pytest.fixture
def service(store):
    return ReportService(store)


@pytest.fixture
def draft(service):
    return service.create(
        title       = "BLACKCAT Ransomware — April 2026",
        report_type = ReportType.INCIDENT_REPORT,
        authors     = ["analyst@example.com"],
        tags        = ["ransomware", "blackcat"],
    )


# ── Report model ──────────────────────────────────────────────────────────────

class TestReportModel:
    def test_defaults(self):
        r = Report(title="Test", report_type=ReportType.INCIDENT_REPORT)
        assert r.status  == ReportStatus.DRAFT
        assert r.version == 1
        assert r.key_findings   == []
        assert r.evidence_links == []

    def test_is_published(self):
        r = Report(title="T", report_type=ReportType.DAILY_BRIEF)
        assert r.is_published is False
        r.status = ReportStatus.PUBLISHED
        assert r.is_published is True

    def test_can_transition_valid(self):
        r = Report(title="T", report_type=ReportType.INCIDENT_REPORT)
        assert r.can_transition_to(ReportStatus.REVIEW)   is True
        assert r.can_transition_to(ReportStatus.ARCHIVED) is True

    def test_can_transition_invalid(self):
        r = Report(title="T", report_type=ReportType.INCIDENT_REPORT)
        assert r.can_transition_to(ReportStatus.APPROVED)  is False
        assert r.can_transition_to(ReportStatus.PUBLISHED) is False

    def test_published_is_terminal_except_archive(self):
        r = Report(title="T", report_type=ReportType.INCIDENT_REPORT)
        r.status = ReportStatus.PUBLISHED
        assert r.can_transition_to(ReportStatus.ARCHIVED) is True
        assert r.can_transition_to(ReportStatus.DRAFT)    is False
        assert r.can_transition_to(ReportStatus.REVIEW)   is False

    def test_roundtrip_serialization(self):
        r = Report(
            title          = "Test Report",
            report_type    = ReportType.CAMPAIGN_ANALYSIS,
            classification = TLPLevel.RED,
            authors        = ["analyst@example.com"],
        )
        r.key_findings.append(Finding(
            statement        = "Key finding 1",
            confidence       = ConfidenceScore.high(),
            mitre_techniques = ["T1059.003"],
        ))
        r.evidence_links.append(EvidenceLink(
            statement       = "Evidence for finding 1",
            artifact_type   = "indicator",
            artifact_id     = "indicator--abc",
            artifact_source = "threatq",
        ))

        data     = r.to_dict()
        restored = Report.from_dict(data)

        assert restored.id              == r.id
        assert restored.title           == r.title
        assert restored.classification  == r.classification
        assert len(restored.key_findings)   == 1
        assert len(restored.evidence_links) == 1
        assert restored.key_findings[0].confidence.stix_confidence == 75
        assert restored.key_findings[0].mitre_techniques == ["T1059.003"]

    def test_ordered_sections(self):
        r = Report(title="T", report_type=ReportType.INCIDENT_REPORT)
        r.body_sections = [
            ReportSection(title="C", order=30),
            ReportSection(title="A", order=10),
            ReportSection(title="B", order=20),
        ]
        ordered = r.ordered_sections
        assert [s.title for s in ordered] == ["A", "B", "C"]


# ── EvidenceLink ──────────────────────────────────────────────────────────────

class TestEvidenceLink:
    def test_roundtrip(self):
        link = EvidenceLink(
            statement       = "IP observed in C2 communications.",
            artifact_type   = "indicator",
            artifact_id     = "indicator--abc-123",
            artifact_source = "threatq",
            link_type       = EvidenceLinkType.SUPPORTS,
            confidence      = ConfidenceScore.medium(),
        )
        data     = link.to_dict()
        restored = EvidenceLink.from_dict(data)

        assert restored.id              == link.id
        assert restored.statement       == link.statement
        assert restored.artifact_source == link.artifact_source
        assert restored.link_type       == link.link_type
        assert restored.confidence.stix_confidence == 50


# ── Attribution ───────────────────────────────────────────────────────────────

class TestAttribution:
    def test_roundtrip(self):
        attr = Attribution(
            threat_actor_name = "BLACKCAT",
            confidence        = ConfidenceScore.high(),
            rationale         = "Shared C2 infra with March 2026 campaign.",
            mitre_group_id    = "G0096",
        )
        data     = attr.to_dict()
        restored = Attribution.from_dict(data)

        assert restored.threat_actor_name == "BLACKCAT"
        assert restored.mitre_group_id    == "G0096"
        assert restored.confidence.band.value == "HIGH"


# ── ReportService lifecycle ───────────────────────────────────────────────────

class TestReportServiceLifecycle:
    def test_create_and_get(self, service, draft):
        r = service.get(draft.id)
        assert r.title  == "BLACKCAT Ransomware — April 2026"
        assert r.status == ReportStatus.DRAFT
        assert "ransomware" in r.tags

    def test_get_not_found(self, service):
        with pytest.raises(ReportError):
            service.get("nonexistent")

    def test_submit_for_review(self, service, draft):
        r = service.submit_for_review(draft.id)
        assert r.status == ReportStatus.REVIEW

    def test_reject_to_draft(self, service, draft):
        service.submit_for_review(draft.id)
        r = service.reject_to_draft(draft.id, reviewer="manager", reason="Needs more evidence.")
        assert r.status == ReportStatus.DRAFT
        assert len(r.changelog) == 2  # submit + reject

    def test_approve(self, service, draft):
        service.submit_for_review(draft.id)
        r = service.approve(draft.id, reviewer="manager@example.com")
        assert r.status == ReportStatus.APPROVED
        assert "manager@example.com" in r.reviewers

    def test_full_lifecycle_to_published(self, service, draft):
        service.update_summary(draft.id, "Executive summary text.")
        service.add_finding(draft.id, "Finding 1", confidence=ConfidenceScore.high())
        service.add_evidence_link(
            draft.id,
            statement       = "IP linked to C2.",
            artifact_type   = "indicator",
            artifact_id     = "indicator--abc",
            artifact_source = "threatq",
        )
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager@example.com")
        published = service.publish(draft.id, changed_by="manager@example.com")

        assert published.status         == ReportStatus.PUBLISHED
        assert published.published_at   is not None
        assert published.stix_report_ref is not None
        assert published.stix_bundle_json is not None

    def test_cannot_publish_from_draft(self, service, draft):
        with pytest.raises(ReportError, match="must be APPROVED"):
            service.publish(draft.id, changed_by="analyst")

    def test_content_immutable_after_publish(self, service, draft):
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager")
        service.publish(draft.id, changed_by="manager")

        with pytest.raises(ReportError, match="immutable"):
            service.update_summary(draft.id, "New summary.")
        with pytest.raises(ReportError, match="immutable"):
            service.add_finding(draft.id, "New finding.")

    def test_archive(self, service, draft):
        r = service.archive(draft.id, changed_by="manager", reason="Superseded.")
        assert r.status == ReportStatus.ARCHIVED

    def test_invalid_transition_raises(self, service, draft):
        with pytest.raises(ReportError, match="Cannot approve"):
            service.approve(draft.id, reviewer="manager")  # DRAFT → APPROVED is invalid

    def test_add_section(self, service, draft):
        section = service.add_section(draft.id, title="Technical Analysis", content="Details here.")
        assert section.title == "Technical Analysis"

        r = service.get(draft.id)
        assert len(r.body_sections) == 1

    def test_section_auto_order(self, service, draft):
        service.add_section(draft.id, title="A", order=10)
        s2 = service.add_section(draft.id, title="B")  # auto order
        assert s2.order == 20

    def test_set_attribution(self, service, draft):
        service.set_attribution(
            draft.id,
            threat_actor_name = "BLACKCAT",
            confidence        = ConfidenceScore.medium(),
            rationale         = "Shared infrastructure.",
            mitre_group_id    = "G0096",
        )
        r = service.get(draft.id)
        assert r.attribution is not None
        assert r.attribution.mitre_group_id == "G0096"

    def test_add_recommendation(self, service, draft):
        service.add_recommendation(draft.id, "Patch CVE-2026-1234 within 24 hours.")
        r = service.get(draft.id)
        assert len(r.recommendations) == 1

    def test_add_tags_deduplicates(self, service, draft):
        service.add_tags(draft.id, ["ransomware", "critical"])
        r = service.get(draft.id)
        assert r.tags.count("ransomware") == 1
        assert "critical" in r.tags

    def test_delete(self, service, draft):
        service.delete(draft.id)
        with pytest.raises(ReportError):
            service.get(draft.id)

    def test_list_by_status(self, service):
        service.create(title="R1", report_type=ReportType.DAILY_BRIEF)
        r2 = service.create(title="R2", report_type=ReportType.DAILY_BRIEF)
        service.submit_for_review(r2.id)

        drafts  = service.list(status=ReportStatus.DRAFT)
        reviews = service.list(status=ReportStatus.REVIEW)
        assert len(drafts)  == 1
        assert len(reviews) == 1

    def test_create_revision(self, service, draft):
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="mgr")
        published = service.publish(draft.id, changed_by="mgr")

        revision = service.create_revision(published.id, author="analyst2@example.com")
        assert revision.status           == ReportStatus.DRAFT
        assert revision.version          == 2
        assert revision.parent_report_id == published.id
        assert revision.stix_report_ref  is None
        assert "analyst2@example.com" in revision.authors

    def test_create_revision_requires_published(self, service, draft):
        with pytest.raises(ReportError, match="PUBLISHED"):
            service.create_revision(draft.id, author="analyst")

    def test_summary(self, service, draft):
        service.add_finding(draft.id, "Finding 1")
        service.add_section(draft.id, title="Section A")

        s = service.summary(draft.id)
        assert s["finding_count"]  == 1
        assert s["section_count"]  == 1
        assert s["status"]         == "draft"
        assert "classification"    in s


# ── STIX export ───────────────────────────────────────────────────────────────

class TestStixExport:
    def test_bundle_structure(self, service, draft):
        service.add_finding(draft.id, "Key finding.", confidence=ConfidenceScore.high())
        service.add_evidence_link(
            draft.id,
            statement       = "Evidence.",
            artifact_type   = "indicator",
            artifact_id     = "indicator--abc-123",
            artifact_source = "threatq",
        )
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager")
        published = service.publish(draft.id, changed_by="manager")

        bundle = json.loads(published.stix_bundle_json)
        assert bundle["type"]         == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) >= 2  # report SDO + identity

        types = {obj["type"] for obj in bundle["objects"]}
        assert "report"   in types
        assert "identity" in types

    def test_report_sdo_fields(self, service, draft):
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager")
        published = service.publish(draft.id, changed_by="manager")

        bundle   = json.loads(published.stix_bundle_json)
        report_obj = next(o for o in bundle["objects"] if o["type"] == "report")

        assert report_obj["name"]            == draft.title
        assert report_obj["spec_version"]    == "2.1"
        assert "object_refs"                 in report_obj
        assert "object_marking_refs"         in report_obj
        assert report_obj["x_gnat_report_id"] == published.id

    def test_attribution_in_bundle(self, service, draft):
        service.set_attribution(
            draft.id,
            threat_actor_name = "BLACKCAT",
            confidence        = ConfidenceScore.high(),
            rationale         = "Infrastructure overlap.",
            mitre_group_id    = "G0096",
        )
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager")
        published = service.publish(draft.id, changed_by="manager")

        bundle = json.loads(published.stix_bundle_json)
        types  = {obj["type"] for obj in bundle["objects"]}
        assert "threat-actor" in types
        assert "relationship"  in types

        ta = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
        assert ta["name"] == "BLACKCAT"
        assert ta.get("x_mitre_group_id") == "G0096"

    def test_standalone_stix_export(self):
        """report_to_stix_bundle can be called directly without going through service."""
        r = Report(
            title       = "Standalone Export Test",
            report_type = ReportType.FINISHED_INTELLIGENCE,
            authors     = ["analyst"],
        )
        bundle = report_to_stix_bundle(r)
        assert bundle["type"] == "bundle"
        obj_types = {o["type"] for o in bundle["objects"]}
        assert "report" in obj_types

    def test_stix_report_ref_matches_bundle(self, service, draft):
        service.submit_for_review(draft.id)
        service.approve(draft.id, reviewer="manager")
        published = service.publish(draft.id, changed_by="manager")

        bundle = json.loads(published.stix_bundle_json)
        report_obj = next(o for o in bundle["objects"] if o["type"] == "report")
        assert published.stix_report_ref == report_obj["id"]
