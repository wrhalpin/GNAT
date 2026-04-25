# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for analysis domain schemas — round-trip from domain dataclasses."""

from __future__ import annotations

from datetime import datetime, timezone

from gnat.analysis.confidence import (
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.copilot.drafting import DraftResult
from gnat.analysis.copilot.gap_detector import GapRecommendation, GapSeverity
from gnat.analysis.graph import GraphContext
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
from gnat.analysis.timeline import TimelineEvent, TimelineEventType
from gnat.analysis.tlp import TLPLevel
from gnat.schemas.analysis.confidence import ConfidenceScoreSchema
from gnat.schemas.analysis.copilot import DraftResultSchema, GapRecommendationSchema
from gnat.schemas.analysis.graph import GraphContextSchema
from gnat.schemas.analysis.investigation import (
    AnalystNoteSchema,
    HypothesisSchema,
    InvestigationSchema,
    InvestigationScopeSchema,
    InvestigationTaskSchema,
)
from gnat.schemas.analysis.timeline import TimelineEventSchema


class TestConfidenceScoreSchema:
    def test_round_trip(self) -> None:
        domain = ConfidenceScore(
            source_reliability=SourceReliability.B_USUALLY_RELIABLE,
            information_credibility=InformationCredibility.PROBABLY_TRUE,
            stix_confidence=75,
            rationale="Cross-corroborated.",
        )
        schema = ConfidenceScoreSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["source_reliability"] == "B"
        assert dumped["information_credibility"] == 2
        assert dumped["stix_confidence"] == 75
        assert dumped["rationale"] == "Cross-corroborated."

    def test_none_rationale(self) -> None:
        domain = ConfidenceScore.medium()
        schema = ConfidenceScoreSchema.from_domain(domain)
        assert schema.rationale is None


class TestHypothesisSchema:
    def test_round_trip(self) -> None:
        conf = ConfidenceScore.high("Strong evidence.")
        domain = Hypothesis(
            statement="APT28 is responsible.",
            confidence=conf,
            status=HypothesisStatus.SUPPORTED,
            supporting_evidence=["ind-001"],
            refuting_evidence=["ind-002"],
        )
        schema = HypothesisSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["statement"] == "APT28 is responsible."
        assert dumped["status"] == "supported"
        assert dumped["supporting_evidence"] == ["ind-001"]
        assert dumped["refuting_evidence"] == ["ind-002"]
        assert dumped["confidence"]["stix_confidence"] == 75
        assert isinstance(dumped["created_at"], datetime)
        assert isinstance(dumped["updated_at"], datetime)

    def test_no_confidence(self) -> None:
        domain = Hypothesis(statement="Test hypothesis.")
        schema = HypothesisSchema.from_domain(domain)
        assert schema.confidence is None
        assert schema.status == "open"


class TestInvestigationSchema:
    def test_round_trip(self) -> None:
        scope = InvestigationScope(
            target_sectors=["financial"],
            keywords=["ransomware"],
        )
        note = AnalystNote(
            content="Initial triage note.",
            author="analyst@example.com",
        )
        task = InvestigationTask(
            title="Collect EDR telemetry",
            priority=TaskPriority.HIGH,
            status=TaskStatus.TODO,
        )
        hyp = Hypothesis(statement="BLACKCAT involvement.")
        domain = Investigation(
            title="April 2026 Ransomware Triage",
            created_by="analyst@example.com",
            description="Investigating suspected BLACKCAT intrusion.",
            status=InvestigationStatus.IN_PROGRESS,
            classification=TLPLevel.RED,
            scope=scope,
            notes=[note],
            tasks=[task],
            hypothesis=[hyp],
            tags=["ransomware", "critical"],
            indicators=["indicator--abc"],
        )

        schema = InvestigationSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["title"] == "April 2026 Ransomware Triage"
        assert dumped["status"] == "in_progress"
        assert dumped["classification"] == "red"
        assert dumped["created_by"] == "analyst@example.com"
        assert dumped["description"] == "Investigating suspected BLACKCAT intrusion."
        assert dumped["tags"] == ["ransomware", "critical"]
        assert dumped["indicators"] == ["indicator--abc"]
        assert len(dumped["hypothesis"]) == 1
        assert dumped["hypothesis"][0]["statement"] == "BLACKCAT involvement."
        assert len(dumped["notes"]) == 1
        assert dumped["notes"][0]["author"] == "analyst@example.com"
        assert len(dumped["tasks"]) == 1
        assert dumped["tasks"][0]["priority"] == "high"
        assert dumped["scope"]["target_sectors"] == ["financial"]

    def test_minimal_investigation(self) -> None:
        domain = Investigation(title="Minimal", created_by="test")
        schema = InvestigationSchema.from_domain(domain)
        assert schema.status == "open"
        assert schema.classification == "amber"
        assert schema.hypothesis == []
        assert schema.stix_bundle_ref is None


class TestInvestigationScopeSchema:
    def test_round_trip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        domain = InvestigationScope(
            date_range_start=now,
            target_sectors=["healthcare", "financial"],
            ioc_types=["ipv4-addr"],
        )
        schema = InvestigationScopeSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["date_range_start"] == now
        assert dumped["date_range_end"] is None
        assert dumped["target_sectors"] == ["healthcare", "financial"]
        assert dumped["ioc_types"] == ["ipv4-addr"]


class TestAnalystNoteSchema:
    def test_round_trip(self) -> None:
        domain = AnalystNote(
            content="Observed lateral movement.",
            author="analyst@corp.com",
            linked_artifacts=["obs-1", "obs-2"],
        )
        schema = AnalystNoteSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["content"] == "Observed lateral movement."
        assert dumped["author"] == "analyst@corp.com"
        assert dumped["linked_artifacts"] == ["obs-1", "obs-2"]
        assert len(dumped["id"]) > 0


class TestInvestigationTaskSchema:
    def test_round_trip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        domain = InvestigationTask(
            title="Analyze malware sample",
            description="Run in sandbox.",
            status=TaskStatus.IN_PROGRESS,
            priority=TaskPriority.CRITICAL,
            assigned_to="analyst@corp.com",
            due_date=now,
        )
        schema = InvestigationTaskSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["title"] == "Analyze malware sample"
        assert dumped["status"] == "in_progress"
        assert dumped["priority"] == "critical"
        assert dumped["assigned_to"] == "analyst@corp.com"
        assert dumped["due_date"] == now


class TestTimelineEventSchema:
    def test_round_trip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        conf = ConfidenceScore.medium("Approximate timing.")
        domain = TimelineEvent(
            timestamp=now,
            title="Initial access detected",
            event_type=TimelineEventType.ATTACK_PHASE,
            description="Phishing email opened.",
            linked_artifacts=["ind-001"],
            source="xsoar",
            confidence=conf,
        )
        schema = TimelineEventSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["timestamp"] == now
        assert dumped["title"] == "Initial access detected"
        assert dumped["event_type"] == "attack_phase"
        assert dumped["precision"] == "exact"
        assert dumped["description"] == "Phishing email opened."
        assert dumped["linked_artifacts"] == ["ind-001"]
        assert dumped["source"] == "xsoar"
        assert dumped["confidence"]["stix_confidence"] == 50

    def test_no_confidence(self) -> None:
        now = datetime.now(tz=timezone.utc)
        domain = TimelineEvent(timestamp=now, title="Event")
        schema = TimelineEventSchema.from_domain(domain)
        assert schema.confidence is None
        assert schema.event_type == "other"


class TestGraphContextSchema:
    def test_round_trip(self) -> None:
        domain = GraphContext(
            nodes={"n1": {"type": "incident"}},
            edges=[{"src": "n1", "tgt": "n2"}],
            seed_ids=["n1"],
        )
        schema = GraphContextSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["nodes"] == {"n1": {"type": "incident"}}
        assert dumped["edges"] == [{"src": "n1", "tgt": "n2"}]
        assert dumped["seed_ids"] == ["n1"]

    def test_empty(self) -> None:
        domain = GraphContext()
        schema = GraphContextSchema.from_domain(domain)
        assert schema.nodes == {}
        assert schema.edges == []
        assert schema.seed_ids == []


class TestGapRecommendationSchema:
    def test_round_trip(self) -> None:
        domain = GapRecommendation(
            description="No evidence artifacts linked.",
            severity=GapSeverity.CRITICAL,
            suggested_action="Link at least one indicator.",
            rule_id="no-evidence",
        )
        schema = GapRecommendationSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["description"] == "No evidence artifacts linked."
        assert dumped["severity"] == "critical"
        assert dumped["suggested_action"] == "Link at least one indicator."
        assert dumped["rule_id"] == "no-evidence"


class TestDraftResultSchema:
    def test_round_trip(self) -> None:
        domain = DraftResult(
            executive_summary="Summary text.",
            key_findings_narrative="Findings narrative.",
            model="claude-sonnet-4-6",
            prompt_tokens=100,
            completion_tokens=200,
            warnings=["Token limit approached."],
        )
        schema = DraftResultSchema.from_domain(domain)
        dumped = schema.model_dump()

        assert dumped["executive_summary"] == "Summary text."
        assert dumped["key_findings_narrative"] == "Findings narrative."
        assert dumped["model"] == "claude-sonnet-4-6"
        assert dumped["prompt_tokens"] == 100
        assert dumped["completion_tokens"] == 200
        assert dumped["warnings"] == ["Token limit approached."]

    def test_defaults(self) -> None:
        domain = DraftResult(
            executive_summary="s",
            key_findings_narrative="f",
        )
        schema = DraftResultSchema.from_domain(domain)
        assert schema.model == ""
        assert schema.prompt_tokens == 0
        assert schema.warnings == []
