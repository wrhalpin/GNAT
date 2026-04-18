# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_attribution_hypothesis.py
======================================================

Unit tests for the attribution hypothesis engine and actor profiles
(Phase 2 of the attribution & campaign tracking extension).
"""

from __future__ import annotations

import pytest

from gnat.analysis.attribution.actor_profile import (
    ActorAlias,
    ActorProfile,
    InfrastructurePattern,
    TargetingEvent,
    TechniqueCapability,
)
from gnat.analysis.attribution.hypothesis import (
    AI_CONFIDENCE_CEILING,
    AttributionEngine,
    AttributionEvidence,
    AttributionHypothesis,
    ConfidenceSnapshot,
)
from gnat.analysis.investigations.models import HypothesisStatus

# ===========================================================================
# Attribution Hypothesis
# ===========================================================================


class TestAttributionHypothesis:
    def test_defaults(self):
        h = AttributionHypothesis(campaign_id="c1", threat_actor_id="ta1")
        assert h.status == HypothesisStatus.OPEN
        assert h.stix_confidence == 0
        assert h.source == "analyst"

    def test_confidence_from_evidence_weights(self):
        h = AttributionHypothesis(
            supporting_evidence=[
                AttributionEvidence(evidence_type="ttp", description="x", weight=40),
                AttributionEvidence(evidence_type="infra", description="y", weight=30),
            ],
            contradicting_evidence=[
                AttributionEvidence(evidence_type="timing", description="z", weight=10),
            ],
        )
        assert h.stix_confidence == 60  # 40+30-10

    def test_confidence_clamped_to_0_100(self):
        h = AttributionHypothesis(
            contradicting_evidence=[
                AttributionEvidence(evidence_type="x", description="x", weight=200),
            ],
        )
        assert h.stix_confidence == 0

    def test_ai_confidence_ceiling(self):
        h = AttributionHypothesis(
            source="ai_copilot",
            supporting_evidence=[
                AttributionEvidence(evidence_type="auto", description="x", weight=90),
            ],
        )
        assert h.stix_confidence == AI_CONFIDENCE_CEILING

    def test_confidence_score_property(self):
        h = AttributionHypothesis(
            supporting_evidence=[
                AttributionEvidence(evidence_type="x", description="x", weight=75),
            ],
        )
        score = h.confidence_score
        assert score.stix_confidence == 75
        assert score.band.value == "HIGH"

    def test_to_dict_from_dict_roundtrip(self):
        h = AttributionHypothesis(
            campaign_id="campaign--test",
            threat_actor_id="threat-actor--apt28",
            threat_actor_name="APT28",
            rationale="TTP overlap",
            source="analyst",
            supporting_evidence=[
                AttributionEvidence(evidence_type="ttp", description="Sofacy", weight=40),
            ],
        )
        d = h.to_dict()
        h2 = AttributionHypothesis.from_dict(d)
        assert h2.campaign_id == "campaign--test"
        assert h2.threat_actor_name == "APT28"
        assert len(h2.supporting_evidence) == 1
        assert h2.supporting_evidence[0].weight == 40


class TestAttributionEvidence:
    def test_roundtrip(self):
        e = AttributionEvidence(
            evidence_type="code_similarity",
            description="85% overlap with known APT28 loader",
            artifact_ids=["malware--abc"],
            weight=35,
            source="sandbox",
        )
        d = e.to_dict()
        e2 = AttributionEvidence.from_dict(d)
        assert e2.evidence_type == "code_similarity"
        assert e2.weight == 35
        assert e2.artifact_ids == ["malware--abc"]


class TestConfidenceSnapshot:
    def test_roundtrip(self):
        s = ConfidenceSnapshot(
            timestamp=AttributionHypothesis().created_at,
            stix_confidence=75,
            reason="added ttp evidence",
        )
        d = s.to_dict()
        s2 = ConfidenceSnapshot.from_dict(d)
        assert s2.stix_confidence == 75
        assert s2.reason == "added ttp evidence"


# ===========================================================================
# Attribution Engine
# ===========================================================================


class TestAttributionEngine:
    def test_propose_creates_hypothesis(self):
        engine = AttributionEngine()
        h = engine.propose(
            campaign_id="campaign--1",
            threat_actor_id="threat-actor--apt28",
            rationale="TTP match",
        )
        assert h.status == HypothesisStatus.OPEN
        assert len(h.confidence_history) == 1
        assert h.confidence_history[0].reason == "initial proposal"

    def test_propose_with_evidence(self):
        engine = AttributionEngine()
        h = engine.propose(
            campaign_id="campaign--1",
            threat_actor_id="threat-actor--apt28",
            evidence=[
                AttributionEvidence(evidence_type="ttp", description="Sofacy", weight=40),
            ],
        )
        assert h.stix_confidence == 40

    def test_add_supporting_evidence(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        engine.add_supporting_evidence(
            h,
            AttributionEvidence(evidence_type="infra", description="shared C2", weight=50),
        )
        assert h.stix_confidence == 50
        assert len(h.confidence_history) == 2

    def test_add_contradicting_evidence(self):
        engine = AttributionEngine()
        h = engine.propose(
            "c1", "ta1",
            evidence=[AttributionEvidence(evidence_type="x", description="x", weight=60)],
        )
        engine.add_contradicting_evidence(
            h,
            AttributionEvidence(evidence_type="timing", description="timezone mismatch", weight=20),
        )
        assert h.stix_confidence == 40  # 60 - 20

    def test_resolve_supported(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        engine.resolve(h, HypothesisStatus.SUPPORTED)
        assert h.status == HypothesisStatus.SUPPORTED
        assert h.resolved_at is not None
        assert h.resolved_by == "analyst"

    def test_resolve_refuted(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        engine.resolve(h, HypothesisStatus.REFUTED, resolved_by="senior_analyst")
        assert h.status == HypothesisStatus.REFUTED
        assert h.resolved_by == "senior_analyst"

    def test_resolve_already_resolved_raises(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        engine.resolve(h, HypothesisStatus.SUPPORTED)
        with pytest.raises(ValueError, match="already resolved"):
            engine.resolve(h, HypothesisStatus.REFUTED)

    def test_resolve_to_open_raises(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        with pytest.raises(ValueError, match="cannot resolve to OPEN"):
            engine.resolve(h, HypothesisStatus.OPEN)

    def test_pick_winner(self):
        engine = AttributionEngine()
        h1 = engine.propose(
            "c1", "ta1",
            evidence=[AttributionEvidence(evidence_type="x", description="x", weight=70)],
        )
        h2 = engine.propose(
            "c1", "ta2",
            evidence=[AttributionEvidence(evidence_type="x", description="x", weight=40)],
        )
        engine.resolve(h1, HypothesisStatus.SUPPORTED)
        engine.resolve(h2, HypothesisStatus.SUPPORTED)
        winner = engine.pick_winner([h1, h2])
        assert winner is h1

    def test_pick_winner_no_supported(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        assert engine.pick_winner([h]) is None

    def test_confidence_history_tracks_changes(self):
        engine = AttributionEngine()
        h = engine.propose("c1", "ta1")
        engine.add_supporting_evidence(
            h, AttributionEvidence(evidence_type="a", description="a", weight=30),
        )
        engine.add_supporting_evidence(
            h, AttributionEvidence(evidence_type="b", description="b", weight=20),
        )
        engine.resolve(h, HypothesisStatus.SUPPORTED)
        assert len(h.confidence_history) == 4  # proposal + 2 evidence + resolve
        assert h.confidence_history[-1].reason.startswith("resolved as supported")


# ===========================================================================
# Actor Profile
# ===========================================================================


class TestActorProfile:
    def test_defaults(self):
        p = ActorProfile(name="Test Actor")
        assert p.id.startswith("threat-actor--")
        assert p.sophistication_level == "intermediate"
        assert p.capabilities == []
        assert p.target_sectors == []

    def test_add_alias_dedup(self):
        p = ActorProfile(name="SANDWORM")
        p.add_alias("Voodoo Bear", source="CrowdStrike", confidence=80)
        p.add_alias("voodoo bear", source="Mandiant", confidence=90)
        assert len(p.aliases) == 1
        assert p.aliases[0].confidence == 90  # upgraded

    def test_add_alias_different(self):
        p = ActorProfile(name="SANDWORM")
        p.add_alias("Voodoo Bear", source="CrowdStrike")
        p.add_alias("Electrum", source="Dragos")
        assert len(p.aliases) == 2

    def test_update_capability_new(self):
        p = ActorProfile(name="APT28")
        p.update_capability("T1059.003", tactic_id="TA0002", proficiency="expert")
        assert len(p.capabilities) == 1
        assert p.capabilities[0].proficiency == "expert"

    def test_update_capability_upgrade(self):
        p = ActorProfile(name="APT28")
        p.update_capability("T1059.003", proficiency="observed", confidence=40)
        p.update_capability("T1059.003", proficiency="expert", confidence=80)
        assert len(p.capabilities) == 1
        assert p.capabilities[0].proficiency == "expert"
        assert p.capabilities[0].confidence == 80

    def test_record_targeting(self):
        p = ActorProfile(name="APT28")
        p.record_targeting("financial", geography="US", campaign_id="c1")
        p.record_targeting("energy", geography="UA")
        assert len(p.targeting_history) == 2
        assert set(p.target_sectors) == {"financial", "energy"}
        assert set(p.target_geographies) == {"US", "UA"}

    def test_ttp_overlap_identical(self):
        p1 = ActorProfile(name="A")
        p2 = ActorProfile(name="B")
        for p in (p1, p2):
            p.update_capability("T1059.003")
            p.update_capability("T1566.001")
        assert p1.ttp_overlap(p2) == 1.0

    def test_ttp_overlap_disjoint(self):
        p1 = ActorProfile(name="A")
        p2 = ActorProfile(name="B")
        p1.update_capability("T1059.003")
        p2.update_capability("T1566.001")
        assert p1.ttp_overlap(p2) == 0.0

    def test_ttp_overlap_partial(self):
        p1 = ActorProfile(name="A")
        p2 = ActorProfile(name="B")
        p1.update_capability("T1059.003")
        p1.update_capability("T1566.001")
        p2.update_capability("T1059.003")
        assert p1.ttp_overlap(p2) == pytest.approx(1 / 2)

    def test_ttp_overlap_both_empty(self):
        p1 = ActorProfile(name="A")
        p2 = ActorProfile(name="B")
        assert p1.ttp_overlap(p2) == 0.0

    def test_to_dict_from_dict_roundtrip(self):
        p = ActorProfile(
            name="SANDWORM",
            threat_actor_types=["nation-state"],
            mitre_group_id="G0034",
            sophistication_level="expert",
        )
        p.add_alias("Voodoo Bear", source="CrowdStrike", confidence=80)
        p.update_capability("T1059.003", tactic_id="TA0002", proficiency="expert")
        p.record_targeting("energy", geography="UA")
        p.preferred_infrastructure.append(
            InfrastructurePattern(pattern_type="c2_framework", value="Cobalt Strike", frequency=5)
        )
        d = p.to_dict()
        p2 = ActorProfile.from_dict(d)
        assert p2.name == "SANDWORM"
        assert p2.mitre_group_id == "G0034"
        assert len(p2.aliases) == 1
        assert len(p2.capabilities) == 1
        assert len(p2.targeting_history) == 1
        assert len(p2.preferred_infrastructure) == 1
        assert p2.preferred_infrastructure[0].value == "Cobalt Strike"


class TestSupportingTypes:
    def test_actor_alias_roundtrip(self):
        a = ActorAlias(alias="Fancy Bear", source="CrowdStrike", confidence=85)
        d = a.to_dict()
        a2 = ActorAlias.from_dict(d)
        assert a2.alias == "Fancy Bear"
        assert a2.confidence == 85

    def test_technique_capability_roundtrip(self):
        t = TechniqueCapability(
            technique_id="T1059.003", tactic_id="TA0002", proficiency="expert"
        )
        d = t.to_dict()
        t2 = TechniqueCapability.from_dict(d)
        assert t2.technique_id == "T1059.003"

    def test_targeting_event_roundtrip(self):
        e = TargetingEvent(sector="energy", geography="UA", campaign_id="c1")
        d = e.to_dict()
        e2 = TargetingEvent.from_dict(d)
        assert e2.sector == "energy"

    def test_infrastructure_pattern_roundtrip(self):
        p = InfrastructurePattern(
            pattern_type="hosting_provider", value="BulletProofHosting", frequency=3
        )
        d = p.to_dict()
        p2 = InfrastructurePattern.from_dict(d)
        assert p2.value == "BulletProofHosting"
        assert p2.frequency == 3
