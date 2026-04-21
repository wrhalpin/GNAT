# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_diamond_killchain_infra.py
======================================================

Unit tests for Phase 3 analytical models: Diamond Model, kill-chain
progression tracking, and infrastructure role classification.
"""

from __future__ import annotations

import pytest

from gnat.analysis.attribution.diamond import DiamondAnalyzer, DiamondVertex
from gnat.analysis.attribution.infrastructure import (
    InfrastructureClassifier,
    InfrastructureNode,
    InfrastructureRole,
)
from gnat.analysis.attribution.killchain import (
    KILL_CHAIN_ORDER,
    KillChainPhaseEntry,
    KillChainTracker,
)

# ===========================================================================
# Diamond Model
# ===========================================================================


class TestDiamondVertex:
    def test_defaults(self):
        v = DiamondVertex()
        assert v.adversary is None
        assert v.capability == []
        assert v.infrastructure == []
        assert v.victim == []

    def test_roundtrip(self):
        v = DiamondVertex(
            adversary="threat-actor--apt28",
            capability=["malware--sofacy", "attack-pattern--T1566"],
            infrastructure=["indicator--c2-ip"],
            victim=["identity--target-org"],
            confidence=75,
            phase="TA0001",
            result="success",
        )
        d = v.to_dict()
        v2 = DiamondVertex.from_dict(d)
        assert v2.adversary == "threat-actor--apt28"
        assert len(v2.capability) == 2
        assert v2.phase == "TA0001"
        assert v2.result == "success"
        assert v2.confidence == 75


class TestDiamondAnalyzer:
    def test_build_vertex(self):
        v = DiamondAnalyzer.build_vertex(
            adversary="threat-actor--apt28",
            capability=["malware--sofacy"],
            infrastructure=["indicator--c2"],
            victim=["identity--target"],
            confidence=80,
            phase="TA0011",
        )
        assert v.adversary == "threat-actor--apt28"
        assert v.timestamp is not None

    def test_find_pivot_points_shared_infra(self):
        v1 = DiamondVertex(infrastructure=["ip-1", "ip-2"])
        v2 = DiamondVertex(infrastructure=["ip-2", "ip-3"])
        v3 = DiamondVertex(infrastructure=["ip-3", "ip-4"])
        pivots = DiamondAnalyzer.find_pivot_points([v1, v2, v3])
        assert "ip-2" in pivots
        assert "ip-3" in pivots
        assert "ip-1" not in pivots

    def test_find_pivot_points_no_overlap(self):
        v1 = DiamondVertex(infrastructure=["ip-1"])
        v2 = DiamondVertex(infrastructure=["ip-2"])
        assert DiamondAnalyzer.find_pivot_points([v1, v2]) == []

    def test_vertices_by_adversary(self):
        v1 = DiamondVertex(adversary="apt28")
        v2 = DiamondVertex(adversary="apt29")
        v3 = DiamondVertex(adversary="apt28")
        groups = DiamondAnalyzer.vertices_by_adversary([v1, v2, v3])
        assert len(groups["apt28"]) == 2
        assert len(groups["apt29"]) == 1

    def test_vertices_by_phase(self):
        v1 = DiamondVertex(phase="TA0001")
        v2 = DiamondVertex(phase="TA0002")
        v3 = DiamondVertex(phase="TA0001")
        groups = DiamondAnalyzer.vertices_by_phase([v1, v2, v3])
        assert len(groups["TA0001"]) == 2
        assert len(groups["TA0002"]) == 1


# ===========================================================================
# Kill-Chain Tracker
# ===========================================================================


class TestKillChainPhaseEntry:
    def test_roundtrip(self):
        e = KillChainPhaseEntry(
            tactic_id="TA0001",
            tactic_name="initial-access",
            techniques_observed=["T1566.001", "T1190"],
            confidence=75,
        )
        d = e.to_dict()
        e2 = KillChainPhaseEntry.from_dict(d)
        assert e2.tactic_id == "TA0001"
        assert e2.techniques_observed == ["T1566.001", "T1190"]


class TestKillChainProgression:
    def test_coverage_pct(self):
        prog = KillChainTracker.build_progression(
            "campaign-1",
            [("T1566.001", "TA0001"), ("T1059.003", "TA0002"), ("T1053", "TA0003")],
        )
        assert prog.coverage_pct == pytest.approx(3 / 14 * 100, abs=0.5)

    def test_deepest_phase(self):
        prog = KillChainTracker.build_progression(
            "campaign-1",
            [("T1566.001", "TA0001"), ("T1059.003", "TA0002")],
        )
        assert prog.deepest_phase == "TA0002"

    def test_gaps(self):
        prog = KillChainTracker.build_progression(
            "campaign-1",
            [("T1566.001", "TA0001")],
        )
        gaps = prog.gaps
        assert "TA0001" not in gaps
        assert "TA0002" in gaps
        assert len(gaps) == 13

    def test_empty_progression(self):
        prog = KillChainTracker.build_progression("empty", [])
        assert prog.coverage_pct == 0.0
        assert prog.deepest_phase == ""
        assert len(prog.gaps) == 14

    def test_full_coverage(self):
        pairs = [(f"T{i}", tactic) for i, tactic in enumerate(KILL_CHAIN_ORDER)]
        prog = KillChainTracker.build_progression("full", pairs)
        assert prog.coverage_pct == 100.0
        assert prog.gaps == []
        assert prog.deepest_phase == "TA0040"

    def test_to_dict(self):
        prog = KillChainTracker.build_progression(
            "campaign-1",
            [("T1566.001", "TA0001")],
        )
        d = prog.to_dict()
        assert d["campaign_id"] == "campaign-1"
        assert d["coverage_pct"] > 0
        assert isinstance(d["gaps"], list)

    def test_deduplicates_techniques(self):
        prog = KillChainTracker.build_progression(
            "campaign-1",
            [("T1566.001", "TA0001"), ("T1566.001", "TA0001"), ("T1190", "TA0001")],
        )
        phase = next(p for p in prog.phases if p.tactic_id == "TA0001")
        assert phase.techniques_observed == ["T1190", "T1566.001"]


class TestKillChainTracker:
    def test_compare_identical(self):
        pairs = [("T1566.001", "TA0001"), ("T1059.003", "TA0002")]
        a = KillChainTracker.build_progression("a", pairs)
        b = KillChainTracker.build_progression("b", pairs)
        assert KillChainTracker.compare(a, b) == 1.0

    def test_compare_disjoint(self):
        a = KillChainTracker.build_progression("a", [("T1566", "TA0001")])
        b = KillChainTracker.build_progression("b", [("T1059", "TA0002")])
        assert KillChainTracker.compare(a, b) == 0.0

    def test_compare_partial(self):
        a = KillChainTracker.build_progression("a", [("T1566", "TA0001"), ("T1059", "TA0002")])
        b = KillChainTracker.build_progression("b", [("T1566", "TA0001")])
        assert KillChainTracker.compare(a, b) == pytest.approx(0.5)

    def test_compare_both_empty(self):
        a = KillChainTracker.build_progression("a", [])
        b = KillChainTracker.build_progression("b", [])
        assert KillChainTracker.compare(a, b) == 0.0


# ===========================================================================
# Infrastructure Classifier
# ===========================================================================


class TestInfrastructureNode:
    def test_defaults(self):
        n = InfrastructureNode(ioc_type="ipv4-addr", ioc_value="1.2.3.4")
        assert n.role == InfrastructureRole.UNKNOWN
        assert n.auto_classified is False

    def test_roundtrip(self):
        n = InfrastructureNode(
            indicator_id="indicator--abc",
            ioc_type="domain-name",
            ioc_value="evil.com",
            role=InfrastructureRole.C2,
            role_confidence=80,
            campaigns=["campaign--1", "campaign--2"],
            hosting_provider="BulletProof",
            asn="AS12345",
        )
        d = n.to_dict()
        n2 = InfrastructureNode.from_dict(d)
        assert n2.role == InfrastructureRole.C2
        assert n2.campaigns == ["campaign--1", "campaign--2"]
        assert n2.hosting_provider == "BulletProof"


class TestInfrastructureClassifier:
    def test_classify_by_infrastructure_types_c2(self):
        role = InfrastructureClassifier.classify(
            "ipv4-addr",
            "1.2.3.4",
            infrastructure_types=["command-and-control"],
        )
        assert role == InfrastructureRole.C2

    def test_classify_by_infrastructure_types_staging(self):
        role = InfrastructureClassifier.classify(
            "domain-name",
            "stage.evil.com",
            infrastructure_types=["staging"],
        )
        assert role == InfrastructureRole.STAGING

    def test_classify_by_infrastructure_types_phishing(self):
        role = InfrastructureClassifier.classify(
            "domain-name",
            "phish.evil.com",
            infrastructure_types=["phishing"],
        )
        assert role == InfrastructureRole.DELIVERY

    def test_classify_by_kill_chain_c2(self):
        role = InfrastructureClassifier.classify(
            "ipv4-addr",
            "1.2.3.4",
            kill_chain_phases=["TA0011"],
        )
        assert role == InfrastructureRole.C2

    def test_classify_by_kill_chain_exfil(self):
        role = InfrastructureClassifier.classify(
            "ipv4-addr",
            "1.2.3.4",
            kill_chain_phases=["TA0010"],
        )
        assert role == InfrastructureRole.EXFILTRATION

    def test_classify_by_kill_chain_initial_access(self):
        role = InfrastructureClassifier.classify(
            "domain-name",
            "delivery.evil.com",
            kill_chain_phases=["TA0001"],
        )
        assert role == InfrastructureRole.DELIVERY

    def test_classify_by_ports_c2(self):
        role = InfrastructureClassifier.classify(
            "ipv4-addr",
            "1.2.3.4",
            ports=[443, 8443],
        )
        assert role == InfrastructureRole.C2

    def test_classify_unknown_when_no_hints(self):
        role = InfrastructureClassifier.classify("ipv4-addr", "1.2.3.4")
        assert role == InfrastructureRole.UNKNOWN

    def test_infrastructure_types_take_priority(self):
        role = InfrastructureClassifier.classify(
            "ipv4-addr",
            "1.2.3.4",
            infrastructure_types=["exfiltration"],
            kill_chain_phases=["TA0011"],
            ports=[443],
        )
        assert role == InfrastructureRole.EXFILTRATION

    def test_find_shared_infrastructure(self):
        nodes = [
            InfrastructureNode(ioc_value="1.1.1.1", campaigns=["c1", "c2"]),
            InfrastructureNode(ioc_value="2.2.2.2", campaigns=["c1"]),
            InfrastructureNode(ioc_value="3.3.3.3", campaigns=["c2", "c3"]),
        ]
        shared = InfrastructureClassifier.find_shared_infrastructure(nodes)
        assert len(shared) == 2
        values = {n.ioc_value for n in shared}
        assert values == {"1.1.1.1", "3.3.3.3"}

    def test_role_enum_values(self):
        assert InfrastructureRole("c2") == InfrastructureRole.C2
        assert InfrastructureRole("staging") == InfrastructureRole.STAGING
        assert InfrastructureRole("exfiltration") == InfrastructureRole.EXFILTRATION
        assert InfrastructureRole("delivery") == InfrastructureRole.DELIVERY
        assert InfrastructureRole("proxy") == InfrastructureRole.PROXY
        assert InfrastructureRole("unknown") == InfrastructureRole.UNKNOWN
