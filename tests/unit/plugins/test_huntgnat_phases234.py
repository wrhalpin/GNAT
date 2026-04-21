# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/plugins/test_huntgnat_phases234.py
================================================

Unit tests for HuntGNAT Phases 2-4:
- Phase 2: Hunt packages, package lifecycle, ATT&CK coverage matrix
- Phase 3: Deployment tracking, drift detection, sighting model
- Phase 4: Validation runs, rule scoring, pass rate
"""

from __future__ import annotations

import pytest

from gnat.plugins.huntgnat.coverage import CoverageAnalyzer
from gnat.plugins.huntgnat.deployment import (
    Deployment,
    DeploymentPlatform,
    DeploymentStatus,
    DriftDetector,
    Sighting,
)
from gnat.plugins.huntgnat.hunt_package import HuntPackage, PackageStatus
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.validation import (
    RuleValidationResult,
    ValidationOutcome,
    ValidationRun,
)

# ===========================================================================
# Phase 2 — Hunt Packages
# ===========================================================================


class TestHuntPackage:
    def test_defaults(self):
        pkg = HuntPackage(name="Test Hunt")
        assert pkg.status == PackageStatus.DRAFT
        assert pkg.id.startswith("grouping--")
        assert pkg.rule_count == 0

    def test_lifecycle_draft_to_active(self):
        pkg = HuntPackage(name="Lifecycle")
        pkg.transition(PackageStatus.PEER_REVIEWED)
        assert pkg.status == PackageStatus.PEER_REVIEWED
        pkg.transition(PackageStatus.ACTIVE)
        assert pkg.status == PackageStatus.ACTIVE

    def test_lifecycle_active_to_retired(self):
        pkg = HuntPackage(name="Retire")
        pkg.transition(PackageStatus.PEER_REVIEWED)
        pkg.transition(PackageStatus.ACTIVE)
        pkg.transition(PackageStatus.RETIRED)
        assert pkg.status == PackageStatus.RETIRED

    def test_retired_is_terminal(self):
        pkg = HuntPackage(name="Terminal")
        pkg.transition(PackageStatus.PEER_REVIEWED)
        pkg.transition(PackageStatus.ACTIVE)
        pkg.transition(PackageStatus.RETIRED)
        with pytest.raises(ValueError, match="invalid transition"):
            pkg.transition(PackageStatus.ACTIVE)

    def test_invalid_transition(self):
        pkg = HuntPackage(name="Invalid")
        with pytest.raises(ValueError, match="invalid transition"):
            pkg.transition(PackageStatus.ACTIVE)

    def test_add_rule(self):
        pkg = HuntPackage(name="With Rules")
        rule = TranslationResult(rule_id="r1", language=RuleLanguage.SIGMA, rule_body="test")
        pkg.add_rule(rule)
        assert pkg.rule_count == 1

    def test_link_technique(self):
        pkg = HuntPackage(name="Techniques")
        pkg.link_technique("T1059.003")
        pkg.link_technique("T1566.001")
        pkg.link_technique("T1059.003")  # dedup
        assert pkg.techniques_covered == ["T1059.003", "T1566.001"]

    def test_coverage_summary(self):
        pkg = HuntPackage(name="Summary")
        pkg.link_technique("T1059.003")
        pkg.add_rule(TranslationResult(language=RuleLanguage.SIGMA, rule_body="x"))
        pkg.add_rule(TranslationResult(language=RuleLanguage.YARA, rule_body="y"))
        summary = pkg.coverage_summary
        assert summary["techniques_covered"] == 1
        assert summary["rules_generated"] == 2
        assert set(summary["languages"]) == {"sigma", "yara"}

    def test_to_dict_from_dict_roundtrip(self):
        pkg = HuntPackage(
            name="Roundtrip",
            narrative="# Hunt for APT28",
            hypothesis_ids=["hypothesis--1"],
            indicator_ids=["indicator--abc"],
            attack_pattern_ids=["attack-pattern--T1059"],
            campaign_id="campaign--test",
            techniques_covered=["T1059.003"],
            tags=["apt28"],
        )
        d = pkg.to_dict()
        pkg2 = HuntPackage.from_dict(d)
        assert pkg2.name == "Roundtrip"
        assert pkg2.narrative == "# Hunt for APT28"
        assert pkg2.campaign_id == "campaign--test"
        assert pkg2.techniques_covered == ["T1059.003"]

    def test_to_dict_has_stix_grouping_type(self):
        pkg = HuntPackage(name="STIX")
        d = pkg.to_dict()
        assert d["type"] == "grouping"
        assert d["context"] == "x-huntgnat-hunt-package"


# ===========================================================================
# Phase 2 — ATT&CK Coverage
# ===========================================================================


class TestCoverageMatrix:
    def test_empty_matrix(self):
        matrix = CoverageAnalyzer.build_matrix([])
        assert matrix.total_techniques == 0
        assert matrix.coverage_pct == 0.0

    def test_single_package_coverage(self):
        pkg = HuntPackage(name="P1")
        pkg.link_technique("T1059.003")
        pkg.link_technique("T1566.001")
        pkg.add_rule(TranslationResult(language=RuleLanguage.SIGMA, rule_body="x"))

        matrix = CoverageAnalyzer.build_matrix([pkg])
        assert matrix.total_techniques == 2
        assert matrix.covered_count == 2
        assert matrix.coverage_pct == 100.0

    def test_coverage_with_all_techniques(self):
        pkg = HuntPackage(name="P1")
        pkg.link_technique("T1059.003")

        all_techs = ["T1059.003", "T1566.001", "T1190"]
        matrix = CoverageAnalyzer.build_matrix([pkg], all_techniques=all_techs)
        assert matrix.total_techniques == 3
        assert matrix.covered_count == 1
        assert len(matrix.gaps) == 2
        assert "T1566.001" in matrix.gaps

    def test_multiple_packages_merge(self):
        p1 = HuntPackage(name="P1")
        p1.link_technique("T1059.003")
        p1.add_rule(TranslationResult(language=RuleLanguage.SIGMA, rule_body="x"))

        p2 = HuntPackage(name="P2")
        p2.link_technique("T1566.001")
        p2.add_rule(TranslationResult(language=RuleLanguage.SURICATA, rule_body="y"))

        matrix = CoverageAnalyzer.build_matrix([p1, p2])
        assert matrix.total_techniques == 2
        assert matrix.covered_count == 2

    def test_find_gaps_by_platform(self):
        pkg = HuntPackage(name="P1")
        pkg.link_technique("T1059.003")
        pkg.add_rule(TranslationResult(language=RuleLanguage.SIGMA, rule_body="x"))

        matrix = CoverageAnalyzer.build_matrix([pkg], all_techniques=["T1059.003", "T1566.001"])
        gaps = CoverageAnalyzer.find_gaps(matrix, platform="suricata")
        assert "T1059.003" in gaps  # covered by sigma but not suricata
        assert "T1566.001" in gaps

    def test_matrix_to_dict(self):
        pkg = HuntPackage(name="P1")
        pkg.link_technique("T1059.003")
        matrix = CoverageAnalyzer.build_matrix([pkg])
        d = matrix.to_dict()
        assert "total_techniques" in d
        assert "coverage_pct" in d
        assert "gaps" in d
        assert "techniques" in d


# ===========================================================================
# Phase 3 — Deployment & Drift
# ===========================================================================


class TestDeployment:
    def test_defaults(self):
        dep = Deployment(rule_id="r1", platform=DeploymentPlatform.SPLUNK)
        assert dep.status == DeploymentStatus.DEPLOYED
        assert dep.platform == DeploymentPlatform.SPLUNK

    def test_roundtrip(self):
        dep = Deployment(
            rule_id="r1",
            platform=DeploymentPlatform.SENTINEL,
            platform_rule_id="sentinel-abc",
            canonical_hash="abc123",
        )
        d = dep.to_dict()
        dep2 = Deployment.from_dict(d)
        assert dep2.rule_id == "r1"
        assert dep2.platform == DeploymentPlatform.SENTINEL
        assert dep2.canonical_hash == "abc123"

    def test_platform_enum(self):
        assert DeploymentPlatform("splunk") == DeploymentPlatform.SPLUNK
        assert DeploymentPlatform("sentinel") == DeploymentPlatform.SENTINEL
        assert DeploymentPlatform("crowdstrike") == DeploymentPlatform.CROWDSTRIKE
        assert DeploymentPlatform("elastic") == DeploymentPlatform.ELASTIC


class TestDriftDetector:
    def test_no_drift_when_hashes_match(self):
        dep = Deployment(
            rule_id="r1",
            canonical_hash="abc",
        )
        # Fake: set canonical_hash to match what we'll provide
        import hashlib

        body = "alert dns $HOME_NET any -> any any (msg:test; sid:1;)"
        dep.canonical_hash = hashlib.sha256(body.encode()).hexdigest()

        event = DriftDetector.check(dep, body)
        assert event is None
        assert dep.status == DeploymentStatus.DEPLOYED

    def test_drift_detected(self):
        dep = Deployment(
            rule_id="r1",
            canonical_hash="original_hash_that_wont_match",
        )
        event = DriftDetector.check(dep, "modified rule body on platform")
        assert event is not None
        assert event.rule_id == "r1"
        assert dep.status == DeploymentStatus.DRIFTED

    def test_drift_event_has_both_hashes(self):
        dep = Deployment(rule_id="r1", canonical_hash="aaa")
        event = DriftDetector.check(dep, "changed")
        assert event.canonical_hash == "aaa"
        assert len(event.remote_hash) == 64  # SHA-256 hex

    def test_reconciled_timestamp_updated(self):
        dep = Deployment(rule_id="r1", canonical_hash="aaa")
        assert dep.last_reconciled_at is None
        DriftDetector.check(dep, "anything")
        assert dep.last_reconciled_at is not None


class TestSighting:
    def test_defaults(self):
        s = Sighting(sighting_of_ref="indicator--abc")
        assert s.id.startswith("sighting--")
        assert s.count == 1

    def test_to_dict(self):
        s = Sighting(
            sighting_of_ref="indicator--abc",
            where_sighted_refs=["identity--splunk"],
            count=5,
            deployment_id="dep-123",
        )
        d = s.to_dict()
        assert d["type"] == "sighting"
        assert d["count"] == 5
        assert d["x_gnat_deployment_id"] == "dep-123"


# ===========================================================================
# Phase 4 — Validation
# ===========================================================================


class TestValidationRun:
    def test_defaults(self):
        run = ValidationRun(package_id="pkg-1")
        assert run.status == "running"
        assert run.total == 0
        assert run.pass_rate == 0.0

    def test_add_results_and_score(self):
        run = ValidationRun(package_id="pkg-1")
        run.add_result(
            RuleValidationResult(
                rule_id="r1",
                technique_id="T1059.003",
                outcome=ValidationOutcome.FIRED,
                duration_seconds=1.2,
            )
        )
        run.add_result(
            RuleValidationResult(
                rule_id="r2",
                technique_id="T1566.001",
                outcome=ValidationOutcome.MISSED,
                duration_seconds=5.0,
            )
        )
        run.add_result(
            RuleValidationResult(
                rule_id="r3",
                technique_id="T1190",
                outcome=ValidationOutcome.FIRED,
                duration_seconds=0.8,
            )
        )
        assert run.total == 3
        assert run.fired_count == 2
        assert run.missed_count == 1
        assert run.pass_rate == pytest.approx(66.7, abs=0.1)

    def test_complete(self):
        run = ValidationRun(package_id="pkg-1")
        run.complete()
        assert run.status == "completed"
        assert run.finished_at is not None

    def test_roundtrip(self):
        run = ValidationRun(
            package_id="pkg-1",
            target_hosts=["lab-host-1"],
            executed_by="analyst",
        )
        run.add_result(
            RuleValidationResult(
                rule_id="r1",
                technique_id="T1059.003",
                outcome=ValidationOutcome.FIRED,
            )
        )
        run.complete()
        d = run.to_dict()
        run2 = ValidationRun.from_dict(d)
        assert run2.package_id == "pkg-1"
        assert run2.status == "completed"
        assert len(run2.results) == 1
        assert run2.results[0].outcome == ValidationOutcome.FIRED

    def test_all_outcomes(self):
        for outcome in ValidationOutcome:
            r = RuleValidationResult(outcome=outcome)
            assert r.outcome == outcome
            d = r.to_dict()
            r2 = RuleValidationResult.from_dict(d)
            assert r2.outcome == outcome
