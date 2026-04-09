"""
tests/unit/test_phase4_reasoning.py
=====================================
Unit tests for Phase 4C — Hypothesis Engine, Negative Evidence, Reasoning Engine.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# STIXHypothesis tests
# ---------------------------------------------------------------------------

class TestSTIXHypothesis:
    def test_create_defaults(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="APT29 behind Q1 campaign", confidence=0.4)
        assert h._properties["statement"] == "APT29 behind Q1 campaign"
        assert h._properties["confidence"] == 0.4
        assert h._properties["status"] == "pending"
        assert h._properties["supporting_evidence"] == []
        assert h._properties["refuting_evidence"] == []
        assert h.id.startswith("x-gnat-hypothesis--")

    def test_invalid_status_raises(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        with pytest.raises(ValueError, match="Invalid hypothesis status"):
            STIXHypothesis(statement="x", confidence=0.5, status="bad-status")

    def test_invalid_confidence_raises(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        with pytest.raises(ValueError, match="confidence must be in"):
            STIXHypothesis(statement="x", confidence=1.5)

    def test_add_supporting_evidence(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.3)
        h.add_supporting_evidence("relationship--abc")
        assert "relationship--abc" in h._properties["supporting_evidence"]
        # Duplicate not added
        h.add_supporting_evidence("relationship--abc")
        assert h._properties["supporting_evidence"].count("relationship--abc") == 1

    def test_add_refuting_evidence(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.3)
        h.add_refuting_evidence("relationship--xyz")
        assert "relationship--xyz" in h._properties["refuting_evidence"]

    def test_update_confidence(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.3)
        h.update_confidence(0.8)
        assert h._properties["confidence"] == 0.8

    def test_update_confidence_invalid(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.3)
        with pytest.raises(ValueError, match="confidence must be in"):
            h.update_confidence(1.1)

    def test_close_confirmed(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.9)
        h.close("confirmed")
        assert h._properties["status"] == "confirmed"

    def test_close_invalid_verdict(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="test", confidence=0.5)
        with pytest.raises(ValueError, match="verdict must be one of"):
            h.close("maybe")

    def test_to_dict_round_trip(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        h = STIXHypothesis(statement="round trip test", confidence=0.6, status="pending")
        h.add_supporting_evidence("rel--1")
        d = h.to_dict()

        assert d["type"] == "x-gnat-hypothesis"
        assert d["statement"] == "round trip test"
        assert d["confidence"] == 0.6
        assert "rel--1" in d["supporting_evidence"]

        h2 = STIXHypothesis.from_dict(d)
        assert h2._properties["statement"] == "round trip test"
        assert h2._properties["confidence"] == 0.6
        assert "rel--1" in h2._properties["supporting_evidence"]


# ---------------------------------------------------------------------------
# NegativeEvidenceRecord tests
# ---------------------------------------------------------------------------

class TestNegativeEvidenceRecord:
    def test_create(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        rec = NegativeEvidenceRecord(
            target_ref="indicator--abc",
            queried_connector="VirusTotalClient",
            ttl_seconds=3600,
        )
        assert rec._properties["target_ref"] == "indicator--abc"
        assert rec._properties["queried_connector"] == "VirusTotalClient"
        assert rec._properties["ttl_seconds"] == 3600
        assert rec.id.startswith("x-gnat-negative-evidence--")

    def test_not_expired_immediately(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        rec = NegativeEvidenceRecord(
            target_ref="indicator--abc",
            queried_connector="TestClient",
            ttl_seconds=3600,
        )
        assert rec.is_expired() is False

    def test_expired_with_past_timestamp(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        rec = NegativeEvidenceRecord(
            target_ref="indicator--abc",
            queried_connector="TestClient",
            ttl_seconds=3600,
            query_timestamp=past,
        )
        assert rec.is_expired() is True

    def test_seconds_remaining_fresh(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        rec = NegativeEvidenceRecord(
            target_ref="indicator--abc",
            queried_connector="TestClient",
            ttl_seconds=3600,
        )
        remaining = rec.seconds_remaining()
        assert remaining > 3590  # Should be close to 3600

    def test_seconds_remaining_expired(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        rec = NegativeEvidenceRecord(
            target_ref="indicator--abc",
            queried_connector="TestClient",
            ttl_seconds=3600,
            query_timestamp=past,
        )
        assert rec.seconds_remaining() == 0.0

    def test_round_trip(self):
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

        rec = NegativeEvidenceRecord(
            target_ref="indicator--xyz",
            queried_connector="CrowdStrikeClient",
            ttl_seconds=7200,
        )
        d = rec.to_dict()
        rec2 = NegativeEvidenceRecord.from_dict(d)
        assert rec2._properties["target_ref"] == "indicator--xyz"
        assert rec2._properties["ttl_seconds"] == 7200


# ---------------------------------------------------------------------------
# HypothesisEngine tests
# ---------------------------------------------------------------------------

class TestHypothesisEngine:
    def _make_engine(self, fixtures=None):
        from gnat.reasoning.hypothesis import HypothesisEngine
        from gnat.search.index import NullSearchIndex

        manager = MagicMock()
        ws = MagicMock()
        ws.objects = {}
        manager.open.return_value = ws

        engine = HypothesisEngine(
            manager=manager,
            workspace_name="test-ws",
            search_index=NullSearchIndex(),
        )
        return engine, ws

    def test_propose_creates_hypothesis(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        engine, ws = self._make_engine()
        h = engine.propose("APT29 is behind Q1 campaign", confidence=0.3)
        assert isinstance(h, STIXHypothesis)
        assert h._properties["statement"] == "APT29 is behind Q1 campaign"
        assert h._properties["confidence"] == 0.3
        assert h._properties["status"] == "pending"
        ws._add_object.assert_called_once()

    def test_propose_with_evidence(self):
        engine, ws = self._make_engine()
        h = engine.propose(
            "Lazarus Group C2",
            initial_evidence=["rel--1", "rel--2"],
            confidence=0.5,
        )
        assert "rel--1" in h._properties["supporting_evidence"]
        assert "rel--2" in h._properties["supporting_evidence"]

    def test_evaluate_no_evidence_unchanged(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        engine, ws = self._make_engine()
        h_obj = STIXHypothesis(statement="test", confidence=0.2)
        ws.objects = {h_obj.id: MagicMock(to_dict=lambda: h_obj.to_dict())}

        h_result = engine.evaluate(h_obj.id)
        # No evidence → stays at initial confidence
        assert h_result._properties["confidence"] == 0.2

    def test_evaluate_missing_hypothesis_raises(self):
        engine, ws = self._make_engine()
        ws.objects = {}

        with pytest.raises(KeyError, match="No hypothesis found"):
            engine.evaluate("x-gnat-hypothesis--nonexistent")

    def test_evaluate_high_support_confirms(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        engine, ws = self._make_engine()
        h_obj = STIXHypothesis(
            statement="confirmed",
            confidence=0.5,
            supporting_evidence=["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
        )
        ws.objects = {h_obj.id: MagicMock(to_dict=lambda: h_obj.to_dict())}

        h_result = engine.evaluate(h_obj.id)
        # High support count → status should be confirmed (confidence ≥ 0.75)
        assert h_result._properties["confidence"] >= 0.75
        assert h_result._properties["status"] == "confirmed"

    def test_close_sets_verdict(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        engine, ws = self._make_engine()
        h_obj = STIXHypothesis(statement="test", confidence=0.4)
        ws.objects = {h_obj.id: MagicMock(to_dict=lambda: h_obj.to_dict())}

        h_result = engine.close(h_obj.id, verdict="refuted")
        assert h_result._properties["status"] == "refuted"

    def test_get_returns_none_for_missing(self):
        engine, ws = self._make_engine()
        ws.objects = {}
        assert engine.get("missing--id") is None

    def test_list_all(self):
        from gnat.stix.sdos.hypothesis import STIXHypothesis

        engine, ws = self._make_engine()
        h1 = STIXHypothesis(statement="h1", confidence=0.3)
        h2 = STIXHypothesis(statement="h2", confidence=0.5)

        class FakeObj:
            stix_type = "x-gnat-hypothesis"
            def to_dict(self): return h1.to_dict()

        ws.objects = {
            h1.id: FakeObj(),
            h2.id: FakeObj(),
        }
        result = engine.list_all()
        assert len(result) == 2


# ---------------------------------------------------------------------------
# ReasoningEngine tests
# ---------------------------------------------------------------------------

class TestReasoningEngine:
    def _make_observable(self, obj_id="indicator--abc", modified_days_ago=1):
        obs = MagicMock()
        obs.id = obj_id
        obs.stix_type = "indicator"
        modified = (datetime.now(timezone.utc) - timedelta(days=modified_days_ago)).isoformat()
        obs.modified = modified
        return obs

    def _make_engine(self, search_hits=0):
        from gnat.reasoning.engine import ReasoningEngine
        from gnat.search.index import NullSearchIndex

        manager = MagicMock()
        ws = MagicMock()
        ws.objects = {}
        manager.open.return_value = ws

        search_index = MagicMock()
        search_index.search.return_value = list(range(search_hits))

        engine = ReasoningEngine(
            manager=manager,
            workspace_name="test-ws",
            search_index=search_index,
        )
        return engine, ws

    def test_prioritize_returns_sorted(self):
        engine, ws = self._make_engine(search_hits=3)

        obs1 = self._make_observable("indicator--1", modified_days_ago=1)
        obs2 = self._make_observable("indicator--2", modified_days_ago=100)

        from gnat.core.context import ExecutionContext
        ctx = ExecutionContext.create(
            initiated_by="test",
            domain="analysis",
            workspace_id="ws1",
            trust_level="trusted_internal",
        )
        results = engine.prioritize([obs1, obs2], context=ctx, store_notes=False)

        assert len(results) == 2
        # Sorted descending by score
        assert results[0][1] >= results[1][1]

    def test_score_in_range(self):
        engine, ws = self._make_engine(search_hits=0)

        obs = self._make_observable("indicator--x", modified_days_ago=5)
        results = engine.prioritize([obs], store_notes=False)

        score = results[0][1]
        assert 0.0 <= score <= 1.0

    def test_explanation_structure(self):
        engine, ws = self._make_engine(search_hits=2)

        obs = self._make_observable("indicator--y", modified_days_ago=2)
        results = engine.prioritize([obs], store_notes=False)

        _, score, explanation = results[0]
        assert "components" in explanation
        assert "trust_weight" in explanation["components"]
        assert "age_factor" in explanation["components"]
        assert "negative_evidence" in explanation["components"]
        assert "corroboration" in explanation["components"]
        assert "score" in explanation
        assert "summary" in explanation

    def test_negative_evidence_reduces_score(self):
        from gnat.reasoning.engine import ReasoningEngine
        from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord
        from gnat.search.index import NullSearchIndex

        manager = MagicMock()
        ws = MagicMock()

        obs_id = "indicator--neg-test"

        # Build negative evidence record pointing at our observable
        neg_rec = NegativeEvidenceRecord(
            target_ref=obs_id,
            queried_connector="VirusTotal",
            ttl_seconds=3600,
        )
        neg_dict = neg_rec.to_dict()

        # Workspace returns the negative evidence on iteration
        fake_obj = MagicMock()
        fake_obj.to_dict.return_value = neg_dict
        ws.objects = {neg_rec.id: fake_obj}
        manager.open.return_value = ws

        engine = ReasoningEngine(
            manager=manager,
            workspace_name="test-ws",
            search_index=NullSearchIndex(),
        )

        obs = self._make_observable(obs_id, modified_days_ago=1)
        results_with_neg = engine.prioritize([obs], store_notes=False)
        neg_score = results_with_neg[0][1]

        # Score with neg evidence should be lower than without
        ws.objects = {}
        results_without = engine.prioritize([obs], store_notes=False)
        clean_score = results_without[0][1]

        assert neg_score < clean_score

    def test_age_factor_decay(self):
        from gnat.reasoning.engine import ReasoningEngine

        # Fresh object (today)
        obs_fresh = MagicMock()
        obs_fresh.modified = datetime.now(timezone.utc).isoformat()
        fresh_factor = ReasoningEngine._age_factor(obs_fresh)
        assert fresh_factor >= 0.95  # barely decayed

        # Old object (20 days ago = 1.0 - 0.05*20 = 0.0)
        obs_old = MagicMock()
        obs_old.modified = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        old_factor = ReasoningEngine._age_factor(obs_old)
        assert old_factor == 0.0

    def test_age_factor_no_modified(self):
        from gnat.reasoning.engine import ReasoningEngine

        obs = MagicMock()
        obs.modified = ""
        assert ReasoningEngine._age_factor(obs) == 0.5

    def test_trusted_internal_scores_higher(self):
        from gnat.reasoning.engine import ReasoningEngine
        from gnat.core.context import ExecutionContext
        from gnat.search.index import NullSearchIndex

        manager = MagicMock()
        ws = MagicMock()
        ws.objects = {}
        manager.open.return_value = ws

        engine = ReasoningEngine(manager=manager, search_index=NullSearchIndex())

        obs = self._make_observable("indicator--trust-test", modified_days_ago=1)

        ctx_trusted = ExecutionContext.create(
            initiated_by="splunk", domain="analysis", workspace_id="ws1",
            trust_level="trusted_internal",
        )
        ctx_untrusted = ExecutionContext.create(
            initiated_by="otx", domain="analysis", workspace_id="ws1",
            trust_level="untrusted_external",
        )

        res_trusted = engine.prioritize([obs], context=ctx_trusted, store_notes=False)
        res_untrusted = engine.prioritize([obs], context=ctx_untrusted, store_notes=False)

        assert res_trusted[0][1] > res_untrusted[0][1]
