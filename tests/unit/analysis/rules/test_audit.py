# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for AuditWriter (in-memory mode)."""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analysis.rules.audit import AuditWriter, _serialize_decision
from gnat.analysis.rules.decisions import annotate, no_op, set_status
from gnat.analysis.rules.result import RuleEvaluationResult, RuleFiring


def _make_result(*decisions):
    result = RuleEvaluationResult()
    for i, d in enumerate(decisions):
        result.firings.append(RuleFiring(
            rule_name=f"rule-{i}",
            rule_source_file=f"rule_{i}.hy",
            rule_git_sha=None,
            decision=d,
        ))
    return result


class TestAuditWriterMemory:
    def test_record_single_firing(self):
        writer = AuditWriter()
        hyp = MagicMock(id="hyp-1")
        inv = MagicMock(id="inv-1")
        result = _make_result(set_status("supported", "test"))
        ids = writer.record_firing(result, hyp, inv, workspace_id=1)
        assert len(ids) == 1
        assert len(writer.memory_log) == 1
        assert writer.memory_log[0]["applied"] is False
        assert writer.memory_log[0]["rule_name"] == "rule-0"

    def test_record_multiple_firings(self):
        writer = AuditWriter()
        hyp = MagicMock(id="hyp-1")
        inv = MagicMock(id="inv-1")
        result = _make_result(
            set_status("supported"),
            annotate("flag", "v"),
        )
        ids = writer.record_firing(result, hyp, inv, workspace_id=1)
        assert len(ids) == 2

    def test_mark_applied_success(self):
        writer = AuditWriter()
        hyp = MagicMock(id="hyp-1")
        inv = MagicMock(id="inv-1")
        result = _make_result(set_status("supported"))
        ids = writer.record_firing(result, hyp, inv, workspace_id=1)
        writer.mark_applied(ids[0])
        assert writer.memory_log[0]["applied"] is True
        assert writer.memory_log[0]["error_message"] is None

    def test_mark_applied_with_error(self):
        writer = AuditWriter()
        hyp = MagicMock(id="hyp-1")
        inv = MagicMock(id="inv-1")
        result = _make_result(set_status("supported"))
        ids = writer.record_firing(result, hyp, inv, workspace_id=1)
        writer.mark_applied(ids[0], error_message="transition failed")
        assert writer.memory_log[0]["applied"] is False
        assert writer.memory_log[0]["error_message"] == "transition failed"

    def test_ids_are_unique(self):
        writer = AuditWriter()
        hyp = MagicMock(id="hyp-1")
        inv = MagicMock(id="inv-1")
        r1 = _make_result(set_status("supported"))
        r2 = _make_result(annotate("k", "v"))
        ids1 = writer.record_firing(r1, hyp, inv, workspace_id=1)
        ids2 = writer.record_firing(r2, hyp, inv, workspace_id=1)
        assert ids1[0] != ids2[0]


class TestSerializeDecision:
    def test_set_status_serialization(self):
        d = set_status("supported", "reason")
        s = _serialize_decision(d)
        assert s["action"] == "set_status"
        assert s["target_status"] == "supported"
        assert s["reason"] == "reason"

    def test_annotate_serialization(self):
        d = annotate("flag", "value", "reason")
        s = _serialize_decision(d)
        assert s["action"] == "annotate"
        assert s["key"] == "flag"
        assert s["value"] == "value"

    def test_no_op_serialization(self):
        d = no_op("waiting")
        s = _serialize_decision(d)
        assert s["action"] == "no_op"
        assert s["target_status"] is None
