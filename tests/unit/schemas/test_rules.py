# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for rule engine schemas — round-trip from audit record dicts."""

from __future__ import annotations

from gnat.schemas.rules.audit import RuleAuditEntrySchema
from gnat.schemas.rules.rule import RuleSchema


class TestRuleAuditEntrySchema:
    def test_round_trip_from_dict(self) -> None:
        record = {
            "id": 42,
            "investigation_id": "inv-001",
            "hypothesis_id": "hyp-001",
            "workspace_id": 1,
            "rule_name": "lateral-movement-requires-host",
            "rule_source_file": "rules/lateral.hy",
            "rule_git_sha": "abc123def456",
            "fired_at": "2026-04-25T10:30:00+00:00",
            "decision": {
                "action": "set_status",
                "reason": "Host IOC linked.",
                "target_status": "supported",
                "key": None,
                "value": None,
            },
            "applied": False,
            "applied_at": None,
            "error_message": None,
            "engine_version": "1.0.0",
        }

        schema = RuleAuditEntrySchema.from_domain(record)
        dumped = schema.model_dump()

        assert dumped["id"] == 42
        assert dumped["investigation_id"] == "inv-001"
        assert dumped["hypothesis_id"] == "hyp-001"
        assert dumped["workspace_id"] == 1
        assert dumped["rule_name"] == "lateral-movement-requires-host"
        assert dumped["rule_source_file"] == "rules/lateral.hy"
        assert dumped["rule_git_sha"] == "abc123def456"
        assert dumped["fired_at"] == "2026-04-25T10:30:00+00:00"
        assert dumped["decision"]["action"] == "set_status"
        assert dumped["applied"] is False
        assert dumped["applied_at"] is None
        assert dumped["error_message"] is None
        assert dumped["engine_version"] == "1.0.0"

    def test_applied_record(self) -> None:
        record = {
            "id": 43,
            "rule_name": "no-evidence-check",
            "fired_at": "2026-04-25T11:00:00+00:00",
            "decision": {"action": "flag", "reason": "No evidence."},
            "applied": True,
            "applied_at": "2026-04-25T11:01:00+00:00",
        }
        schema = RuleAuditEntrySchema.from_domain(record)
        assert schema.applied is True
        assert schema.applied_at == "2026-04-25T11:01:00+00:00"

    def test_error_record(self) -> None:
        record = {
            "id": 44,
            "rule_name": "broken-rule",
            "fired_at": "2026-04-25T12:00:00+00:00",
            "decision": {},
            "applied": False,
            "error_message": "KeyError: 'missing_field'",
        }
        schema = RuleAuditEntrySchema.from_domain(record)
        assert schema.applied is False
        assert schema.error_message == "KeyError: 'missing_field'"


class TestRuleSchema:
    def test_round_trip(self) -> None:
        schema = RuleSchema(
            name="no-evidence-check",
            source_file="rules/base.hy",
            engine="hy",
            description="Checks for missing evidence.",
            enabled=True,
            metadata={"author": "system"},
        )
        dumped = schema.model_dump()

        assert dumped["name"] == "no-evidence-check"
        assert dumped["source_file"] == "rules/base.hy"
        assert dumped["engine"] == "hy"
        assert dumped["description"] == "Checks for missing evidence."
        assert dumped["enabled"] is True
        assert dumped["metadata"] == {"author": "system"}

    def test_defaults(self) -> None:
        schema = RuleSchema(name="test")
        assert schema.source_file == ""
        assert schema.engine == ""
        assert schema.enabled is True
        assert schema.metadata == {}
