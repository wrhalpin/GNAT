"""
tests/unit/test_phase4_governor.py
====================================
Unit tests for Phase 4D — AgentGovernor, HITLGateway, and policy models.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Policy model tests (AgentActionType)
# ---------------------------------------------------------------------------

class TestAgentActionType:
    def test_all_action_types_defined(self):
        from gnat.policy.models import AgentActionType

        expected = {
            "read_stix", "write_stix", "delete_stix", "enrich",
            "ingest", "export", "trigger_playbook", "manage_workspace",
            "escalate", "hypothesize",
        }
        actual = {a.value for a in AgentActionType}
        assert expected == actual

    def test_trusted_internal_has_all_actions(self):
        from gnat.policy.models import AgentActionType, agent_can_act

        for action in AgentActionType:
            assert agent_can_act("trusted_internal", action) is True

    def test_untrusted_external_limited(self):
        from gnat.policy.models import AgentActionType, agent_can_act

        # Untrusted cannot trigger playbooks
        assert agent_can_act("untrusted_external", AgentActionType.TRIGGER_PLAYBOOK) is False
        assert agent_can_act("untrusted_external", AgentActionType.EXPORT) is False

        # But can read and hypothesize
        assert agent_can_act("untrusted_external", AgentActionType.READ_STIX) is True
        assert agent_can_act("untrusted_external", AgentActionType.HYPOTHESIZE) is True

    def test_semi_trusted_can_enrich(self):
        from gnat.policy.models import AgentActionType, agent_can_act

        assert agent_can_act("semi_trusted", AgentActionType.ENRICH) is True
        assert agent_can_act("semi_trusted", AgentActionType.TRIGGER_PLAYBOOK) is False

    def test_unknown_trust_level_denied(self):
        from gnat.policy.models import AgentActionType, agent_can_act

        assert agent_can_act("unknown_level", AgentActionType.ENRICH) is False


# ---------------------------------------------------------------------------
# AgentGovernor tests
# ---------------------------------------------------------------------------

class TestAgentGovernor:
    def _make_governor(self, **kwargs):
        from gnat.agents.governor import AgentGovernor
        return AgentGovernor(**kwargs)

    def test_can_act_trusted_internal(self):
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        assert gov.can_act("agent-1", AgentActionType.TRIGGER_PLAYBOOK, "trusted_internal") is True

    def test_can_act_untrusted_denied(self):
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        assert gov.can_act("agent-1", AgentActionType.TRIGGER_PLAYBOOK, "untrusted_external") is False

    def test_require_can_act_raises(self):
        from gnat.agents.governor import AgentPermissionDenied
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        with pytest.raises(AgentPermissionDenied):
            gov.require_can_act("agent-1", AgentActionType.TRIGGER_PLAYBOOK, "untrusted_external")

    def test_policy_override_allow(self):
        from gnat.policy.models import AgentActionType

        gov = self._make_governor(
            policy_overrides={"agent-special": {"trigger_playbook": True}}
        )
        # Override allows untrusted external to trigger playbooks
        assert gov.can_act("agent-special", AgentActionType.TRIGGER_PLAYBOOK, "untrusted_external") is True

    def test_policy_override_deny(self):
        from gnat.policy.models import AgentActionType

        gov = self._make_governor(
            policy_overrides={"agent-restricted": {"enrich": False}}
        )
        # Override denies trusted_internal from enriching
        assert gov.can_act("agent-restricted", AgentActionType.ENRICH, "trusted_internal") is False

    def test_set_policy_override_runtime(self):
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        gov.set_policy_override("agent-X", AgentActionType.EXPORT, True)
        assert gov.can_act("agent-X", AgentActionType.EXPORT, "untrusted_external") is True

    def test_record_action(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.ENRICH,
            target_ref="indicator--abc",
            impact_level="low",
        )
        gov.record_action(action)
        log = gov.get_action_log()
        assert len(log) == 1
        assert log[0].agent_id == "agent-1"

    def test_get_action_log_filtered(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        gov = self._make_governor()
        a1 = AgentAction(agent_id="agent-A", action_type=AgentActionType.ENRICH)
        a2 = AgentAction(agent_id="agent-B", action_type=AgentActionType.READ_STIX)
        gov.record_action(a1)
        gov.record_action(a2)

        assert len(gov.get_action_log("agent-A")) == 1
        assert len(gov.get_action_log("agent-B")) == 1
        assert len(gov.get_action_log()) == 2

    def test_rate_limit_check_passes(self):
        gov = self._make_governor(max_calls_per_window=5, window_seconds=60)
        for _ in range(5):
            gov.rate_limit_check("agent-1")
        # 5th call should succeed

    def test_rate_limit_check_raises(self):
        from gnat.agents.governor import RateLimitExceeded

        gov = self._make_governor(max_calls_per_window=3, window_seconds=60)
        gov.rate_limit_check("agent-1")
        gov.rate_limit_check("agent-1")
        gov.rate_limit_check("agent-1")
        with pytest.raises(RateLimitExceeded) as exc_info:
            gov.rate_limit_check("agent-1")
        assert exc_info.value.agent_id == "agent-1"
        assert exc_info.value.window_seconds == 60

    def test_rate_limit_window_expires(self):
        import time
        from gnat.agents.governor import AgentGovernor

        gov = AgentGovernor(max_calls_per_window=2, window_seconds=1)
        gov.rate_limit_check("agent-1")
        gov.rate_limit_check("agent-1")
        # Wait for window to expire
        time.sleep(1.1)
        # Should be allowed again
        gov.rate_limit_check("agent-1")


# ---------------------------------------------------------------------------
# AgentAction tests
# ---------------------------------------------------------------------------

class TestAgentAction:
    def test_create(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.ENRICH,
            target_ref="indicator--abc",
            impact_level="high",
        )
        assert action.agent_id == "agent-1"
        assert action.impact_level == "high"
        assert action.status == "pending"
        assert action.action_id  # auto-generated

    def test_invalid_impact_level(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        with pytest.raises(ValueError, match="impact_level must be one of"):
            AgentAction(
                agent_id="agent-1",
                action_type=AgentActionType.ENRICH,
                impact_level="extreme",
            )

    def test_to_dict(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        action = AgentAction(
            agent_id="test",
            action_type=AgentActionType.WRITE_STIX,
            target_ref="indicator--xyz",
            impact_level="medium",
        )
        d = action.to_dict()
        assert d["agent_id"] == "test"
        assert d["action_type"] == "write_stix"
        assert d["impact_level"] == "medium"
        assert "action_id" in d
        assert "submitted_at" in d


# ---------------------------------------------------------------------------
# HITLGateway tests
# ---------------------------------------------------------------------------

class TestHITLGateway:
    def _make_gateway(self, auto_approve=True):
        from gnat.agents.hitl import HITLGateway

        review_service = MagicMock()
        mock_item = MagicMock()
        mock_item.id = "review-item-123"
        from datetime import datetime, timezone
        mock_item.submitted_at = datetime.now(timezone.utc)

        from gnat.review.models import ReviewStatus
        mock_item.status = ReviewStatus.PENDING
        review_service.submit.return_value = mock_item
        review_service.get.return_value = mock_item
        review_service.approve.return_value = mock_item

        gateway = HITLGateway(review_service=review_service, approval_timeout_seconds=3600)
        return gateway, review_service, mock_item

    def test_low_impact_auto_approved(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        gateway, _, _ = self._make_gateway()
        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.READ_STIX,
            impact_level="low",
        )
        approved, review_item = gateway.evaluate(action)
        assert approved is True
        assert review_item is None
        assert action.approved_by == "auto-policy"
        assert action.status == "approved"

    def test_medium_impact_auto_approved(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        gateway, _, _ = self._make_gateway()
        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.ENRICH,
            impact_level="medium",
        )
        approved, review_item = gateway.evaluate(action)
        assert approved is True

    def test_high_impact_creates_review_item(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType

        gateway, review_service, mock_item = self._make_gateway()
        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.TRIGGER_PLAYBOOK,
            impact_level="high",
        )
        approved, review_item = gateway.evaluate(action)
        assert approved is False
        assert review_item is not None
        assert review_item.id == "review-item-123"
        review_service.submit.assert_called_once()
        assert action.status == "pending"

    def test_critical_impact_notifies_xsoar(self):
        from gnat.agents.governor import AgentAction
        from gnat.policy.models import AgentActionType
        from gnat.agents.hitl import HITLGateway

        review_service = MagicMock()
        mock_item = MagicMock()
        mock_item.id = "review-crit-999"
        from datetime import datetime, timezone
        mock_item.submitted_at = datetime.now(timezone.utc)
        from gnat.review.models import ReviewStatus
        mock_item.status = ReviewStatus.PENDING
        review_service.submit.return_value = mock_item

        xsoar = MagicMock()
        gateway = HITLGateway(
            review_service=review_service,
            xsoar_client=xsoar,
        )

        action = AgentAction(
            agent_id="agent-1",
            action_type=AgentActionType.TRIGGER_PLAYBOOK,
            impact_level="critical",
        )
        approved, review_item = gateway.evaluate(action)
        assert approved is False
        xsoar.upsert_object.assert_called_once()

    def test_check_approval_status_timeout(self):
        from gnat.agents.hitl import HITLGateway
        from gnat.review.models import ReviewStatus
        from datetime import datetime, timezone, timedelta

        review_service = MagicMock()
        mock_item = MagicMock()
        mock_item.id = "review-timeout"
        mock_item.submitted_at = datetime.now(timezone.utc) - timedelta(hours=2)
        mock_item.status = ReviewStatus.PENDING
        review_service.get.return_value = mock_item

        rejected_item = MagicMock()
        rejected_item.status = ReviewStatus.REJECTED

        # After reject, get returns the rejected item
        call_count = [0]
        def get_side_effect(item_id):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_item
            return rejected_item
        review_service.get.side_effect = get_side_effect

        gateway = HITLGateway(review_service=review_service, approval_timeout_seconds=60)
        status = gateway.check_approval_status("review-timeout")
        review_service.reject.assert_called_once()
        assert status == ReviewStatus.REJECTED

    def test_auto_approve_pending(self):
        from gnat.agents.hitl import HITLGateway
        from gnat.review.models import ReviewStatus

        review_service = MagicMock()
        mock_item = MagicMock()
        mock_item.status = ReviewStatus.APPROVED
        review_service.approve.return_value = mock_item

        gateway = HITLGateway(review_service=review_service)
        gateway.auto_approve_pending("review-123", reviewer="system-test")
        review_service.approve.assert_called_once_with(
            "review-123", reviewed_by="system-test"
        )


# ---------------------------------------------------------------------------
# AgentTestHarness tests
# ---------------------------------------------------------------------------

class TestAgentTestHarness:
    def test_run_action_low_impact(self):
        from gnat.testing import AgentTestHarness
        from gnat.policy.models import AgentActionType

        harness = AgentTestHarness()
        approved, action = harness.run_action(
            agent_id="test-agent",
            action_type=AgentActionType.ENRICH,
            impact_level="low",
            trust_level="semi_trusted",
        )
        assert approved is True
        assert action.status == "approved"
        assert len(harness.recorded_actions) == 1

    def test_run_action_denied(self):
        from gnat.testing import AgentTestHarness
        from gnat.agents.governor import AgentPermissionDenied
        from gnat.policy.models import AgentActionType

        harness = AgentTestHarness()
        with pytest.raises(AgentPermissionDenied):
            harness.run_action(
                agent_id="test-agent",
                action_type=AgentActionType.TRIGGER_PLAYBOOK,
                trust_level="untrusted_external",
            )

    def test_multiple_actions_recorded(self):
        from gnat.testing import AgentTestHarness
        from gnat.policy.models import AgentActionType

        harness = AgentTestHarness()
        for _ in range(5):
            harness.run_action(
                agent_id="bulk-agent",
                action_type=AgentActionType.READ_STIX,
                trust_level="semi_trusted",
            )
        assert len(harness.recorded_actions) == 5
