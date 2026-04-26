# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_governor
==============================

Safety governance for Investigation Copilot and Live Analyst Assistant.
Integrates with AgentGovernor for permission checks and HITL gates.
Tracks costs, audit trail, and escalations.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any

from gnat.agents.governor import AgentGovernor, Permission
from gnat.context import ExecutionContext


class CopilotAction(str, Enum):
    """Actions that may require governance checks."""
    ASK_QUESTION = "ask_question"
    INVOKE_WORKFLOW = "invoke_workflow"
    SUGGEST_STEP = "suggest_step"
    REFINE_HYPOTHESIS = "refine_hypothesis"
    ESCALATE_TO_IR = "escalate_to_ir"


class AssistantAction(str, Enum):
    """Assistant actions that may require checks."""
    SUGGEST_ENRICHMENT = "suggest_enrichment"
    DRAFT_REPORT = "draft_report"
    EXPLAIN_FINDING = "explain_finding"
    SEARCH_HELP = "search_help"


class ActionRisk(str, Enum):
    """Risk level of action (affects gating)."""
    LOW = "low"  # Just informational, no gate needed
    MEDIUM = "medium"  # Analyst approval recommended for high-confidence
    HIGH = "high"  # Analyst approval required before action
    CRITICAL = "critical"  # Triggers immediate HITL + escalation


@dataclass
class GovernedAction:
    """Action metadata for governance tracking."""
    action_type: str
    investigation_id: str
    analyst_id: str
    risk_level: ActionRisk
    confidence: float
    description: str
    metadata: Dict[str, Any] = None
    timestamp: datetime = None
    execution_context: Optional[ExecutionContext] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def to_dict(self) -> dict:
        """Serialize for audit trail."""
        return {
            "action_type": self.action_type,
            "investigation_id": self.investigation_id,
            "analyst_id": self.analyst_id,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "description": self.description,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "context_id": self.execution_context.context_id if self.execution_context else None,
        }


class CopilotGovernor:
    """
    Safety gates for Investigation Copilot.
    Integrates with AgentGovernor for permission checks.
    Escalates high-confidence suggestions to ReviewService.
    """

    def __init__(self, agent_governor: Optional[AgentGovernor] = None):
        """
        Initialize governor.

        Args:
            agent_governor: Optional AgentGovernor instance (creates default if None)
        """
        self.governor = agent_governor or AgentGovernor.from_config()
        self.audit_trail = []

    async def check_copilot_action(
        self,
        action: CopilotAction,
        investigation_id: str,
        analyst_id: str,
        confidence: float,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Check if copilot action is permitted.

        Args:
            action: Type of action (ASK_QUESTION, INVOKE_WORKFLOW, etc.)
            investigation_id: Investigation being worked on
            analyst_id: Analyst performing action
            confidence: Confidence score (0-1) of the suggestion
            description: Human-readable description
            metadata: Additional context

        Returns:
            True if action permitted, False otherwise
        """
        governed_action = GovernedAction(
            action_type=action.value,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            risk_level=self._determine_risk(action, confidence),
            confidence=confidence,
            description=description,
            metadata=metadata or {},
        )

        # Log to audit trail
        self.audit_trail.append(governed_action.to_dict())

        # Check permissions based on action and risk
        if governed_action.risk_level == ActionRisk.CRITICAL:
            # Always require HITL for critical actions
            return False

        elif governed_action.risk_level == ActionRisk.HIGH and confidence > 0.8:
            # High-risk + high-confidence requires analyst approval
            # Implementation: return False, trigger ReviewService HITL gate
            # ReviewService.submit_for_approval(governed_action)
            return False

        else:
            # Medium/Low risk actions are auto-approved
            return True

    async def check_assistant_action(
        self,
        action: AssistantAction,
        investigation_id: str,
        analyst_id: str,
        description: str,
    ) -> bool:
        """
        Check if assistant action is permitted.

        Args:
            action: Type of action
            investigation_id: Investigation ID
            analyst_id: Analyst ID
            description: Action description

        Returns:
            True if permitted
        """
        governed_action = GovernedAction(
            action_type=action.value,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            risk_level=self._risk_for_assistant(action),
            confidence=1.0,  # Assistant actions are deterministic
            description=description,
        )

        self.audit_trail.append(governed_action.to_dict())

        # Assistant actions are generally low-risk (informational)
        return governed_action.risk_level != ActionRisk.CRITICAL

    def _determine_risk(self, action: CopilotAction, confidence: float) -> ActionRisk:
        """Determine risk level of copilot action."""
        if action == CopilotAction.ESCALATE_TO_IR:
            return ActionRisk.CRITICAL

        elif action == CopilotAction.INVOKE_WORKFLOW:
            # Enrichment workflows are MEDIUM risk
            return ActionRisk.MEDIUM

        elif action == CopilotAction.REFINE_HYPOTHESIS:
            # High-confidence hypothesis refinement is HIGH risk
            if confidence > 0.85:
                return ActionRisk.HIGH
            return ActionRisk.MEDIUM

        else:
            # Questions, suggestions are LOW risk
            return ActionRisk.LOW

    def _risk_for_assistant(self, action: AssistantAction) -> ActionRisk:
        """Determine risk level of assistant action."""
        if action in [AssistantAction.SUGGEST_ENRICHMENT, AssistantAction.EXPLAIN_FINDING]:
            return ActionRisk.LOW  # Just suggestions

        elif action == AssistantAction.DRAFT_REPORT:
            return ActionRisk.MEDIUM  # Content may go to executives

        else:
            return ActionRisk.LOW

    def get_audit_trail(self) -> list:
        """Retrieve audit trail of all governed actions."""
        return self.audit_trail


@dataclass
class CostTracker:
    """Track LLM token usage and cost."""
    investigation_id: str
    tokens_in_total: int = 0
    tokens_out_total: int = 0
    latency_ms_total: float = 0.0
    call_count: int = 0
    cost_estimate: float = 0.0  # USD, assuming $3/1M input, $15/1M output tokens

    MODEL_COSTS = {
        "claude-opus-4-7": {"input": 0.000003, "output": 0.000015},
        "claude-sonnet-4-6": {"input": 0.000003, "output": 0.000015},
        "claude-haiku-4-5": {"input": 0.00000080, "output": 0.000004},
    }

    def add_call(
        self,
        tokens_in: int,
        tokens_out: int,
        latency_ms: float,
        model: str = "claude-sonnet-4-6",
    ) -> None:
        """Record an LLM call."""
        self.tokens_in_total += tokens_in
        self.tokens_out_total += tokens_out
        self.latency_ms_total += latency_ms
        self.call_count += 1

        # Update cost estimate
        costs = self.MODEL_COSTS.get(model, self.MODEL_COSTS["claude-sonnet-4-6"])
        call_cost = (tokens_in * costs["input"]) + (tokens_out * costs["output"])
        self.cost_estimate += call_cost

    def should_alert_on_cost(self, threshold_usd: float = 10.0) -> bool:
        """Check if cost exceeds threshold."""
        return self.cost_estimate >= threshold_usd

    def get_stats(self) -> dict:
        """Return cost/usage statistics."""
        avg_latency = (
            self.latency_ms_total / self.call_count if self.call_count > 0 else 0
        )
        return {
            "investigation_id": self.investigation_id,
            "call_count": self.call_count,
            "tokens_in": self.tokens_in_total,
            "tokens_out": self.tokens_out_total,
            "total_tokens": self.tokens_in_total + self.tokens_out_total,
            "avg_latency_ms": avg_latency,
            "cost_estimate_usd": round(self.cost_estimate, 4),
        }
