# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_investigation
====================================

Investigation Copilot: bidirectional conversational agent that guides analysts
through investigations and invokes workflow steps.

Analyst interaction: "What should I ask next?" → Copilot suggests questions
Workflow interaction: Workflow step pauses, triggers copilot gate, resumes with analyst feedback
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
import asyncio

from gnat.agents.conversations import ConversationStore, ConversationTurn, ConversationRole, SessionContext
from gnat.agents.llm import LLMClient
from gnat.agents.base import AgentConfig


class CopilotPhase(str, Enum):
    """State machine for investigation progress."""
    IDLE = "IDLE"
    GATHERING = "GATHERING"  # Collecting initial details
    HYPOTHESIZING = "HYPOTHESIZING"  # Building and testing hypotheses
    TESTING = "TESTING"  # Running enrichment/validation
    CLOSING = "CLOSING"  # Drafting final assessment
    COMPLETE = "COMPLETE"


@dataclass
class CopilotSuggestion:
    """Suggested next action."""
    action_type: str  # "question" | "workflow_step" | "enrichment"
    text: str
    metadata: Dict[str, Any]
    confidence: float = 0.8


class InvestigationCopilotSession:
    """
    Bidirectional investigation copilot.
    Guides analysts with questions and recommendations.
    Can be invoked by workflow steps and can invoke them back.
    """

    def __init__(
        self,
        conversation_id: str,
        config: AgentConfig,
        conversation_store: Optional[ConversationStore] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        """
        Initialize copilot session.

        Args:
            conversation_id: Unique session ID
            config: Agent configuration (LLM settings, confidence ceiling)
            conversation_store: Optional custom store; uses default if None
            llm_client: Optional custom LLM client; uses Claude if None
        """
        self.conversation_id = conversation_id
        self.config = config
        self.store = conversation_store or ConversationStore()
        self.llm = llm_client or LLMClient.from_config(config)

        ctx = self.store.get_session(conversation_id)
        if not ctx:
            raise ValueError(f"Conversation {conversation_id} not found")

        self.session_context = ctx

    async def ask_clarifying_question(self, user_input: str) -> str:
        """
        Analyst has provided context. Generate next clarifying question.

        Args:
            user_input: Analyst's response to previous question (or initial input)

        Returns:
            Copilot's clarifying question as string
        """
        # Log analyst input
        await self._add_turn(ConversationRole.ANALYST, user_input)

        # Fetch investigation state (IOCs, hypotheses, confidence)
        # TODO: Query workspace to get investigation object
        investigation_state = {}  # Placeholder

        # Generate question based on phase
        phase = CopilotPhase(self.session_context.state)
        prompt = self._build_question_prompt(phase, investigation_state, user_input)

        # Call Claude (streaming)
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token

        # Log copilot response
        await self._add_turn(ConversationRole.COPILOT, response_text)

        # Determine next phase
        new_phase = self._advance_phase(phase, investigation_state)
        self.store.update_session_state(self.conversation_id, new_phase.value)

        return response_text

    async def refine_hypothesis(self, analyst_feedback: str) -> Dict[str, Any]:
        """
        Analyst has provided feedback on a hypothesis. Refine confidence + scope.

        Args:
            analyst_feedback: "I'm confident in this" | "This seems unlikely" | etc.

        Returns:
            Updated hypothesis with new confidence scores
        """
        # Log feedback
        await self._add_turn(ConversationRole.ANALYST, analyst_feedback)

        # TODO: Fetch current hypotheses from investigation
        hypotheses = []  # Placeholder

        # Use Claude to score feedback + update confidence
        prompt = self._build_refinement_prompt(hypotheses, analyst_feedback)
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token

        # Parse response + extract new scores
        # TODO: Parse Claude response to extract hypothesis updates
        updated_hypothesis = {"text": response_text, "confidence": 0.75}

        # Log response
        await self._add_turn(ConversationRole.COPILOT, response_text)

        return updated_hypothesis

    async def suggest_next_step(self) -> CopilotSuggestion:
        """
        Suggest next investigation action based on current state.

        Returns:
            CopilotSuggestion with action type and metadata
        """
        # Fetch investigation state
        # TODO: Query workspace
        investigation_state = {}  # Placeholder
        turns = self.store.get_turns(self.conversation_id)

        # Build prompt to suggest action
        prompt = self._build_step_suggestion_prompt(investigation_state, turns)
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token

        # Log suggestion
        await self._add_turn(ConversationRole.COPILOT, response_text)

        # Parse response to extract action type
        # TODO: Parse Claude response
        suggestion = CopilotSuggestion(
            action_type="workflow_step",
            text=response_text,
            metadata={"workflow_step": "enrichment", "estimated_duration_sec": 120},
        )

        return suggestion

    async def invoke_workflow_step(
        self,
        step_name: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Invoke a workflow step (e.g., enrichment, gap detection).
        Bidirectional: workflow can later call back to copilot.

        Args:
            step_name: Name of workflow step to invoke
            context: Workflow context (investigation, objects, etc.)

        Returns:
            Step execution result
        """
        # Log invocation
        metadata = {"step_name": step_name, "context_keys": list(context.keys())}
        await self._add_turn(
            ConversationRole.SYSTEM,
            f"Invoking workflow step: {step_name}",
            metadata=metadata,
        )

        # TODO: Invoke actual workflow step via WorkflowDAG
        # For now, return placeholder
        result = {
            "step_name": step_name,
            "status": "completed",
            "output": {},
        }

        # Log result
        await self._add_turn(
            ConversationRole.SYSTEM,
            f"Step {step_name} completed",
            metadata={"result_keys": list(result.keys())},
        )

        return result

    async def workflow_gate_prompt(
        self,
        gate_question: str,
        context: Dict[str, Any],
    ) -> str:
        """
        Workflow step has hit a gate that requires analyst input.
        Pause workflow, prompt analyst via copilot, return answer.

        Args:
            gate_question: The question the workflow is asking
            context: Workflow context for framing

        Returns:
            Analyst's answer (will be awaited by workflow)
        """
        # Log gate
        await self._add_turn(
            ConversationRole.SYSTEM,
            f"Workflow gate: {gate_question}",
            metadata={"context_keys": list(context.keys())},
        )

        # Return without response; frontend will prompt analyst
        # When analyst responds, _add_turn(ANALYST, response) is called,
        # triggering workflow to resume
        return gate_question

    # Private helpers

    async def _add_turn(
        self,
        role: ConversationRole,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConversationTurn:
        """Log a conversational turn."""
        return self.store.add_turn(
            self.conversation_id,
            role,
            text,
            metadata=metadata or {},
        )

    def _build_question_prompt(
        self,
        phase: CopilotPhase,
        investigation_state: Dict[str, Any],
        user_input: str,
    ) -> str:
        """Build Claude prompt for clarifying question."""
        # Placeholder: real implementation will be in copilot_prompts.py
        return f"""
        Phase: {phase.value}
        Investigation state: {investigation_state}
        Analyst said: {user_input}

        What is the next clarifying question to narrow scope and build hypothesis?
        Keep it concise (1 sentence).
        """

    def _build_refinement_prompt(
        self,
        hypotheses: List[Dict[str, Any]],
        analyst_feedback: str,
    ) -> str:
        """Build Claude prompt for hypothesis refinement."""
        return f"""
        Current hypotheses: {hypotheses}
        Analyst feedback: {analyst_feedback}

        Re-score the hypotheses based on this feedback. Return JSON with updated confidence values.
        """

    def _build_step_suggestion_prompt(
        self,
        investigation_state: Dict[str, Any],
        turns: List[ConversationTurn],
    ) -> str:
        """Build Claude prompt to suggest next investigation step."""
        return f"""
        Investigation state: {investigation_state}
        Conversation history: {len(turns)} turns

        What is the next recommended action? Choose from:
        - Query ThreatQ for campaign overlap
        - Run hunt package XYZ
        - Check Recorded Future for reputation
        - Narrow scope by excluding actors

        Recommend one action with reasoning.
        """

    def _advance_phase(self, current: CopilotPhase, state: Dict[str, Any]) -> CopilotPhase:
        """Determine next phase based on current state."""
        # Placeholder: real logic will analyze investigation state
        phase_order = [
            CopilotPhase.IDLE,
            CopilotPhase.GATHERING,
            CopilotPhase.HYPOTHESIZING,
            CopilotPhase.TESTING,
            CopilotPhase.CLOSING,
            CopilotPhase.COMPLETE,
        ]
        idx = phase_order.index(current)
        return phase_order[min(idx + 1, len(phase_order) - 1)]
