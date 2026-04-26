# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_workflows
===============================

Built-in guided workflows that integrate copilot with investigation automation.
Copilot asks clarifying questions, then executes workflow steps.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable
from datetime import datetime

from gnat.agents.copilot_investigation import InvestigationCopilotSession, CopilotPhase
from gnat.agents.conversations import ConversationStore


@dataclass
class GuidedWorkflowStep:
    """Step in a guided workflow."""
    step_name: str
    description: str
    copilot_gate_question: Optional[str] = None  # If set, copilot asks before executing
    execute_fn: Optional[Callable] = None  # Actual execution function
    auto_proceed: bool = True  # Auto-advance if no gate question


class CopilotGuidedPhishingTriage:
    """
    Guided workflow for phishing triage investigations.
    Copilot asks clarifying questions, then orchestrates enrichment, correlation, reporting.
    """

    WORKFLOW_STEPS = [
        GuidedWorkflowStep(
            step_name="gather_details",
            description="Ask analyst for email details (sender, recipient, links, attachments)",
            copilot_gate_question="Let's gather details. What's the sender domain? (or 'unknown')",
            auto_proceed=False,
        ),
        GuidedWorkflowStep(
            step_name="assess_impact",
            description="Determine if email reached inbox or was caught",
            copilot_gate_question="Did the email reach the target inbox, or was it filtered?",
            auto_proceed=False,
        ),
        GuidedWorkflowStep(
            step_name="enrichment",
            description="Run automated enrichment (reputation, IOC checks, URL scanning)",
            copilot_gate_question=None,  # Auto-execute
            auto_proceed=True,
        ),
        GuidedWorkflowStep(
            step_name="correlation",
            description="Check for similar emails, phishing campaigns",
            copilot_gate_question=None,
            auto_proceed=True,
        ),
        GuidedWorkflowStep(
            step_name="draft_report",
            description="Generate phishing analysis report",
            copilot_gate_question="Should we escalate to incident response, or close as analysis complete?",
            auto_proceed=False,
        ),
    ]

    def __init__(self, copilot_session: InvestigationCopilotSession):
        """
        Initialize phishing triage workflow.

        Args:
            copilot_session: Active copilot session
        """
        self.copilot = copilot_session
        self.steps_executed = []
        self.investigation_data = {}

    async def run(self) -> Dict[str, Any]:
        """
        Execute phishing triage workflow with copilot guidance.

        Returns:
            Workflow result with status, findings, recommendations
        """
        result = {
            "workflow": "phishing_triage",
            "investigation_id": self.copilot.session_context.investigation_id,
            "started_at": datetime.utcnow().isoformat(),
            "steps_executed": [],
            "findings": {},
            "recommendation": None,
            "status": "in_progress",
        }

        try:
            for step in self.WORKFLOW_STEPS:
                # If step has a gate question, ask copilot
                if step.copilot_gate_question and not step.auto_proceed:
                    response = await self.copilot.ask_clarifying_question(
                        step.copilot_gate_question
                    )
                    self.investigation_data[step.step_name] = response

                # Execute step
                step_result = await self._execute_step(step)
                self.steps_executed.append(step.step_name)
                result["steps_executed"].append({
                    "step": step.step_name,
                    "status": "completed",
                    "result": step_result,
                })

                # Check for early exit (e.g., analyst says "close investigation")
                if self._should_exit_early(response=self.investigation_data.get(step.step_name)):
                    break

            result["status"] = "completed"
            result["recommendation"] = await self._generate_recommendation()

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)

        result["completed_at"] = datetime.utcnow().isoformat()
        return result

    async def _execute_step(self, step: GuidedWorkflowStep) -> Dict[str, Any]:
        """
        Execute a workflow step.

        Args:
            step: Step to execute

        Returns:
            Step result
        """
        # Placeholder: real implementation calls actual enrichment/correlation/report generation
        return {
            "step_name": step.step_name,
            "description": step.description,
            "status": "completed",
            "data": {},
        }

    def _should_exit_early(self, response: Optional[str]) -> bool:
        """Check if analyst wants to exit early."""
        if not response:
            return False

        exit_keywords = ["close", "done", "finish", "stop", "end"]
        return any(kw in response.lower() for kw in exit_keywords)

    async def _generate_recommendation(self) -> str:
        """Generate final recommendation based on workflow findings."""
        if "escalate" in str(self.investigation_data).lower():
            return "ESCALATE: Submit to incident response for containment"
        elif "benign" in str(self.investigation_data).lower():
            return "BENIGN: No suspicious activity detected. Close investigation."
        else:
            return "MONITOR: Mark as suspicious. Monitor for similar emails."


class CopilotGuidedIncidentResponse:
    """
    Guided workflow for incident response investigations.
    Copilot helps determine scope, impact, and response actions.
    """

    WORKFLOW_STEPS = [
        GuidedWorkflowStep(
            step_name="scope",
            description="Determine scope of incident (how many systems/users affected)",
            copilot_gate_question="How many systems/users are affected? (estimate or 'unknown')",
            auto_proceed=False,
        ),
        GuidedWorkflowStep(
            step_name="impact",
            description="Assess business impact (confidentiality, integrity, availability)",
            copilot_gate_question="What's the suspected impact? (data loss / system access / disruption / unknown)",
            auto_proceed=False,
        ),
        GuidedWorkflowStep(
            step_name="containment",
            description="Execute containment measures",
            copilot_gate_question=None,
            auto_proceed=True,
        ),
        GuidedWorkflowStep(
            step_name="investigation",
            description="Deep forensic investigation (timelines, lateral movement, persistence)",
            copilot_gate_question=None,
            auto_proceed=True,
        ),
        GuidedWorkflowStep(
            step_name="recovery",
            description="Plan recovery and remediation",
            copilot_gate_question="Should we initiate full recovery, or continue investigation first?",
            auto_proceed=False,
        ),
    ]

    def __init__(self, copilot_session: InvestigationCopilotSession):
        """Initialize incident response workflow."""
        self.copilot = copilot_session
        self.steps_executed = []
        self.incident_data = {}

    async def run(self) -> Dict[str, Any]:
        """Execute incident response workflow."""
        result = {
            "workflow": "incident_response",
            "investigation_id": self.copilot.session_context.investigation_id,
            "started_at": datetime.utcnow().isoformat(),
            "steps_executed": [],
            "incident_summary": {},
            "status": "in_progress",
        }

        try:
            for step in self.WORKFLOW_STEPS:
                if step.copilot_gate_question and not step.auto_proceed:
                    response = await self.copilot.ask_clarifying_question(
                        step.copilot_gate_question
                    )
                    self.incident_data[step.step_name] = response

                step_result = await self._execute_step(step)
                self.steps_executed.append(step.step_name)
                result["steps_executed"].append({
                    "step": step.step_name,
                    "status": "completed",
                    "result": step_result,
                })

            result["status"] = "completed"
            result["incident_summary"] = self.incident_data

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)

        result["completed_at"] = datetime.utcnow().isoformat()
        return result

    async def _execute_step(self, step: GuidedWorkflowStep) -> Dict[str, Any]:
        """Execute a workflow step."""
        return {
            "step_name": step.step_name,
            "description": step.description,
            "status": "completed",
            "data": {},
        }


class WorkflowFactory:
    """Factory for creating guided workflows."""

    WORKFLOW_TYPES = {
        "phishing_triage": CopilotGuidedPhishingTriage,
        "incident_response": CopilotGuidedIncidentResponse,
    }

    @classmethod
    def create(
        cls,
        workflow_type: str,
        copilot_session: InvestigationCopilotSession,
    ):
        """
        Create a guided workflow.

        Args:
            workflow_type: Type of workflow ("phishing_triage", "incident_response", etc.)
            copilot_session: Active copilot session

        Returns:
            Workflow instance
        """
        workflow_class = cls.WORKFLOW_TYPES.get(workflow_type)
        if not workflow_class:
            raise ValueError(
                f"Unknown workflow type: {workflow_type}. "
                f"Available: {list(cls.WORKFLOW_TYPES.keys())}"
            )

        return workflow_class(copilot_session)

    @classmethod
    def list_workflows(cls) -> list:
        """List available guided workflows."""
        return list(cls.WORKFLOW_TYPES.keys())
