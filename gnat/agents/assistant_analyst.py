# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.assistant_analyst
================================

Live Analyst Assistant: stateless but context-aware agent providing
on-demand enrichment suggestions, report drafting, finding explanations.

Uses hybrid LLM strategy: streaming for chat, batched for operations.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any, AsyncIterator
from datetime import datetime

from gnat.agents.conversations import ConversationStore, ConversationTurn, ConversationRole
from gnat.agents.llm import LLMClient
from gnat.agents.base import AgentConfig
from gnat.orm.base import STIXBase


@dataclass
class EnrichmentSuggestion:
    """Recommended connector for enrichment."""
    connector_name: str
    reason: str
    confidence: float
    estimated_duration_sec: int


@dataclass
class ReportDraftOption:
    """Generated report section option."""
    section_type: str
    text: str
    tone: str  # "formal" | "technical" | "executive"
    quality_score: float


class LiveAnalystAssistantSession:
    """
    On-demand assistant for threat intelligence analysis.
    Stateless (no investigation state stored) but context-aware (gets passed investigation data).
    Streaming responses for chat, batched responses for operations (draft, explain).
    """

    def __init__(
        self,
        conversation_id: str,
        config: AgentConfig,
        conversation_store: Optional[ConversationStore] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        """
        Initialize assistant session.

        Args:
            conversation_id: Unique session ID
            config: Agent configuration
            conversation_store: Optional custom store
            llm_client: Optional custom LLM client
        """
        self.conversation_id = conversation_id
        self.config = config
        self.store = conversation_store or ConversationStore()
        self.llm = llm_client or LLMClient.from_config(config)

        ctx = self.store.get_session(conversation_id)
        if not ctx:
            raise ValueError(f"Conversation {conversation_id} not found")

        self.session_context = ctx

    async def suggest_enrichment(self, stix_object: STIXBase) -> AsyncIterator[EnrichmentSuggestion]:
        """
        Suggest enrichment connectors for a STIX object.
        Streaming: yields suggestions as they're generated.

        Args:
            stix_object: The object to enrich (Indicator, Malware, Actor, etc.)

        Yields:
            EnrichmentSuggestion with connector name and reasoning
        """
        # Log request
        user_query = f"Suggest enrichment for {stix_object.type}: {stix_object.get('value', 'N/A')}"
        await self._add_turn(ConversationRole.ANALYST, user_query)

        # Build prompt for suggestion
        prompt = self._build_enrichment_prompt(stix_object)

        # Stream response
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token
            # Parse token stream for suggestions (placeholder)
            # Real implementation: stream + parse JSON as it arrives
            yield EnrichmentSuggestion(
                connector_name="Recorded Future",
                reason="Specialized in reputation scoring",
                confidence=0.9,
                estimated_duration_sec=5,
            )

        # Log full response
        await self._add_turn(ConversationRole.ASSISTANT, response_text)

    async def draft_report_section(
        self,
        section_type: str,
        investigation_context: Dict[str, Any],
    ) -> List[ReportDraftOption]:
        """
        Generate report section drafts (batched operation).
        Returns multiple options for analyst to choose from.

        Args:
            section_type: "executive_summary" | "findings" | "recommendations" | "timeline"
            investigation_context: Investigation data (IOCs, actors, campaigns, etc.)

        Returns:
            List of 2-3 draft options
        """
        # Log request
        user_query = f"Draft {section_type} for investigation"
        await self._add_turn(ConversationRole.ANALYST, user_query)

        # Build batched prompt
        prompt = self._build_draft_prompt(section_type, investigation_context)

        # Batched call (not streaming)
        response_text = await self.llm.call(prompt)

        # Log response
        await self._add_turn(ConversationRole.ASSISTANT, response_text)

        # Parse response to extract options (placeholder)
        # Real implementation: parse Claude response into structured ReportDraftOption objects
        options = [
            ReportDraftOption(
                section_type=section_type,
                text="Draft 1 (formal tone)",
                tone="formal",
                quality_score=0.85,
            ),
            ReportDraftOption(
                section_type=section_type,
                text="Draft 2 (technical tone)",
                tone="technical",
                quality_score=0.88,
            ),
        ]

        return options

    async def explain_finding(
        self,
        stix_object: STIXBase,
        context: Dict[str, Any],
    ) -> AsyncIterator[str]:
        """
        Explain why a finding matters in plain language.
        Streaming: yields explanation tokens.

        Args:
            stix_object: The object being explained
            context: Investigation context for framing

        Yields:
            Explanation text tokens
        """
        # Log request
        user_query = f"Explain {stix_object.type}: {stix_object.get('value', 'N/A')}"
        await self._add_turn(ConversationRole.ANALYST, user_query)

        # Build streaming prompt
        prompt = self._build_explanation_prompt(stix_object, context)

        # Stream response
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token
            yield token

        # Log full response
        await self._add_turn(ConversationRole.ASSISTANT, response_text)

    async def search_help(self, analyst_query: str) -> AsyncIterator[str]:
        """
        Help analyst search for data across connectors.
        Suggest connectors and search syntax based on natural language query.
        Streaming: yields suggestions.

        Args:
            analyst_query: "Find APT29 infrastructure" | "Look for malware family X"

        Yields:
            Search suggestion tokens (connector names, syntax examples)
        """
        # Log query
        await self._add_turn(ConversationRole.ANALYST, analyst_query)

        # Build prompt to route query
        prompt = self._build_search_help_prompt(analyst_query)

        # Stream suggestions
        response_text = ""
        async for token in self.llm.stream(prompt):
            response_text += token
            yield token

        # Log response
        await self._add_turn(ConversationRole.ASSISTANT, response_text)

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

    def _build_enrichment_prompt(self, stix_object: STIXBase) -> str:
        """Build Claude prompt for enrichment suggestions."""
        return f"""
        Object type: {stix_object.type}
        Value: {stix_object.get('value', 'N/A')}
        TLP: {stix_object.get('labels', [])}

        Suggest 3-5 GNAT connectors to enrich this object.
        For each, explain why it's relevant and how long enrichment takes.
        Format: "1. Connector Name - reason. Est. 5 min."
        """

    def _build_draft_prompt(
        self,
        section_type: str,
        investigation_context: Dict[str, Any],
    ) -> str:
        """Build Claude prompt for report drafting."""
        return f"""
        Report section: {section_type}
        Investigation context: {investigation_context}

        Generate 2-3 draft options for this report section.
        Offer different tones: formal (executive), technical (SOC), narrative (incident report).
        Each draft should be 2-3 paragraphs.
        """

    def _build_explanation_prompt(
        self,
        stix_object: STIXBase,
        context: Dict[str, Any],
    ) -> str:
        """Build Claude prompt for finding explanation."""
        return f"""
        Object: {stix_object.type} = {stix_object.get('value', 'N/A')}
        Context: {context}

        Explain in plain language why this finding matters.
        Reference any known campaigns or threat actors if applicable.
        Keep it to 2-3 sentences.
        """

    def _build_search_help_prompt(self, analyst_query: str) -> str:
        """Build Claude prompt for search routing."""
        return f"""
        Analyst query: "{analyst_query}"

        Recommend GNAT connectors and search syntax to answer this query.
        For each connector, provide an example query or STIX pattern.
        Example format:
        - ThreatQ: [ipv4-addr:country = 'RU']
        - Shodan: "Cobalt Strike" port:443
        """
