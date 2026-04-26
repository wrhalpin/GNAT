# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.assistant_screen
====================================

TUI screen for Live Analyst Assistant (F11).
On-demand helper for enrichment, report drafting, explanation.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, Tabs, TabPane
from textual.widgets import Static, Input, RichLog, Button
from textual.reactive import reactive
from rich.text import Text
from rich.panel import Panel

from gnat.agents import LiveAnalystAssistantSession, ConversationStore, AgentConfig


class AssistantPanel(RichLog):
    """Display area for assistant responses."""

    def __init__(self, name: str = None):
        super().__init__(markup=True, name=name)
        self.session = None

    def add_user_query(self, text: str) -> None:
        """Log user query."""
        self.write(Text(f"You: {text}", style="blue"))

    def add_assistant_response(self, text: str) -> None:
        """Log assistant response."""
        self.write(Text(f"Assistant: {text}", style="yellow"))

    def add_suggestion(self, title: str, content: str) -> None:
        """Add a formatted suggestion."""
        self.write(Panel(content, title=title))


class AssistantInput(Input):
    """Input field for assistant queries."""

    def __init__(self, panel: AssistantPanel, name: str = None):
        super().__init__(placeholder="Ask assistant a question", name=name)
        self.panel = panel

    async def process_input(self, text: str) -> None:
        """Process query."""
        if not text.strip():
            return

        self.panel.add_user_query(text)

        if text.startswith("/enrich"):
            await self._handle_enrichment()
        elif text.startswith("/draft"):
            await self._handle_draft()
        elif text.startswith("/explain"):
            await self._handle_explanation(text)
        else:
            await self._handle_search(text)

        self.value = ""

    async def _handle_enrichment(self) -> None:
        """Get enrichment suggestions."""
        if not self.panel.session:
            self.panel.add_assistant_response("Session not initialized")
            return

        # TODO: Get current STIX object from context
        from gnat.orm import Indicator
        stix_obj = Indicator(pattern="[ipv4-addr:value = '1.2.3.4']", pattern_type="stix")

        try:
            suggestions = []
            async for suggestion in self.panel.session.suggest_enrichment(stix_obj):
                suggestions.append(suggestion)
                self.panel.add_suggestion(
                    title=suggestion.connector_name,
                    content=f"{suggestion.reason}\nEst. {suggestion.estimated_duration_sec}s"
                )
        except Exception as e:
            self.panel.add_assistant_response(f"Error: {e}")

    async def _handle_draft(self) -> None:
        """Draft a report section."""
        if not self.panel.session:
            self.panel.add_assistant_response("Session not initialized")
            return

        try:
            options = await self.panel.session.draft_report_section(
                section_type="findings",
                investigation_context={},  # TODO: Get from context
            )

            for i, option in enumerate(options, 1):
                self.panel.add_suggestion(
                    title=f"Option {i} ({option.tone})",
                    content=option.text
                )
        except Exception as e:
            self.panel.add_assistant_response(f"Error: {e}")

    async def _handle_explanation(self, text: str) -> None:
        """Explain a finding."""
        if not self.panel.session:
            self.panel.add_assistant_response("Session not initialized")
            return

        # Parse: /explain ipv4-addr:1.2.3.4
        parts = text.split(":")
        if len(parts) < 2:
            self.panel.add_assistant_response("Usage: /explain <stix-type>:<value>")
            return

        try:
            from gnat.orm import Indicator
            stix_obj = Indicator(
                pattern=f"[{parts[0]}:value = '{parts[1]}']",
                pattern_type="stix"
            )

            response_text = ""
            async for token in self.panel.session.explain_finding(stix_obj, {}):
                response_text += token
                # Could yield token-by-token for streaming, but for simplicity buffer

            self.panel.add_assistant_response(response_text)
        except Exception as e:
            self.panel.add_assistant_response(f"Error: {e}")

    async def _handle_search(self, query: str) -> None:
        """Get search routing help."""
        if not self.panel.session:
            self.panel.add_assistant_response("Session not initialized")
            return

        try:
            response_text = ""
            async for token in self.panel.session.search_help(query):
                response_text += token

            self.panel.add_assistant_response(response_text)
        except Exception as e:
            self.panel.add_assistant_response(f"Error: {e}")


class AssistantScreen(Container):
    """Live Analyst Assistant TUI screen."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
    ]

    def __init__(self, investigation_id: str, name: str = None):
        super().__init__(name=name)
        self.investigation_id = investigation_id
        self.conversation_store = ConversationStore()
        self.agent_config = AgentConfig.from_ini()
        self.assistant_session = None

    def compose(self) -> ComposeResult:
        """Build screen layout."""
        panel = AssistantPanel(id="response")

        yield Vertical(
            Static("Live Analyst Assistant — /help for commands", id="header"),
            panel,
            AssistantInput(panel=panel, id="input"),
        )

    def on_mount(self) -> None:
        """Initialize assistant session."""
        try:
            session_ctx = self.conversation_store.create_session(
                analyst_id="current_user",  # TODO: Get from context
                investigation_id=self.investigation_id,
                agent_type="assistant",
            )
            self.assistant_session = LiveAnalystAssistantSession(
                conversation_id=session_ctx.conversation_id,
                config=self.agent_config,
                conversation_store=self.conversation_store,
            )

            panel = self.query_one("#response", AssistantPanel)
            panel.session = self.assistant_session
            panel.add_assistant_response(
                "Ready to help. Commands: /enrich (suggest enrichment), "
                "/draft (draft section), /explain <type>:<value> (explain finding), "
                "or just ask a question for search help."
            )

            # Set focus to input
            self.query_one("#input", AssistantInput).focus()

        except Exception as e:
            self.query_one("#response", AssistantPanel).add_assistant_response(
                f"Failed to initialize: {e}"
            )

    def action_dismiss(self) -> None:
        """Close the assistant screen."""
        self.app.pop_screen()
