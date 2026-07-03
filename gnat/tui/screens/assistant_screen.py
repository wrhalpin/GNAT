# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.assistant_screen
====================================

TUI screen for Live Analyst Assistant (F11).
On-demand helper for enrichment, report drafting, explanation.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, RichLog, Static

from gnat.agents import AgentConfig, ConversationStore, LiveAnalystAssistantSession

# Color scheme
COLOR_ANALYST = "blue"
COLOR_ASSISTANT = "yellow"
COLOR_SUGGESTION = "green"


class AssistantPanel(RichLog):
    """Display area for assistant responses."""

    def add_user_query(self, text: str) -> None:
        line = Text("You: ", style=f"bold {COLOR_ANALYST}")
        line.append(text, style=COLOR_ANALYST)
        self.write(line)

    def add_assistant_response(self, text: str) -> None:
        line = Text("Assistant: ", style=f"bold {COLOR_ASSISTANT}")
        line.append(text, style=COLOR_ASSISTANT)
        self.write(line)

    def add_suggestion(self, title: str, content: str) -> None:
        self.write(Panel(content, title=title, border_style=COLOR_SUGGESTION, title_align="left"))


class AssistantScreen(ModalScreen):
    """Live Analyst Assistant modal screen (F11)."""

    BINDINGS = [
        ("escape", "dismiss_screen", "Close"),
        ("f1", "show_help", "Help"),
    ]

    CSS = """
    AssistantScreen {
        align: center middle;
    }

    #assistant-body {
        width: 90%;
        height: 90%;
        background: $surface;
        border: heavy $accent;
    }

    #header {
        height: 1;
        padding: 0 1;
    }

    #response {
        height: 1fr;
        border: heavy $panel;
    }

    #input {
        border: heavy $accent;
    }
    """

    def __init__(self, investigation_id: str, name: str | None = None):
        super().__init__(name=name)
        self.investigation_id = investigation_id
        self.assistant_session = None
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Live Analyst Assistant — F1 for help", id="header"),
            AssistantPanel(id="response"),
            Input(placeholder="Ask a question or /enrich /draft /explain", id="input"),
            id="assistant-body",
        )

    def on_mount(self) -> None:
        """Initialize assistant session."""
        panel = self.query_one("#response", AssistantPanel)
        try:
            store = ConversationStore()
            session_ctx = store.create_session(
                analyst_id="current_user",  # TODO: thread analyst identity from app
                investigation_id=self.investigation_id,
                agent_type="assistant",
            )
            self.assistant_session = LiveAnalystAssistantSession(
                conversation_id=session_ctx.conversation_id,
                config=AgentConfig.from_ini(),
                conversation_store=store,
            )
            panel.add_assistant_response(
                "Ready to help. Commands: /enrich, /draft, /explain <type>:<value>, "
                "or just ask a question for search help."
            )
        except Exception as e:
            panel.add_assistant_response(f"Failed to initialize: {e}")

        self.query_one("#input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Process an analyst query."""
        text = event.value.strip()
        event.input.value = ""
        if not text or self._busy:
            return

        panel = self.query_one("#response", AssistantPanel)
        panel.add_user_query(text)

        if text == "/help":
            self.action_show_help()
            return

        if not self.assistant_session:
            panel.add_assistant_response("Session not initialized")
            return

        self._busy = True
        try:
            if text.startswith("/enrich"):
                await self._handle_enrichment(panel)
            elif text.startswith("/draft"):
                await self._handle_draft(panel)
            elif text.startswith("/explain"):
                await self._handle_explanation(text, panel)
            else:
                await self._handle_search(text, panel)
        except Exception as e:
            panel.add_assistant_response(f"Error: {e}")
        finally:
            self._busy = False

    async def _handle_enrichment(self, panel: AssistantPanel) -> None:
        """Get enrichment suggestions."""
        # TODO: Get current STIX object from investigation context
        from gnat.orm import Indicator

        stix_obj = Indicator(pattern="[ipv4-addr:value = '1.2.3.4']", pattern_type="stix")

        async for suggestion in self.assistant_session.suggest_enrichment(stix_obj):
            panel.add_suggestion(
                title=suggestion.connector_name,
                content=f"{suggestion.reason}\nEst. {suggestion.estimated_duration_sec}s",
            )

    async def _handle_draft(self, panel: AssistantPanel) -> None:
        """Draft a report section."""
        options = await self.assistant_session.draft_report_section(
            section_type="findings",
            investigation_context={},  # TODO: populate from investigation
        )
        for i, option in enumerate(options, 1):
            panel.add_suggestion(title=f"Option {i} ({option.tone})", content=option.text)

    async def _handle_explanation(self, text: str, panel: AssistantPanel) -> None:
        """Explain a finding. Usage: /explain <stix-type>:<value>"""
        _, _, spec = text.partition(" ")
        stix_type, sep, value = spec.partition(":")
        if not sep or not stix_type or not value:
            panel.add_assistant_response("Usage: /explain <stix-type>:<value>")
            return

        from gnat.orm import Indicator

        stix_obj = Indicator(pattern=f"[{stix_type}:value = '{value}']", pattern_type="stix")

        response_text = ""
        async for token in self.assistant_session.explain_finding(stix_obj, {}):
            response_text += token
        panel.add_assistant_response(response_text)

    async def _handle_search(self, query: str, panel: AssistantPanel) -> None:
        """Get search routing help."""
        response_text = ""
        async for token in self.assistant_session.search_help(query):
            response_text += token
        panel.add_assistant_response(response_text)

    def action_dismiss_screen(self) -> None:
        """Close the assistant screen."""
        self.app.pop_screen()

    def action_show_help(self) -> None:
        """Show assistant help."""
        panel = self.query_one("#response", AssistantPanel)
        panel.add_assistant_response(
            "Commands:\n"
            "  /enrich — Get enrichment connector suggestions\n"
            "  /draft — Draft report section\n"
            "  /explain <type>:<value> — Explain a STIX object\n"
            "  Or just ask a question for search routing help\n"
            "Examples:\n"
            "  /explain ipv4-addr:1.2.3.4\n"
            "  Find APT29 infrastructure\n"
            "Keybindings:\n"
            "  Escape — Close assistant\n"
            "  F1 — Show this help"
        )
