# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.copilot_screen
==================================

TUI screen for Investigation Copilot (F10).
Multi-turn conversation interface with streaming responses.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Input, RichLog, Button
from textual.reactive import reactive
from rich.text import Text
from rich.panel import Panel
import asyncio

from gnat.agents import InvestigationCopilotSession, ConversationStore, AgentConfig


class CopilotStatus(Static):
    """Display copilot phase and investigation summary."""

    phase = reactive("IDLE")
    ioc_count = reactive(0)
    confidence = reactive(0.0)

    def render(self) -> str:
        """Render status bar."""
        status_text = f"Phase: {self.phase} | IOCs: {self.ioc_count} | Confidence: {self.confidence:.0%}"
        return Panel(status_text, expand=False)


class CopilotConversation(RichLog):
    """Scrollable conversation history with streaming support."""

    def __init__(self, name: str = None):
        super().__init__(markup=True, name=name)
        self.session = None

    def add_analyst_message(self, text: str) -> None:
        """Add analyst message to conversation."""
        self.write(Text(f"You: {text}", style="blue"))

    def add_copilot_message(self, text: str) -> None:
        """Add copilot message to conversation."""
        self.write(Text(f"Copilot: {text}", style="red"))

    def add_system_message(self, text: str) -> None:
        """Add system status message."""
        self.write(Text(f"[System] {text}", style="yellow"))

    async def stream_copilot_response(self, prompt: str) -> None:
        """Stream response tokens from copilot."""
        if not self.session:
            self.add_system_message("Session not initialized")
            return

        self.write(Text("Copilot: ", style="red"), end="")

        try:
            response = await self.session.ask_clarifying_question(prompt)
            self.write(Text(response, style="red"))
        except Exception as e:
            self.add_system_message(f"Error: {e}")


class CopilotInput(Input):
    """Input field for analyst messages."""

    def __init__(self, conversation: CopilotConversation, name: str = None):
        super().__init__(placeholder="Type your response or /help", name=name)
        self.conversation = conversation

    async def process_input(self, text: str) -> None:
        """Process user input and trigger copilot response."""
        if not text.strip():
            return

        if text.startswith("/"):
            await self._handle_command(text)
        else:
            self.conversation.add_analyst_message(text)
            await self.conversation.stream_copilot_response(text)

        self.value = ""

    async def _handle_command(self, cmd: str) -> None:
        """Handle slash commands."""
        if cmd == "/help":
            self.conversation.add_system_message(
                "Commands: /next (suggest next step), /close (end investigation), /help"
            )
        elif cmd == "/next":
            if self.conversation.session:
                suggestion = await self.conversation.session.suggest_next_step()
                self.conversation.add_system_message(
                    f"Next step: {suggestion.text}"
                )
        elif cmd == "/close":
            self.conversation.add_system_message("Investigation marked as closing phase")


class CopilotScreen(Container):
    """Main Investigation Copilot TUI screen."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("ctrl+c", "cancel_stream", "Cancel"),
    ]

    def __init__(self, investigation_id: str, name: str = None):
        super().__init__(name=name)
        self.investigation_id = investigation_id
        self.conversation_store = ConversationStore()
        self.agent_config = AgentConfig.from_ini()
        self.copilot_session = None

    def compose(self) -> ComposeResult:
        """Build screen layout."""
        yield Vertical(
            CopilotStatus(id="status"),
            CopilotConversation(id="history"),
            CopilotInput(
                conversation=self.query_one("#history", CopilotConversation),
                id="input"
            ),
        )

    def on_mount(self) -> None:
        """Initialize copilot session and display welcome."""
        try:
            session_ctx = self.conversation_store.create_session(
                analyst_id="current_user",  # TODO: Get from context
                investigation_id=self.investigation_id,
                agent_type="copilot",
            )
            self.copilot_session = InvestigationCopilotSession(
                conversation_id=session_ctx.conversation_id,
                config=self.agent_config,
                conversation_store=self.conversation_store,
            )

            history = self.query_one("#history", CopilotConversation)
            history.session = self.copilot_session
            history.add_system_message(
                "Investigation Copilot initialized. Let's begin. What do you know about this activity?"
            )

            # Set focus to input
            self.query_one("#input", CopilotInput).focus()

        except Exception as e:
            self.query_one("#history", CopilotConversation).add_system_message(
                f"Failed to initialize: {e}"
            )

    def action_dismiss(self) -> None:
        """Close the copilot screen."""
        self.app.pop_screen()

    def action_cancel_stream(self) -> None:
        """Cancel ongoing LLM streaming."""
        # TODO: Implement stream cancellation
        pass
