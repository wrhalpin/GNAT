# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.copilot_screen
==================================

TUI screen for Investigation Copilot (F10).
Multi-turn conversation interface.
"""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, RichLog, Static

from gnat.agents import AgentConfig, ConversationStore, InvestigationCopilotSession

# Color scheme
COLOR_ANALYST = "blue"
COLOR_COPILOT = "red"
COLOR_SYSTEM = "yellow"


class CopilotStatus(Static):
    """Display copilot phase and investigation summary."""

    phase = reactive("IDLE")
    ioc_count = reactive(0)
    confidence = reactive(0.0)

    def render(self) -> str:
        return f"Phase: {self.phase} | IOCs: {self.ioc_count} | Confidence: {self.confidence:.0%}"


class CopilotConversation(RichLog):
    """Scrollable conversation history."""

    def add_analyst_message(self, text: str) -> None:
        line = Text("You: ", style=f"bold {COLOR_ANALYST}")
        line.append(text, style=COLOR_ANALYST)
        self.write(line)

    def add_copilot_message(self, text: str) -> None:
        line = Text("Copilot: ", style=f"bold {COLOR_COPILOT}")
        line.append(text, style=COLOR_COPILOT)
        self.write(line)

    def add_system_message(self, text: str) -> None:
        self.write(Text(f"[System] {text}", style=f"dim {COLOR_SYSTEM}"))


class CopilotScreen(ModalScreen):
    """Investigation Copilot modal screen (F10)."""

    BINDINGS = [
        ("escape", "dismiss_screen", "Close"),
        ("f1", "show_help", "Help"),
    ]

    CSS = """
    CopilotScreen {
        align: center middle;
    }

    #copilot-body {
        width: 90%;
        height: 90%;
        background: $surface;
        border: heavy $accent;
    }

    #status {
        height: 1;
        padding: 0 1;
    }

    #history {
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
        self.copilot_session = None
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Vertical(
            CopilotStatus(id="status"),
            CopilotConversation(id="history"),
            Input(placeholder="Type your response or /help (Esc to close)", id="input"),
            id="copilot-body",
        )

    def on_mount(self) -> None:
        """Initialize copilot session and display welcome."""
        history = self.query_one("#history", CopilotConversation)
        try:
            store = ConversationStore()
            session_ctx = store.create_session(
                analyst_id="current_user",  # TODO: thread analyst identity from app
                investigation_id=self.investigation_id,
                agent_type="copilot",
            )
            self.copilot_session = InvestigationCopilotSession(
                conversation_id=session_ctx.conversation_id,
                config=AgentConfig.from_ini(),
                conversation_store=store,
            )
            history.add_system_message(
                "Investigation Copilot initialized. What do you know about this activity?"
            )
        except Exception as e:
            history.add_system_message(f"Failed to initialize: {e}")

        self.query_one("#input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle a submitted analyst message."""
        text = event.value.strip()
        event.input.value = ""
        if not text or self._busy:
            return

        history = self.query_one("#history", CopilotConversation)

        if text.startswith("/"):
            await self._handle_command(text, history)
            return

        history.add_analyst_message(text)

        if not self.copilot_session:
            history.add_system_message("Session not initialized")
            return

        self._busy = True
        try:
            response = await self.copilot_session.ask_clarifying_question(text)
            history.add_copilot_message(response)
        except Exception as e:
            history.add_system_message(f"Error: {e}")
        finally:
            self._busy = False

    async def _handle_command(self, cmd: str, history: CopilotConversation) -> None:
        """Handle slash commands."""
        if cmd == "/help":
            self.action_show_help()
        elif cmd == "/next":
            if not self.copilot_session:
                history.add_system_message("Session not initialized")
                return
            try:
                suggestion = await self.copilot_session.suggest_next_step()
                history.add_system_message(f"Next step: {suggestion.text}")
            except Exception as e:
                history.add_system_message(f"Error: {e}")
        elif cmd == "/close":
            history.add_system_message("Investigation marked as closing phase")
        else:
            history.add_system_message(f"Unknown command: {cmd} (try /help)")

    def action_dismiss_screen(self) -> None:
        """Close the copilot screen."""
        self.app.pop_screen()

    def action_show_help(self) -> None:
        """Show copilot help."""
        history = self.query_one("#history", CopilotConversation)
        history.add_system_message(
            "Commands:\n"
            "  /next — Suggest next investigation step\n"
            "  /close — Mark investigation as closing\n"
            "  /help — Show this help\n"
            "Keybindings:\n"
            "  Escape — Close copilot\n"
            "  F1 — Show this help"
        )
