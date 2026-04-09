# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.widgets.copilot_pane
==============================

Collapsible AI copilot side-pane for inline threat intelligence assistance.

Renders an :class:`Input` field where analysts can type questions.
Responses stream from :class:`~gnat.agents.llm.LLMClient` into a scrollable
:class:`Log` widget.

Usage::

    from gnat.tui.widgets.copilot_pane import CopilotPane
    from gnat.agents.llm import LLMClient

    yield CopilotPane(llm_client=LLMClient(backend="claude"))
"""

from __future__ import annotations

import threading
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Input, Label, Log, Static


class CopilotPane(Widget):
    """
    Collapsible AI copilot side-pane.

    Parameters
    ----------
    llm_client : LLMClient, optional
        When ``None``, responses display a "LLM not configured" message.
    system_prompt : str
        System prompt prepended to every user query.
    max_log_lines : int
        Maximum lines to keep in the response log.  Default ``500``.
    """

    DEFAULT_CSS = """
    CopilotPane {
        width: 40;
        height: 100%;
        border-left: solid $primary;
        background: $surface;
        layout: vertical;
        padding: 1;
        display: none;
    }
    CopilotPane.visible {
        display: block;
    }
    CopilotPane #pane-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    CopilotPane #response-log {
        height: 1fr;
        border: solid $panel;
        margin-bottom: 1;
    }
    CopilotPane #query-input {
        height: 3;
    }
    CopilotPane #status-line {
        height: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("ctrl+k", "toggle_pane", "Toggle Copilot", show=True),
    ]

    is_visible: reactive[bool] = reactive(False)
    is_loading: reactive[bool] = reactive(False)

    def __init__(
        self,
        llm_client:    Any = None,
        system_prompt: str = (
            "You are a threat intelligence analyst assistant. "
            "Provide concise, actionable answers grounded in STIX 2.1 concepts."
        ),
        max_log_lines: int = 500,
        **kwargs: Any,
    ) -> None:
        """Initialize CopilotPane."""
        super().__init__(**kwargs)
        self._llm          = llm_client
        self._system       = system_prompt
        self._max_lines    = max_log_lines

    def compose(self) -> ComposeResult:
        """Build copilot pane layout."""
        yield Static("🤖 AI Copilot", id="pane-title")
        yield Log(id="response-log", max_lines=self._max_lines, markup=False)
        yield Input(placeholder="Ask a threat intel question…", id="query-input")
        yield Label("", id="status-line")

    def on_mount(self) -> None:
        """Initial state — hidden by default."""
        if not self.is_visible:
            self.remove_class("visible")

    # ── Actions ──────────────────────────────────────────────────────────────────

    def action_toggle_pane(self) -> None:
        """Toggle the pane visibility."""
        self.is_visible = not self.is_visible

    def watch_is_visible(self, visible: bool) -> None:
        """Show or hide the pane."""
        if visible:
            self.add_class("visible")
            self.query_one("#query-input", Input).focus()
        else:
            self.remove_class("visible")

    def watch_is_loading(self, loading: bool) -> None:
        """Update status label."""
        label = self.query_one("#status-line", Label)
        label.update("⏳ Thinking…" if loading else "")

    # ── Input handling ────────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in the query input."""
        query = event.value.strip()
        if not query:
            return
        event.input.clear()
        self._submit_query(query)

    def _submit_query(self, query: str) -> None:
        """Submit query to LLM in a background thread to avoid blocking the UI."""
        log: Log = self.query_one("#response-log", Log)
        log.write_line(f"\n> {query}")

        if self._llm is None:
            log.write_line("⚠ LLM client not configured. Set up [claude] or [openai] in config.ini.")
            return

        self.is_loading = True

        def _run() -> None:
            try:
                buffer = ""
                try:
                    # Attempt streaming first
                    for chunk in self._llm.stream(
                        [{"role": "user", "content": query}],
                        system=self._system,
                    ):
                        buffer += chunk
                        self.call_from_thread(log.write, chunk)
                    self.call_from_thread(log.write_line, "")  # trailing newline
                except NotImplementedError:
                    # Fallback to non-streaming
                    response = self._llm.chat(
                        [{"role": "user", "content": query}],
                        system=self._system,
                    )
                    text = ""
                    if "content" in response:
                        for block in response.get("content", []):
                            if block.get("type") == "text":
                                text = block.get("text", "")
                                break
                    elif "choices" in response:
                        text = response["choices"][0].get("message", {}).get("content", "")
                    self.call_from_thread(log.write_line, text)

            except Exception as exc:
                self.call_from_thread(log.write_line, f"❌ Error: {exc}")
            finally:
                self.call_from_thread(setattr, self, "is_loading", False)

        threading.Thread(target=_run, name="copilot-query", daemon=True).start()
