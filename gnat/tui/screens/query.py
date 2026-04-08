# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.query
========================
NLP query screen — type a natural-language threat-intel query and view
matching STIX objects in a scrollable table.

If the ``[nlp]`` backend is not configured (no Claude API key, no config),
the screen degrades gracefully to the ``builtin`` regex parser.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label

from gnat.tui.widgets.stix_table import STIXTable

_HELP = (
    "Examples: 'IPs related to APT28 since last 30 days'  ·  "
    "'domains from Cobalt Strike campaigns'  ·  "
    "'CVE-2024-1234 vulnerabilities'"
)


class QueryScreen(Screen):
    """Interactive NLP threat-intel query screen."""

    TITLE = "GNAT — NLP Query"
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("ctrl+l", "clear_results", "Clear", show=True),
    ]

    CSS = """
    QueryScreen {
        layout: vertical;
    }
    #query-bar {
        height: 3;
        padding: 0 1;
        background: $panel;
    }
    #query-input {
        width: 1fr;
    }
    #query-btn {
        width: 12;
    }
    #help-label {
        color: $text-muted;
        padding: 0 1;
        height: 1;
    }
    #status-label {
        padding: 0 1;
        height: 1;
        color: $success;
    }
    #results-table {
        height: 1fr;
    }
    """

    def __init__(
        self,
        config_path: str | None = None,
        platform: str | None = None,
        backend: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize QueryScreen."""
        super().__init__(**kwargs)
        self._config_path = config_path
        self._platform = platform
        self._backend = backend
        self._engine = None

    def compose(self) -> ComposeResult:
        """Build and return the QueryScreen."""
        yield Header()
        with Vertical():
            with Horizontal(id="query-bar"):
                yield Input(
                    placeholder="Natural-language query…",
                    id="query-input",
                )
                yield Button("Search", variant="primary", id="query-btn")
            yield Label(_HELP, id="help-label")
            yield Label("", id="status-label")
            yield STIXTable(id="results-table")
        yield Footer()

    def on_mount(self) -> None:
        """Initialise the NLP engine (non-blocking: uses builtin parser by default)."""
        self._engine = self._build_engine()
        self.query_one("#query-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the button pressed event."""
        if event.button.id == "query-btn":
            self._run_query()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle the input submitted event."""
        self._run_query()

    def action_clear_results(self) -> None:
        """Action clear results."""
        self.query_one(STIXTable).clear()
        self.query_one("#status-label", Label).update("")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_query(self) -> None:
        """Internal helper for run query."""
        inp = self.query_one("#query-input", Input)
        status = self.query_one("#status-label", Label)
        table = self.query_one(STIXTable)
        query = inp.value.strip()
        if not query:
            return

        status.update("Searching…")
        try:
            results = self._engine.query(query) if self._engine else []
        except Exception as exc:
            status.update(f"[red]Error: {exc}[/red]")
            return

        table.load_stix(results)
        n = len(results)
        status.update(f"[green]{n} result{'s' if n != 1 else ''}[/green] for: {query[:60]}")

    def _build_engine(self):
        """Internal helper for build engine."""
        try:
            from gnat.nlp.parser import NLPQueryEngine

            if self._config_path:
                from gnat.config import GNATConfig

                cfg = GNATConfig(self._config_path)
                engine = NLPQueryEngine.from_config(cfg)
            else:
                backend = self._backend or "builtin"
                engine = NLPQueryEngine(backend=backend)
            return engine
        except Exception:
            return None
