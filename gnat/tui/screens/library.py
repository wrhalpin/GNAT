# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.library
==========================
Research library browser screen.

Allows analysts to search the curated library and staging area, view
STIX object details, and promote or reject staging entries.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label

_STAGING_HELP = "Staging entries await promotion to the curated library."


class LibraryScreen(Screen):
    """Research library browser — search, filter, promote/reject staging entries."""

    TITLE = "GNAT — Research Library"
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("ctrl+r", "refresh", "Refresh", show=True),
        Binding("ctrl+p", "promote_entry", "Promote", show=True),
        Binding("ctrl+x", "reject_entry", "Reject", show=True),
    ]

    CSS = """
    LibraryScreen {
        layout: vertical;
    }
    #search-bar {
        height: 3;
        padding: 0 1;
        background: $panel;
    }
    #search-input {
        width: 1fr;
    }
    #tab-bar {
        height: 3;
        padding: 0 1;
    }
    #lib-btn {
        width: 16;
    }
    #staging-btn {
        width: 18;
    }
    #status-label {
        padding: 0 1;
        height: 1;
        color: $success;
    }
    #library-table {
        height: 1fr;
    }
    """

    def __init__(
        self,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize LibraryScreen."""
        super().__init__(**kwargs)
        self._config_path = config_path
        self._library = None
        self._mode = "library"  # "library" | "staging"

    def compose(self) -> ComposeResult:
        """Build and return the LibraryScreen."""
        yield Header()
        with Vertical():
            with Horizontal(id="search-bar"):
                yield Input(
                    placeholder="Search topics, tags, researcher…",
                    id="search-input",
                )
                yield Button("Search", variant="primary", id="search-btn")
            with Horizontal(id="tab-bar"):
                yield Button("Library", variant="success", id="lib-btn")
                yield Button("Staging Queue", variant="warning", id="staging-btn")
                yield Button("Refresh", id="refresh-btn")
            yield Label("", id="status-label")
            yield DataTable(id="library-table", zebra_stripes=True, cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        """Handle the mount event."""
        self._setup_table()
        self._library = self._build_library()
        self._load_library()
        self.query_one("#search-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the button pressed event."""
        btn = event.button.id
        if btn == "search-btn":
            self._run_search()
        elif btn == "lib-btn":
            self._mode = "library"
            self._load_library()
        elif btn == "staging-btn":
            self._mode = "staging"
            self._load_staging()
        elif btn == "refresh-btn":
            self.action_refresh()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle the input submitted event."""
        self._run_search()

    def action_refresh(self) -> None:
        """Action refresh."""
        if self._mode == "staging":
            self._load_staging()
        else:
            self._load_library()

    def action_promote_entry(self) -> None:
        """Promote the selected staging entry to the curated library."""
        if self._mode != "staging" or self._library is None:
            return
        topic = self._selected_topic()
        if not topic:
            return
        try:
            # promote() requires a workspace; here we just move by topic key
            _ = self._library._manager  # ensure connected
            status = self.query_one("#status-label", Label)
            status.update(
                f"[yellow]Promotion requires a workspace — use CLI: gnat research promote {topic}[/yellow]"
            )
        except Exception as exc:
            self.query_one("#status-label", Label).update(f"[red]{exc}[/red]")

    def action_reject_entry(self) -> None:
        """Remove the selected staging entry."""
        if self._mode != "staging" or self._library is None:
            return
        topic = self._selected_topic()
        if not topic:
            return
        try:
            self._library.reject(topic)
            self._load_staging()
            self.query_one("#status-label", Label).update(f"[green]Rejected '{topic}'[/green]")
        except Exception as exc:
            self.query_one("#status-label", Label).update(f"[red]{exc}[/red]")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _setup_table(self) -> None:
        """Internal helper for setup table."""
        table: DataTable = self.query_one("#library-table", DataTable)
        table.add_column("Topic", key="topic", width=28)
        table.add_column("TLP", key="tlp", width=8)
        table.add_column("Researcher", key="researcher", width=20)
        table.add_column("Date", key="date", width=20)
        table.add_column("Objects", key="objects", width=8)
        table.add_column("Status", key="status", width=14)

    def _build_library(self):
        """Internal helper for build library."""
        try:
            from gnat.research.library import ResearchLibrary

            return ResearchLibrary.default(config_path=self._config_path)
        except Exception:
            return None

    def _load_library(self) -> None:
        """Internal helper for load library."""
        table = self.query_one("#library-table", DataTable)
        status = self.query_one("#status-label", Label)
        table.clear()
        if self._library is None:
            status.update("[yellow]Research library not configured.[/yellow]")
            return
        try:
            entries = self._library.list_entries()
            for e in entries:
                table.add_row(
                    e.get("topic", ""),
                    e.get("tlp", ""),
                    e.get("researcher", ""),
                    str(e.get("promoted_at", ""))[:19],
                    str(e.get("stix_count", 0)),
                    "curated",
                )
            status.update(f"[green]{len(entries)} library entries[/green]")
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")

    def _load_staging(self) -> None:
        """Internal helper for load staging."""
        table = self.query_one("#library-table", DataTable)
        status = self.query_one("#status-label", Label)
        table.clear()
        if self._library is None:
            status.update("[yellow]Research library not configured.[/yellow]")
            return
        try:
            entries = self._library.list_staging()
            for e in entries:
                table.add_row(
                    e.get("topic", ""),
                    e.get("tlp", "white"),
                    e.get("researcher", ""),
                    str(e.get("created_at", ""))[:19],
                    str(e.get("stix_count", 0)),
                    "staging",
                )
            status.update(
                f"[yellow]{len(entries)} staging entries[/yellow]  "
                f"Ctrl+P to promote · Ctrl+X to reject"
            )
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")

    def _run_search(self) -> None:
        """Internal helper for run search."""
        query = self.query_one("#search-input", Input).value.strip()
        status = self.query_one("#status-label", Label)
        table = self.query_one("#library-table", DataTable)
        if not query or self._library is None:
            return
        try:
            results = self._library.search(query)
            table.clear()
            for e in results:
                table.add_row(
                    e.get("topic", ""),
                    e.get("tlp", ""),
                    e.get("researcher", ""),
                    str(e.get("promoted_at", ""))[:19],
                    str(e.get("stix_count", 0)),
                    "curated",
                )
            status.update(f"[green]{len(results)} results for '{query}'[/green]")
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")

    def _selected_topic(self) -> str | None:
        """Internal helper for selected topic."""
        table: DataTable = self.query_one("#library-table", DataTable)
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            return str(table.get_cell(row_key, "topic"))
        except Exception:
            return None
