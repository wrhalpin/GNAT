# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.screens.workflows
===========================

Workflow catalog and run history TUI screen.

Displays:
- Left panel: available workflows from :class:`~gnat.agents.catalog.WorkflowCatalog`
- Right panel: recent run history from :class:`~gnat.agents.workflow_store.WorkflowStore`
- Bottom bar: Trigger button, Ctrl+R refresh

Keybindings:
- ``Ctrl+R`` — refresh both panels
- ``Ctrl+T`` — trigger the selected workflow
- ``Escape``  — return to previous screen
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Static,
)


class WorkflowsScreen(Screen):
    """
    Workflow catalog and run history screen.

    Parameters
    ----------
    store : WorkflowStore, optional
        Run history store.  When ``None``, the history panel shows a
        "no store configured" message.
    """

    TITLE = "GNAT — Workflows"
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("ctrl+r", "refresh_all", "Refresh", show=True),
        Binding("ctrl+t", "trigger_selected", "Trigger", show=True),
    ]

    CSS = """
    WorkflowsScreen {
        layout: vertical;
    }
    #panels {
        layout: horizontal;
        height: 1fr;
    }
    #catalog-panel {
        width: 1fr;
        border: solid $primary;
        padding: 1;
        margin: 0 1 0 0;
    }
    #history-panel {
        width: 2fr;
        border: solid $primary;
        padding: 1;
    }
    #toolbar {
        height: 3;
        padding: 0 1;
        background: $panel;
    }
    .panel-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #status-label {
        padding: 0 1;
        height: 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        store: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize WorkflowsScreen."""
        super().__init__(**kwargs)
        self._store = store

    def compose(self) -> ComposeResult:
        """Build workflow screen layout."""
        yield Header()
        with Vertical():
            with Horizontal(id="toolbar"):
                yield Button("Refresh", id="refresh-btn")
                yield Button("Trigger", id="trigger-btn", variant="success")
            yield Label("", id="status-label")
            with Horizontal(id="panels"):
                with Vertical(id="catalog-panel"):
                    yield Static("Workflow Catalog", classes="panel-title")
                    yield DataTable(id="catalog-table", zebra_stripes=True)
                with Vertical(id="history-panel"):
                    yield Static("Recent Runs", classes="panel-title")
                    yield DataTable(id="history-table", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        """Populate tables on mount."""
        self._setup_catalog_table()
        self._setup_history_table()
        self._populate_catalog()
        self._populate_history()

    # ── Table setup ─────────────────────────────────────────────────────────────

    def _setup_catalog_table(self) -> None:
        table: DataTable = self.query_one("#catalog-table", DataTable)
        table.add_columns("Name", "Tags", "Description")

    def _setup_history_table(self) -> None:
        table: DataTable = self.query_one("#history-table", DataTable)
        table.add_columns("Run ID", "Workflow", "Status", "Steps", "Time (s)", "Started")

    # ── Data loading ─────────────────────────────────────────────────────────────

    def _populate_catalog(self) -> None:
        table: DataTable = self.query_one("#catalog-table", DataTable)
        table.clear()
        try:
            from gnat.agents.catalog import WorkflowCatalog
            for entry in WorkflowCatalog.list():
                tags = ", ".join(entry.tags)
                desc = entry.description[:60] + ("…" if len(entry.description) > 60 else "")
                table.add_row(entry.name, tags, desc)
        except Exception as exc:
            table.add_row("Error", "", str(exc)[:60])

    def _populate_history(self) -> None:
        table: DataTable = self.query_one("#history-table", DataTable)
        table.clear()
        if self._store is None:
            table.add_row("—", "No store configured", "", "", "", "")
            return
        try:
            records = self._store.list(limit=50)
            for r in records:
                run_id   = r.run_id[:8] + "…"
                status   = "✓" if r.status == "success" else "✗"
                steps    = f"{len(r.steps_completed)}/{len(r.steps_completed) + len(r.steps_failed)}"
                elapsed  = f"{r.elapsed_seconds:.1f}"
                started  = r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "—"
                table.add_row(run_id, r.workflow_name, status, steps, elapsed, started)
        except Exception as exc:
            table.add_row("Error", str(exc)[:60], "", "", "", "")

    # ── Actions ──────────────────────────────────────────────────────────────────

    def action_refresh_all(self) -> None:
        """Refresh both catalog and history panels."""
        self._populate_catalog()
        self._populate_history()
        self._set_status("Refreshed")

    def action_trigger_selected(self) -> None:
        """Trigger the selected catalog workflow."""
        table: DataTable = self.query_one("#catalog-table", DataTable)
        if table.cursor_row is None:
            self._set_status("Select a workflow first")
            return

        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        row_values = table.get_row(row_key)
        if not row_values:
            return
        name = str(row_values[0])
        self._trigger_workflow(name)

    def _trigger_workflow(self, name: str) -> None:
        """Fire-and-forget workflow trigger."""
        import threading

        def _run() -> None:
            try:
                from gnat.agents.catalog import WorkflowCatalog
                from gnat.agents.workflow import WorkflowContext
                wf  = WorkflowCatalog.build(name)
                ctx = WorkflowContext()
                result = wf.run(ctx)
                if self._store is not None:
                    self._store.save(result, workflow_name=name)
                self.call_from_thread(self._populate_history)
                self.call_from_thread(self._set_status, f"'{name}' completed (success={result.success})")
            except Exception as exc:
                self.call_from_thread(self._set_status, f"Trigger failed: {exc}")

        self._set_status(f"Running '{name}' …")
        threading.Thread(target=_run, name=f"trigger-{name}", daemon=True).start()

    def _set_status(self, msg: str) -> None:
        label: Label = self.query_one("#status-label", Label)
        label.update(msg)

    # ── Button handlers ───────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "refresh-btn":
            self.action_refresh_all()
        elif event.button.id == "trigger-btn":
            self.action_trigger_selected()
