"""
gnat.tui.screens.scheduler
============================
Scheduler status and control screen.

Displays a live-updating table of feed jobs with their last/next run times,
run counts, and status.  Supports manual job triggering.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label

from gnat.tui.widgets.job_table import JobTable

_NO_SCHED_MSG = (
    "No scheduler available.  "
    "Start GNAT with a scheduler instance to see job status."
)


class SchedulerScreen(Screen):
    """Live scheduler status view with manual trigger support."""

    TITLE   = "GNAT — Scheduler"
    BINDINGS = [
        Binding("escape",  "app.pop_screen",    "Back",    show=True),
        Binding("ctrl+r",  "refresh",           "Refresh", show=True),
        Binding("ctrl+t",  "trigger_selected",  "Trigger", show=True),
    ]

    CSS = """
    SchedulerScreen {
        layout: vertical;
    }
    #toolbar {
        height: 3;
        padding: 0 1;
        background: $panel;
    }
    #status-label {
        padding: 0 1;
        height: 1;
        color: $text-muted;
    }
    #job-table {
        height: 1fr;
    }
    """

    def __init__(
        self,
        scheduler=None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._scheduler  = scheduler
        self._config_path = config_path

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            with Horizontal(id="toolbar"):
                yield Button("Refresh",        id="refresh-btn")
                yield Button("Trigger Job",    id="trigger-btn",  variant="warning")
                yield Button("Toggle Enable",  id="toggle-btn")
            yield Label("", id="status-label")
            yield JobTable(id="job-table")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_jobs()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "refresh-btn":
            self.action_refresh()
        elif btn == "trigger-btn":
            self.action_trigger_selected()
        elif btn == "toggle-btn":
            self._toggle_selected()

    def action_refresh(self) -> None:
        self._refresh_jobs()

    def action_trigger_selected(self) -> None:
        """Manually execute the currently selected job in a background thread."""
        sched  = self._scheduler
        status = self.query_one("#status-label", Label)
        if sched is None:
            status.update("[yellow]No scheduler connected.[/yellow]")
            return
        table  = self.query_one(JobTable)
        job_id = table.selected_job_id()
        if not job_id:
            status.update("[yellow]Select a job row first.[/yellow]")
            return
        try:
            job = sched.get(job_id)
            import threading
            t = threading.Thread(target=job.execute, daemon=True)
            t.start()
            status.update(f"[green]Triggered '{job_id}' in background.[/green]")
        except Exception as exc:
            status.update(f"[red]Trigger failed: {exc}[/red]")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _refresh_jobs(self) -> None:
        sched  = self._scheduler
        table  = self.query_one(JobTable)
        status = self.query_one("#status-label", Label)
        if sched is None:
            status.update(f"[yellow]{_NO_SCHED_MSG}[/yellow]")
            table.clear()
            return
        try:
            jobs = sched.status_summary()
            table.load_jobs(jobs)
            n = len(jobs)
            status.update(
                f"[green]{n} job{'s' if n != 1 else ''}[/green]  "
                f"Ctrl+T to trigger · Ctrl+R to refresh"
            )
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")

    def _toggle_selected(self) -> None:
        sched  = self._scheduler
        status = self.query_one("#status-label", Label)
        if sched is None:
            return
        table  = self.query_one(JobTable)
        job_id = table.selected_job_id()
        if not job_id:
            return
        try:
            job = sched.get(job_id)
            job.enabled = not job.enabled
            state = "enabled" if job.enabled else "disabled"
            status.update(f"[green]Job '{job_id}' {state}.[/green]")
            self._refresh_jobs()
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")
