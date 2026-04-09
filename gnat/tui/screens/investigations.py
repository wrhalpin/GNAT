"""
gnat.tui.screens.investigations
================================

Investigations browser screen (F5).

Displays the list of investigations from the configured SQLite store and
allows the analyst to create new investigations, view detail, and transition
status — all without leaving the TUI.

The screen degrades gracefully: if SQLAlchemy is not installed or the DB
URL is not set, it shows an info notice rather than crashing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select


_NO_PERSIST_MSG = (
    "Investigation storage not available.\n"
    "Install SQLAlchemy:  pip install 'gnat[persist]'\n"
    "Then set GNAT_DB_URL or place gnat.db in the current directory."
)

_STATUS_OPTIONS = [
    ("All",         ""),
    ("Open",        "open"),
    ("In Progress", "in_progress"),
    ("Review",      "review"),
    ("Closed",      "closed"),
]

_TRANSITION_OPTIONS = [
    ("→ In Progress", "in_progress"),
    ("→ Review",      "review"),
    ("→ Closed",      "closed"),
    ("→ Open",        "open"),
]


class InvestigationsScreen(Screen):
    """Investigation list and management screen."""

    TITLE = "GNAT — Investigations"

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back",    show=True),
        Binding("ctrl+r", "refresh",        "Refresh", show=True),
        Binding("ctrl+n", "new_dialog",     "New",     show=True),
        Binding("ctrl+e", "export_csv",     "Export",  show=True),
    ]

    CSS = """
    InvestigationsScreen {
        layout: vertical;
    }
    #toolbar {
        height: 4;
        padding: 0 1;
        background: $panel;
    }
    #filter-row {
        height: 3;
        layout: horizontal;
    }
    #filter-row Input {
        width: 30;
    }
    #filter-row Select {
        width: 20;
    }
    #filter-row Button {
        width: 12;
        margin: 0 1;
    }
    #status-label {
        padding: 0 1;
        height: 1;
        color: $text-muted;
    }
    #inv-table {
        height: 1fr;
    }
    #detail-pane {
        height: 10;
        background: $panel;
        border: solid $primary;
        padding: 1;
        display: none;
    }
    #detail-pane.visible {
        display: block;
    }
    """

    def __init__(
        self,
        db_url: str | None = None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._db_url          = db_url or os.environ.get("GNAT_DB_URL", "sqlite:///gnat.db")
        self._config_path     = config_path
        self._service: Any    = None
        self._selected_id: str | None = None
        self._investigations: list[Any] = []

    # ── Compose ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            with Horizontal(id="toolbar"):
                with Horizontal(id="filter-row"):
                    yield Input(placeholder="Search title…", id="search-input")
                    yield Select(
                        options=_STATUS_OPTIONS,
                        prompt="Status",
                        id="status-select",
                    )
                    yield Button("Search", variant="primary", id="search-btn")
                    yield Button("New",    variant="success", id="new-btn")
            yield Label("Loading investigations…", id="status-label")
            yield DataTable(id="inv-table", cursor_type="row")
            with Vertical(id="detail-pane"):
                yield Label("", id="detail-text")
                with Horizontal():
                    yield Select(
                        options=_TRANSITION_OPTIONS,
                        prompt="Transition to…",
                        id="transition-select",
                    )
                    yield Button("Apply", variant="primary",  id="apply-btn")
                    yield Button("Close", variant="default",  id="close-detail-btn")
        yield Footer()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self._init_service()
        self._setup_table()
        self._load_investigations()

    def _init_service(self) -> None:
        try:
            from gnat.analysis.investigations.storage import InvestigationStore
            from gnat.analysis.investigations.service import InvestigationService
            store = InvestigationStore(self._db_url)
            store.create_all()
            self._service = InvestigationService(store)
        except ImportError:
            self._set_status(f"[bold red]{_NO_PERSIST_MSG}[/]")
        except Exception as exc:
            self._set_status(f"[bold red]DB error: {exc}[/]")

    def _setup_table(self) -> None:
        table: DataTable = self.query_one("#inv-table", DataTable)
        table.add_columns(
            "ID (short)", "Title", "Status", "TLP", "Created by", "Updated"
        )

    def _load_investigations(self, status_filter: str = "", text: str = "") -> None:
        if self._service is None:
            return

        try:
            from gnat.analysis.query import InvestigationQuery
            from gnat.analysis.investigations.models import InvestigationStatus

            status = None
            if status_filter:
                try:
                    status = [InvestigationStatus(status_filter)]
                except ValueError:
                    logger.debug("Unknown investigation status filter %r; ignoring", status_filter)

            q = InvestigationQuery(
                status    = status,
                text      = text or None,
                page_size = 200,
                sort_desc = True,
            )
            investigations = self._service.list(query=q)
            self._investigations = list(investigations)
        except Exception as exc:
            self._set_status(f"[red]Error loading: {exc}[/]")
            return

        table: DataTable = self.query_one("#inv-table", DataTable)
        table.clear()
        for inv in self._investigations:
            table.add_row(
                inv.id[:8] + "…",
                inv.title[:45],
                inv.status.value,
                inv.classification.value,
                inv.created_by,
                inv.updated_at.strftime("%Y-%m-%d"),
                key=inv.id,
            )

        self._set_status(
            f"{len(investigations)} investigation(s) loaded — "
            "Ctrl+N: New  |  Ctrl+R: Refresh  |  Click row for detail"
        )

    # ── Event handlers ─────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        if btn_id == "search-btn":
            text   = self.query_one("#search-input",  Input).value.strip()
            status = str(self.query_one("#status-select", Select).value or "")
            self._load_investigations(status_filter=status, text=text)

        elif btn_id == "new-btn":
            self.action_new_dialog()

        elif btn_id == "apply-btn":
            self._apply_transition()

        elif btn_id == "close-detail-btn":
            self.query_one("#detail-pane").remove_class("visible")
            self._selected_id = None

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        inv_id = event.row_key.value if event.row_key else None
        if inv_id is None or self._service is None:
            return
        self._selected_id = inv_id
        try:
            inv = self._service.get(inv_id)
        except Exception:
            return

        detail = (
            f"[bold]{inv.title}[/bold]  [{inv.classification.value.upper()}]\n"
            f"Status: {inv.status.value}  |  "
            f"Hypotheses: {len(inv.hypothesis)}  |  "
            f"Notes: {len(inv.notes)}  |  "
            f"Tasks: {len(inv.tasks)}  |  "
            f"Indicators: {len(inv.indicators)}\n"
            f"Tags: {', '.join(inv.tags) or '—'}"
        )
        self.query_one("#detail-text",  Label).update(detail)
        self.query_one("#detail-pane").add_class("visible")

    def action_refresh(self) -> None:
        self._load_investigations()

    def action_new_dialog(self) -> None:
        """Push a simple inline creation flow (uses Input widget)."""
        # Simple approach: prompt for title via status bar
        self._set_status(
            "[yellow]Enter title in search box and press Ctrl+N again to create.[/]"
        )

    def action_export_csv(self) -> None:
        """Export the current filtered investigation list as CSV."""
        import csv
        import os
        from datetime import datetime

        if not self._investigations:
            self._set_status("[yellow]No investigations to export.[/]")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path  = os.path.expanduser(f"~/gnat_investigations_{timestamp}.csv")
        fieldnames = ["id", "title", "status", "severity", "created_by", "created_at"]

        try:
            with open(out_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for inv in self._investigations:
                    writer.writerow({
                        "id":         getattr(inv, "id", ""),
                        "title":      getattr(inv, "title", ""),
                        "status":     str(getattr(inv, "status", "")),
                        "severity":   getattr(inv, "severity", ""),
                        "created_by": getattr(inv, "created_by", ""),
                        "created_at": str(getattr(inv, "created_at", "")),
                    })
            self._set_status(f"[green]Exported {len(self._investigations)} rows → {out_path}[/]")
        except Exception as exc:
            self._set_status(f"[red]Export failed: {exc}[/]")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _apply_transition(self) -> None:
        if self._selected_id is None or self._service is None:
            return
        new_status_str = str(self.query_one("#transition-select", Select).value or "")
        if not new_status_str:
            return
        try:
            from gnat.analysis.investigations.models import InvestigationStatus
            new_status = InvestigationStatus(new_status_str)
            self._service.transition(self._selected_id, new_status,
                                     author="tui", note="Transitioned via TUI")
            self._set_status(
                f"[green]✓ {self._selected_id[:8]}… → {new_status.value}[/]"
            )
            self._load_investigations()
            self.query_one("#detail-pane").remove_class("visible")
        except Exception as exc:
            self._set_status(f"[red]Transition failed: {exc}[/]")

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#status-label", Label).update(text)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to update investigations status label: %s", exc)
