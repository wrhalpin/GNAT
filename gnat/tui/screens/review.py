"""
gnat.tui.screens.review
========================

AI-extracted intel review queue screen (F6).

Displays PENDING review items from the configured DB and lets analysts
approve, reject, or modify confidence — without leaving the TUI.

Degrades gracefully: if SQLAlchemy is not installed or GNAT_DB_URL is
unset, shows an info notice rather than crashing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select

logger = logging.getLogger(__name__)

_NO_PERSIST_MSG = (
    "Review queue not available.\n"
    "Install SQLAlchemy:  pip install 'gnat[persist]'\n"
    "Then set GNAT_DB_URL or place gnat.db in the current directory."
)

_STATUS_OPTIONS = [
    ("Pending", "pending"),
    ("Approved", "approved"),
    ("Rejected", "rejected"),
    ("Modified", "modified"),
    ("All", ""),
]

_TYPE_OPTIONS = [
    ("All types", ""),
    ("indicator", "indicator"),
    ("malware", "malware"),
    ("threat-actor", "threat-actor"),
    ("tool", "tool"),
    ("vulnerability", "vulnerability"),
    ("campaign", "campaign"),
]


class ReviewScreen(Screen):
    """AI-extracted intel review queue browser (F6)."""

    BINDINGS = [
        Binding("f6", "app.switch_tab('review')", "Review", show=True),
        Binding("ctrl+r", "refresh", "Refresh", show=True),
        Binding("ctrl+a", "approve_selected", "Approve", show=True),
        Binding("ctrl+d", "reject_selected", "Reject", show=True),
    ]

    DEFAULT_CSS = """
    ReviewScreen {
        layout: vertical;
    }
    #toolbar {
        height: 3;
        background: $surface;
        padding: 0 1;
    }
    #search-input {
        width: 30;
        margin-right: 1;
    }
    #status-filter {
        width: 18;
        margin-right: 1;
    }
    #type-filter {
        width: 18;
        margin-right: 1;
    }
    #refresh-btn {
        width: 12;
        margin-right: 1;
    }
    #stats-bar {
        height: 1;
        background: $boost;
        padding: 0 1;
        color: $text-muted;
    }
    #queue-table {
        height: 1fr;
    }
    #detail-pane {
        height: 14;
        border: solid $accent;
        padding: 1;
        display: none;
    }
    #detail-pane.visible {
        display: block;
    }
    #detail-header {
        height: 1;
        color: $accent;
        margin-bottom: 1;
    }
    #detail-stix-id {
        height: 1;
        color: $text-muted;
    }
    #detail-confidence {
        height: 1;
    }
    #detail-notes-input {
        height: 3;
        margin-top: 1;
    }
    #action-bar {
        height: 3;
        padding: 0 1;
    }
    #approve-btn {
        background: $success;
        margin-right: 1;
    }
    #reject-btn {
        background: $error;
        margin-right: 1;
    }
    #confidence-input {
        width: 10;
        margin-right: 1;
    }
    #status-label {
        height: 1;
        background: $surface;
        padding: 0 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        db_url: str | None = None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._db_url = db_url
        self._config_path = config_path
        self._service: Any | None = None
        self._selected_id: str | None = None
        self._items: list[Any] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="toolbar"):
            yield Input(placeholder="Search submitted_by…", id="search-input")
            yield Select(_STATUS_OPTIONS, id="status-filter", value="pending")
            yield Select(_TYPE_OPTIONS, id="type-filter", value="")
            yield Button("⟳ Refresh", id="refresh-btn", variant="default")
        yield Label("", id="stats-bar")
        yield DataTable(id="queue-table", cursor_type="row")
        with Vertical(id="detail-pane"):
            yield Label("", id="detail-header")
            yield Label("", id="detail-stix-id")
            yield Label("", id="detail-confidence")
            yield Input(placeholder="Reviewer notes (optional)…", id="detail-notes-input")
            with Horizontal(id="action-bar"):
                yield Button("✓ Approve", id="approve-btn", variant="success")
                yield Button("✗ Reject", id="reject-btn", variant="error")
                yield Input(placeholder="Conf 0-100", id="confidence-input")
        yield Label("Loading…", id="status-label")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#queue-table", DataTable)
        table.add_columns("Type", "STIX ID", "Submitted by", "Confidence", "Submitted at", "Status")
        self._init_service()
        self._load_items()

    # ------------------------------------------------------------------
    # Service initialisation
    # ------------------------------------------------------------------

    def _init_service(self) -> None:
        db_url = self._db_url or os.environ.get("GNAT_DB_URL", "sqlite:///gnat.db")
        try:
            from gnat.review.service import ReviewService
            from gnat.review.store import ReviewQueueStore

            store = ReviewQueueStore(db_url)
            store.create_all()
            self._service = ReviewService(store)
        except ImportError:
            self._set_status(f"[yellow]{_NO_PERSIST_MSG}[/]")
        except Exception as exc:
            self._set_status(f"[red]DB error: {exc}[/]")

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_items(self) -> None:
        if self._service is None:
            return

        try:
            status_select = self.query_one("#status-filter", Select)
            type_select = self.query_one("#type-filter", Select)
            search_input = self.query_one("#search-input", Input)

            status = str(status_select.value) if status_select.value else None
            stix_type = str(type_select.value) if type_select.value else None
            submitted_by = search_input.value.strip() or None

            self._items = self._service.list(
                status=status,
                stix_type=stix_type,
                submitted_by=submitted_by,
                page_size=200,
            )

            table = self.query_one("#queue-table", DataTable)
            table.clear()
            for item in self._items:
                conf = item.stix_data.get("confidence", "—")
                table.add_row(
                    item.stix_type,
                    item.stix_id[:40] + "…" if len(item.stix_id) > 40 else item.stix_id,
                    item.submitted_by[:20],
                    str(conf),
                    item.submitted_at.strftime("%Y-%m-%d %H:%M"),
                    item.status.value,
                    key=item.id,
                )

            stats = self._service.stats()
            self._set_stats_bar(stats)
            self._set_status(
                f"{len(self._items)} item(s) — Ctrl+A: Approve  |  Ctrl+D: Reject  |  "
                "Click row for detail"
            )
        except Exception as exc:
            self._set_status(f"[red]Load error: {exc}[/]")

    # ------------------------------------------------------------------
    # Detail pane
    # ------------------------------------------------------------------

    def _show_detail(self, item: Any) -> None:
        self._selected_id = item.id

        name_or_val = item.stix_data.get("name") or item.stix_data.get("value") or item.stix_id
        self.query_one("#detail-header", Label).update(f"[bold]{item.stix_type}[/]  {name_or_val}")
        self.query_one("#detail-stix-id", Label).update(f"ID: {item.stix_id}")
        conf = item.stix_data.get("confidence", "—")
        src = item.stix_data.get("x_source_type", "—")
        self.query_one("#detail-confidence", Label).update(
            f"Confidence: {conf}  |  Source type: {src}  |  Submitted by: {item.submitted_by}"
        )
        if item.reviewer_notes:
            self.query_one("#detail-notes-input", Input).value = item.reviewer_notes

        self.query_one("#detail-pane").add_class("visible")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        self._load_items()
        self.query_one("#detail-pane").remove_class("visible")
        self._selected_id = None

    def action_approve_selected(self) -> None:
        if self._selected_id:
            self._do_approve(self._selected_id)

    def action_reject_selected(self) -> None:
        if self._selected_id:
            self._do_reject(self._selected_id)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = str(event.row_key.value) if event.row_key.value else None
        if not row_key:
            return
        item = next((i for i in self._items if i.id == row_key), None)
        if item:
            self._show_detail(item)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "refresh-btn":
            self.action_refresh()
        elif btn_id == "approve-btn" and self._selected_id:
            self._do_approve(self._selected_id)
        elif btn_id == "reject-btn" and self._selected_id:
            self._do_reject(self._selected_id)

    # ------------------------------------------------------------------
    # Approve / reject helpers
    # ------------------------------------------------------------------

    def _do_approve(self, item_id: str) -> None:
        if self._service is None:
            return
        try:
            notes_input = self.query_one("#detail-notes-input", Input)
            conf_input = self.query_one("#confidence-input", Input)

            notes = notes_input.value.strip() or None
            conf_override: int | None = None
            if conf_input.value.strip():
                try:
                    conf_override = int(conf_input.value.strip())
                except ValueError:
                    self._set_status("[red]Confidence must be an integer 0-100[/]")
                    return

            self._service.approve(
                item_id,
                reviewed_by="tui-analyst",
                notes=notes,
                confidence_override=conf_override,
            )
            self._set_status(f"[green]✓ Approved {item_id[:8]}…[/]")
            self._load_items()
            self.query_one("#detail-pane").remove_class("visible")
            self._selected_id = None
        except Exception as exc:
            self._set_status(f"[red]Approve failed: {exc}[/]")

    def _do_reject(self, item_id: str) -> None:
        if self._service is None:
            return
        try:
            notes_input = self.query_one("#detail-notes-input", Input)
            reason = notes_input.value.strip() or None
            self._service.reject(item_id, reviewed_by="tui-analyst", reason=reason)
            self._set_status(f"[yellow]✗ Rejected {item_id[:8]}…[/]")
            self._load_items()
            self.query_one("#detail-pane").remove_class("visible")
            self._selected_id = None
        except Exception as exc:
            self._set_status(f"[red]Reject failed: {exc}[/]")

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def _set_stats_bar(self, stats: dict) -> None:
        try:
            bar = self.query_one("#stats-bar", Label)
            bar.update(
                f"Pending: {stats.get('pending', 0)}  |  "
                f"Approved: {stats.get('approved', 0)}  |  "
                f"Rejected: {stats.get('rejected', 0)}  |  "
                f"Modified: {stats.get('modified', 0)}  |  "
                f"Total: {stats.get('total', 0)}"
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to update review stats bar: %s", exc)

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#status-label", Label).update(text)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to update review status label: %s", exc)
