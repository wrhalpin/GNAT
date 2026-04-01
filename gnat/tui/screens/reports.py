"""
gnat.tui.screens.reports
==========================
Generated report list screen.

Lists reports produced by ``ReportGenerator``, shows metadata, and
opens rendered HTML in the system browser via ``webbrowser.open()``.
"""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label


class ReportsScreen(Screen):
    """Report list browser — view and open generated reports."""

    TITLE = "GNAT — Reports"
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("ctrl+r", "refresh", "Refresh", show=True),
        Binding("ctrl+o", "open_selected", "Open", show=True),
    ]

    CSS = """
    ReportsScreen {
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
    #reports-table {
        height: 1fr;
    }
    """

    def __init__(
        self,
        reports_dir: str | None = None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._reports_dir = reports_dir
        self._config_path = config_path
        self._entries: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            with Horizontal(id="toolbar"):
                yield Button("Refresh", id="refresh-btn")
                yield Button("Open in Browser", id="open-btn", variant="primary")
            yield Label("", id="status-label")
            yield DataTable(id="reports-table", zebra_stripes=True, cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self._setup_table()
        self._load_reports()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "refresh-btn":
            self.action_refresh()
        elif btn == "open-btn":
            self.action_open_selected()

    def action_refresh(self) -> None:
        self._load_reports()

    def action_open_selected(self) -> None:
        """Open the selected report's HTML file in the system browser."""
        status = self.query_one("#status-label", Label)
        table = self.query_one("#reports-table", DataTable)
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            path_str = str(table.get_cell(row_key, "path"))
        except Exception:
            status.update("[yellow]Select a report row first.[/yellow]")
            return

        if not path_str or path_str == "—":
            status.update("[yellow]No file path available for this report.[/yellow]")
            return

        path = Path(path_str)
        # Try HTML first, then any matching extension
        html_path = path.with_suffix(".html") if path.suffix != ".html" else path
        target = html_path if html_path.exists() else path if path.exists() else None

        if target is None:
            status.update(f"[red]File not found: {path_str}[/red]")
            return

        webbrowser.open(target.as_uri())
        status.update(f"[green]Opened: {target.name}[/green]")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _setup_table(self) -> None:
        table: DataTable = self.query_one("#reports-table", DataTable)
        table.add_column("Name", key="name", width=30)
        table.add_column("Type", key="rtype", width=14)
        table.add_column("Format", key="fmt", width=10)
        table.add_column("Created", key="created", width=20)
        table.add_column("Size", key="size", width=10)
        table.add_column("Path", key="path", width=50)

    def _load_reports(self) -> None:
        table = self.query_one("#reports-table", DataTable)
        status = self.query_one("#status-label", Label)
        table.clear()
        self._entries = []

        reports_dir = self._resolve_reports_dir()
        if reports_dir is None or not Path(reports_dir).is_dir():
            status.update(
                "[yellow]Reports directory not configured or does not exist.  "
                "Set output_dir in [report:*] INI sections.[/yellow]"
            )
            return

        try:
            entries = self._scan_reports_dir(reports_dir)
            self._entries = entries
            for e in entries:
                table.add_row(
                    e.get("name", ""),
                    e.get("rtype", ""),
                    e.get("fmt", ""),
                    e.get("created", ""),
                    e.get("size", ""),
                    e.get("path", ""),
                )
            n = len(entries)
            status.update(f"[green]{n} report{'s' if n != 1 else ''}[/green]  Ctrl+O to open")
        except Exception as exc:
            status.update(f"[red]{exc}[/red]")

    def _resolve_reports_dir(self) -> str | None:
        if self._reports_dir:
            return self._reports_dir
        if self._config_path:
            try:
                import configparser

                cfg = configparser.ConfigParser()
                cfg.read(self._config_path)
                for section in cfg.sections():
                    if section.startswith("report"):
                        d = cfg.get(section, "output_dir", fallback=None)
                        if d:
                            return d
            except Exception:
                pass
        return None

    @staticmethod
    def _scan_reports_dir(reports_dir: str) -> list[dict]:
        """Scan a directory for PDF/HTML/DOCX files and return metadata dicts."""
        entries = []
        base = Path(reports_dir)
        extensions = {".pdf", ".html", ".docx", ".txt"}
        for f in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.suffix.lower() not in extensions:
                continue
            stat = f.stat()
            size_kb = stat.st_size // 1024
            import datetime

            created = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            # Infer report type from filename / path
            name_lower = f.name.lower()
            rtype = (
                "executive"
                if "executive" in name_lower
                else "trends"
                if "trend" in name_lower
                else "yearly"
                if "annual" in name_lower or "yearly" in name_lower
                else "report"
            )
            entries.append(
                {
                    "name": f.stem[:28],
                    "rtype": rtype,
                    "fmt": f.suffix.lstrip("."),
                    "created": created,
                    "size": f"{size_kb} KB",
                    "path": str(f),
                }
            )
        return entries
