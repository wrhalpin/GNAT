# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.tui.app
=============
Root Textual application for the GNAT interactive terminal UI.

Provides a tabbed interface with five analyst screens:

* **Query** (F1)          — NLP threat-intel query bar + STIX results table
* **Library** (F2)        — Research library browser + staging queue
* **Scheduler** (F3)      — Feed job status + manual trigger
* **Reports** (F4)        — Generated report list + browser open
* **Investigations** (F5) — Investigation browser, status transitions, notes

Launch::

    from gnat.tui.app import GNATApp
    GNATApp().run()

Or via CLI::

    gnat tui [query|library|scheduler|reports|investigations]
"""

from __future__ import annotations

import contextlib

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, TabbedContent, TabPane

from gnat.tui.screens.investigations import InvestigationsScreen
from gnat.tui.screens.library import LibraryScreen
from gnat.tui.screens.query import QueryScreen
from gnat.tui.screens.reports import ReportsScreen
from gnat.tui.screens.scheduler import SchedulerScreen

_VERSION = "0.1.0"


class GNATApp(App):
    """
    GNAT interactive terminal UI.

    Parameters
    ----------
    config_path : str, optional
        Path to ``gnat.ini`` / ``config.ini``.  When omitted GNAT uses
        the standard config search order.
    initial_tab : str, optional
        Tab to show on launch: ``"query"``, ``"library"``,
        ``"scheduler"``, or ``"reports"``.  Default ``"query"``.
    scheduler : FeedScheduler, optional
        A running :class:`~gnat.schedule.scheduler.FeedScheduler` instance
        to pass to the scheduler screen.  If ``None`` the screen shows a
        "not configured" notice.
    reports_dir : str, optional
        Directory to scan for generated report files.
    nlp_backend : str, optional
        NLP backend override: ``"builtin"`` or ``"claude"``.
    nlp_platform : str, optional
        Platform key to query when running an NLP search.
    """

    TITLE = f"GNAT — Cybersecurity Threat Management  v{_VERSION}"
    CSS_PATH = None  # inline CSS only

    BINDINGS = [
        Binding("f1", "switch_tab('query')", "Query", show=True),
        Binding("f2", "switch_tab('library')", "Library", show=True),
        Binding("f3", "switch_tab('scheduler')", "Scheduler", show=True),
        Binding("f4", "switch_tab('reports')", "Reports", show=True),
        Binding("f5", "switch_tab('investigations')", "Investigations", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    CSS = """
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0;
    }
    """

    def __init__(
        self,
        config_path: str | None = None,
        initial_tab: str = "query",
        scheduler=None,
        reports_dir: str | None = None,
        nlp_backend: str | None = None,
        nlp_platform: str | None = None,
        db_url: str | None = None,
        **kwargs,
    ) -> None:
        """Initialize GNATApp."""
        super().__init__(**kwargs)
        self._config_path = config_path
        self._initial_tab = initial_tab
        self._scheduler = scheduler
        self._reports_dir = reports_dir
        self._nlp_backend = nlp_backend
        self._nlp_platform = nlp_platform
        self._db_url = db_url

    def compose(self) -> ComposeResult:
        """Build and return the GNATApp."""
        yield Header()
        with TabbedContent(initial=self._initial_tab):
            with TabPane("Query  F1", id="query"):
                yield QueryScreen(
                    config_path=self._config_path,
                    platform=self._nlp_platform,
                    backend=self._nlp_backend,
                )
            with TabPane("Library  F2", id="library"):
                yield LibraryScreen(config_path=self._config_path)
            with TabPane("Scheduler  F3", id="scheduler"):
                yield SchedulerScreen(
                    scheduler=self._scheduler,
                    config_path=self._config_path,
                )
            with TabPane("Reports  F4", id="reports"):
                yield ReportsScreen(
                    reports_dir=self._reports_dir,
                    config_path=self._config_path,
                )
            with TabPane("Investigations  F5", id="investigations"):
                yield InvestigationsScreen(
                    db_url=self._db_url,
                    config_path=self._config_path,
                )
        yield Footer()

    def action_switch_tab(self, tab_id: str) -> None:
        """Switch the active tab by id (used by F-key bindings)."""
        with contextlib.suppress(Exception):
            self.query_one(TabbedContent).active = tab_id


def run(
    config_path: str | None = None,
    initial_tab: str = "query",
    scheduler=None,
    reports_dir: str | None = None,
    nlp_backend: str | None = None,
    nlp_platform: str | None = None,
    db_url: str | None = None,
) -> None:
    """
    Launch the GNAT TUI.

    Convenience wrapper used by the ``gnat tui`` CLI subcommand.
    """
    GNATApp(
        config_path=config_path,
        initial_tab=initial_tab,
        scheduler=scheduler,
        reports_dir=reports_dir,
        nlp_backend=nlp_backend,
        nlp_platform=nlp_platform,
        db_url=db_url,
    ).run()
