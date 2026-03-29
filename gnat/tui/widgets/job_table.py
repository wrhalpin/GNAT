"""
gnat.tui.widgets.job_table
=============================
Reusable DataTable widget for displaying FeedScheduler job status.

Columns: job_id, enabled, last_run, next_run, run_count, status.
"""

from typing import List

from textual.widgets import DataTable


class JobTable(DataTable):
    """DataTable pre-configured for scheduler job status dicts."""

    def on_mount(self) -> None:
        """Add job status column headers."""
        self.add_column("Job ID",     key="job_id",    width=25)
        self.add_column("On",         key="enabled",   width=4)
        self.add_column("Last Run",   key="last_run",  width=20)
        self.add_column("Next Run",   key="next_run",  width=20)
        self.add_column("Runs",       key="run_count", width=5)
        self.add_column("Status",     key="status",    width=12)
        self.cursor_type = "row"
        self.zebra_stripes = True

    def load_jobs(self, jobs: List[dict]) -> None:
        """
        Clear and populate the table from a list of job status dicts.

        Each dict should have the keys produced by
        ``FeedJob.status_dict()``:
        ``job_id``, ``enabled``, ``last_run``, ``next_run``,
        ``run_count``, ``status``.
        """
        self.clear()
        for job in jobs:
            last = (job.get("last_run") or "")[:19]
            nxt  = (job.get("next_run") or "")[:19]
            self.add_row(
                job.get("job_id", ""),
                "✓" if job.get("enabled") else "✗",
                last or "—",
                nxt  or "—",
                str(job.get("run_count", 0)),
                job.get("status", ""),
            )

    def selected_job_id(self) -> str | None:
        """Return the job_id of the currently highlighted row, or None."""
        try:
            row_key, _ = self.coordinate_to_cell_key(self.cursor_coordinate)
            cell = self.get_cell(row_key, "job_id")
            return str(cell)
        except Exception:
            return None
