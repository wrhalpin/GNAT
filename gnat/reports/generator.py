"""
gnat.reports.generator
==========================

:class:`ReportGenerator` — orchestrates the full report generation pipeline:

    Collect → Filter → Aggregate → Synthesize → Render → Deliver

:class:`ReportJob` — a :class:`~gnat.schedule.job.FeedJob` subclass
that wraps ``ReportGenerator`` for scheduled execution.

Usage
-----
::

    from gnat.reports import ReportGenerator, ReportConfig, AIMode
    from gnat.agents import AgentConfig

    config = ReportConfig(
        report_type = "daily",
        workspaces  = ["_ctmsak_library", "analyst-ws"],
        sectors     = ["Healthcare", "Opportunistic"],
        ai_mode     = AIMode.ASSISTED,
        formats     = ["pdf", "html", "markdown"],
        delivery    = ["email", "file"],
        email_to    = ["soc-team@example.com"],
        output_dir  = "/var/reports",
        org_name    = "Acme Health",
    )

    generator = ReportGenerator(
        manager        = workspace_manager,
        config         = config,
        agent_config   = AgentConfig.from_ini(),
        research_library = lib,
    )
    result = generator.run()
    print(result)

Scheduled generation::

    from gnat.reports import ReportJob
    from gnat.schedule import FeedScheduler

    job = ReportJob(
        manager        = workspace_manager,
        config         = config,
        agent_config   = AgentConfig.from_ini(),
        research_library = lib,
        job_id         = "daily-healthcare-report",
    )

    with FeedScheduler() as scheduler:
        scheduler.add(job)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from gnat.reports.aggregator import DataAggregator
from gnat.reports.base import (
    AIMode,
    ReportConfig,
    ReportDocument,
    ReportResult,
    ReportSection,
    SectorFilter,
    _utcnow,
)
from gnat.reports.renderers import (
    DOCXRenderer,
    HTMLRenderer,
    MarkdownRenderer,
    PDFRenderer,
)
from gnat.schedule.job import FeedJob

if TYPE_CHECKING:
    from gnat.agents.base import AgentConfig
    from gnat.context.workspace import WorkspaceManager
    from gnat.research.library import ResearchLibrary

logger = logging.getLogger(__name__)

_RENDERERS = {
    "markdown": MarkdownRenderer,
    "html":     HTMLRenderer,
    "pdf":      PDFRenderer,
    "docx":     DOCXRenderer,
}

_FORMAT_EXT = {
    "markdown": ".md",
    "html":     ".html",
    "pdf":      ".pdf",
    "docx":     ".docx",
}


class ReportGenerator:
    """
    Orchestrates the full report generation pipeline.

    Parameters
    ----------
    manager : WorkspaceManager
        Used to open configured workspaces for data collection.
    config : ReportConfig
        Report configuration.
    agent_config : AgentConfig, optional
        Required when ``config.ai_mode != AIMode.NONE``.
    research_library : ResearchLibrary, optional
        Provides research context for AI synthesis.

    Examples
    --------
    ::

        generator = ReportGenerator(
            manager        = manager,
            config         = config,
            agent_config   = AgentConfig.from_ini(),
            research_library = lib,
        )
        result = generator.run()
        print(result.files_written)
    """

    def __init__(
        self,
        manager: WorkspaceManager,
        config: ReportConfig,
        agent_config: AgentConfig | None = None,
        research_library: ResearchLibrary | None = None,
    ):
        self._manager = manager
        self._config  = config
        self._acfg    = agent_config
        self._lib     = research_library

    def run(self) -> ReportResult:
        """Execute the full pipeline and return a ``ReportResult``."""
        t_start = time.perf_counter()
        now     = _utcnow()

        result = ReportResult(
            report_type  = self._config.report_type,
            title        = "",
            generated_at = now,
        )

        # ── 1. Build sector filter ─────────────────────────────────────────
        sector_filter = None
        if self._config.sectors:
            sector_filter = SectorFilter.from_config(self._config)

        # ── 2. Aggregate ───────────────────────────────────────────────────
        agg = DataAggregator(
            manager         = self._manager,
            config          = self._config,
            sector_filter   = sector_filter,
            research_library= self._lib,
        ).run()

        result.objects_analysed = agg.total_objects

        # ── 3. Build document title ────────────────────────────────────────
        title = self._config.title or self._auto_title(now)
        result.title = title

        doc = ReportDocument(
            title        = title,
            report_type  = self._config.report_type,
            generated_at = now,
            period_start = agg.period_start,
            period_end   = agg.period_end,
            config       = self._config,
            metadata     = {
                "total_objects":  agg.total_objects,
                "sector_filter":  self._config.sectors,
                "window_days":    self._config.window_days,
            },
        )

        # ── 4. Always add data sections (no AI required) ───────────────────
        self._add_data_sections(doc, agg)

        # ── 5. AI synthesis (assisted / full modes) ────────────────────────
        ai_calls = 0
        if self._config.ai_mode != AIMode.NONE:
            if not self._acfg:
                logger.warning(
                    "ReportGenerator: ai_mode=%s but no agent_config provided "
                    "— skipping synthesis",
                    self._config.ai_mode.value,
                )
            else:
                from gnat.reports.synthesizer import ReportSynthesizer
                synth = ReportSynthesizer(
                    config           = self._config,
                    agent_config     = self._acfg,
                    research_library = self._lib,
                )
                narrative_sections = synth.synthesize(
                    agg, self._config.report_type
                )
                ai_calls = synth.calls_made

                # Merge: AI sections go first (lower order numbers),
                # data sections fill in remaining
                for ns in narrative_sections:
                    existing = doc.get_section(ns.title)
                    if existing:
                        existing.narrative = ns.narrative
                        existing.data.update(ns.data)
                    else:
                        doc.add_section(ns)

        result.ai_calls_made      = ai_calls
        result.sections_generated = len(doc.sections)

        # ── 6. Render ──────────────────────────────────────────────────────
        output_dir = Path(self._config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        date_str   = now.strftime("%Y-%m-%d")
        base_name  = f"{self._config.report_type}-intel-{date_str}"
        if self._config.config_name:
            safe_name = self._config.config_name.replace(".", "_").replace(" ", "_")
            base_name = f"{safe_name}-{date_str}"

        for fmt in self._config.formats:
            fmt = fmt.lower().strip()
            if fmt not in _RENDERERS:
                logger.warning("ReportGenerator: unknown format %r — skipping", fmt)
                continue
            ext  = _FORMAT_EXT[fmt]
            path = str(output_dir / f"{base_name}{ext}")
            try:
                renderer = _RENDERERS[fmt]()
                renderer.render(doc, path)
                result.formats_rendered.append(fmt)
                result.files_written.append(path)
                logger.info("ReportGenerator: rendered %s → %s", fmt, path)
            except Exception as exc:
                msg = f"Render failed ({fmt}): {exc}"
                result.errors.append(msg)
                logger.error("ReportGenerator: %s", msg)

        # ── 7. Deliver ─────────────────────────────────────────────────────
        if result.files_written:
            self._deliver(result, doc)

        result.duration_seconds = time.perf_counter() - t_start
        logger.info(
            "ReportGenerator: %s complete — %s (%.1fs)",
            self._config.report_type, result, result.duration_seconds,
        )
        return result

    # ── Data sections (no AI) ─────────────────────────────────────────────

    def _add_data_sections(
        self, doc: ReportDocument, agg: ReportAggregates
    ) -> None:
        """Add pure-data sections — always present regardless of AI mode."""

        # Intel volume summary
        doc.add_section(ReportSection(
            title="Intelligence Volume",
            data={
                "total_objects":   agg.total_objects,
                "new_objects":     agg.new_objects,
                "updated_objects": agg.updated_objects,
                "by_type":         agg.by_type,
                "new_by_type":     agg.new_by_type,
                "window_days":     agg.window_days,
            },
            section_type="table",
            order=10,
        ))

        if agg.indicator_count:
            doc.add_section(ReportSection(
                title="Indicators of Compromise",
                data={
                    "indicator_count":    agg.indicator_count,
                    "ioc_by_type":        agg.ioc_by_type,
                    "top_indicators":     agg.top_indicators[:20],
                    "high_conf_indicators": agg.high_conf_indicators[:20],
                },
                section_type="table",
                order=11,
            ))

        if agg.vuln_count:
            doc.add_section(ReportSection(
                title="Vulnerabilities",
                data={
                    "vuln_count":       agg.vuln_count,
                    "critical_vulns":   agg.critical_vulns,
                    "exploited_vulns":  agg.exploited_vulns,
                    "cvss_distribution":agg.cvss_distribution,
                },
                section_type="table",
                order=12,
            ))

        if agg.actor_count:
            doc.add_section(ReportSection(
                title="Threat Actors",
                data={
                    "actor_count":      agg.actor_count,
                    "top_actors":       agg.top_actors,
                    "actor_motivations":agg.actor_motivations,
                },
                section_type="table",
                order=13,
            ))

        if agg.ttp_count:
            doc.add_section(ReportSection(
                title="Tactics, Techniques and Procedures",
                data={
                    "ttp_count":          agg.ttp_count,
                    "top_ttps":           agg.top_ttps,
                    "tactic_distribution":agg.tactic_distribution,
                },
                section_type="table",
                order=14,
            ))

        if agg.sector_distribution:
            doc.add_section(ReportSection(
                title="Sector Targeting",
                data={
                    "sector_distribution": agg.sector_distribution,
                    "opportunistic_count": agg.opportunistic_count,
                },
                section_type="table",
                order=15,
            ))

        if agg.source_breakdown:
            doc.add_section(ReportSection(
                title="Source Intelligence",
                data={
                    "source_breakdown":   agg.source_breakdown,
                    "ai_extracted_count": agg.ai_extracted_count,
                    "avg_confidence":     round(agg.avg_confidence, 1),
                    "confidence_distribution": agg.confidence_distribution,
                },
                section_type="table",
                order=16,
            ))

        # Time series appendix for longer windows
        if agg.monthly_counts:
            doc.add_section(ReportSection(
                title="Collection Trend",
                data={
                    "monthly_counts": agg.monthly_counts,
                    "weekly_counts":  agg.weekly_counts[-12:] if agg.weekly_counts else [],
                },
                section_type="chart_data",
                order=20,
            ))

    # ── Delivery ───────────────────────────────────────────────────────────

    def _deliver(self, result: ReportResult, doc: ReportDocument | None = None) -> None:
        """Dispatch to configured delivery targets."""
        for target in self._config.delivery:
            t = target.lower().strip()
            if t == "file":
                result.deliveries_sent.append(f"file:{self._config.output_dir}")
                continue
            if t == "email":
                self._deliver_email(result, doc)
            elif t == "sharepoint":
                self._deliver_sharepoint(result)
            else:
                logger.warning("ReportGenerator: unknown delivery target %r", t)

    def _deliver_email(
        self, result: ReportResult, doc: ReportDocument | None = None
    ) -> None:
        if not self._config.email_to:
            logger.warning("ReportGenerator: email delivery but no email_to configured")
            return
        try:
            from gnat.reports.delivery import EmailDelivery
            subject = self._config.email_subject.format(
                report_type=self._config.report_type.title(),
                date=result.generated_at.strftime("%Y-%m-%d"),
            )

            # Populate HTML body: prefer the rendered HTML file; fall back to
            # the Executive Summary narrative for PDF/DOCX-only deliveries.
            body_html = self._extract_email_body_html(result, doc)

            delivery = EmailDelivery.from_ini(
                to_addresses=self._config.email_to,
                subject=subject,
                body_html=body_html,
            )
            outcome = delivery.send(result.files_written)
            if outcome["success"]:
                result.deliveries_sent.append(
                    f"email:{','.join(self._config.email_to)}"
                )
            else:
                result.errors.append(f"Email failed: {outcome['error']}")
        except Exception as exc:
            result.errors.append(f"Email delivery error: {exc}")
            logger.error("ReportGenerator: email delivery failed — %s", exc)

    def _extract_email_body_html(
        self, result: ReportResult, doc: ReportDocument | None = None
    ) -> str:
        """Return HTML content for the email body.

        Reads the rendered ``.html`` file when available; otherwise builds a
        compact HTML snippet from the Executive Summary section narrative
        (capped at 2 000 characters) for PDF/DOCX-only reports.
        """
        # 1. Use rendered HTML file if present
        html_files = [f for f in result.files_written if f.endswith(".html")]
        if html_files:
            try:
                return Path(html_files[0]).read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning(
                    "ReportGenerator: could not read HTML file for email body — %s", exc
                )

        # 2. Fall back to executive summary narrative from the document
        if doc is not None:
            for section in doc.sections:
                if "executive" in section.title.lower() and section.has_narrative:
                    snippet = section.narrative[:2000]
                    return (
                        f"<html><body><h2>{result.title}</h2>"
                        f"<p>{snippet.replace(chr(10), '<br>')}</p>"
                        "</body></html>"
                    )

        return ""

    def _deliver_sharepoint(self, result: ReportResult) -> None:
        if not self._config.sharepoint_url:
            logger.warning(
                "ReportGenerator: sharepoint delivery but no sharepoint_url configured"
            )
            return
        try:
            from urllib.parse import urlparse

            from gnat.reports.delivery import SharePointDelivery
            parsed   = urlparse(self._config.sharepoint_url)
            # Split site path from library
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                site_path = "/".join(path_parts[:2])
                library   = "/".join(path_parts[2:]) if len(path_parts) > 2 else "Documents"
            else:
                site_path = parsed.path.strip("/")
                library   = "Documents"

            site_url = f"{parsed.scheme}://{parsed.netloc}/{site_path}"
            delivery = SharePointDelivery.from_ini(
                site_url     = site_url,
                library_path = library,
                folder       = result.generated_at.strftime("%Y/%m"),
            )
            # Upload only PDF and DOCX to SharePoint (most useful for SharePoint viewers)
            sp_files = [
                f for f in result.files_written
                if any(f.endswith(ext) for ext in (".pdf", ".docx"))
            ] or result.files_written[:1]

            outcome = delivery.upload(sp_files)
            if outcome["success"]:
                result.deliveries_sent.append(
                    f"sharepoint:{self._config.sharepoint_url}"
                )
                if outcome.get("urls"):
                    logger.info(
                        "ReportGenerator: SharePoint URLs: %s", outcome["urls"]
                    )
            else:
                result.errors.append(f"SharePoint failed: {outcome['error']}")
        except Exception as exc:
            result.errors.append(f"SharePoint delivery error: {exc}")
            logger.error("ReportGenerator: SharePoint delivery failed — %s", exc)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _auto_title(self, now: datetime) -> str:
        type_names = {
            "daily":  "Daily Threat Intelligence Report",
            "trends": "Threat Intelligence Trends Report",
            "yearly": "Annual Threat Intelligence Report",
        }
        base = type_names.get(self._config.report_type, "Threat Intelligence Report")
        org  = f" — {self._config.org_name}" if self._config.org_name else ""
        date = now.strftime("%Y-%m-%d")
        return f"{base}{org} — {date}"


# ---------------------------------------------------------------------------
# ReportJob
# ---------------------------------------------------------------------------

class ReportJob(FeedJob):
    """
    Scheduled report generation job.

    Wraps :class:`ReportGenerator` in a :class:`~gnat.schedule.job.FeedJob`
    so reports can be generated on a schedule via
    :class:`~gnat.schedule.scheduler.FeedScheduler`.

    Parameters
    ----------
    manager : WorkspaceManager
        Used to open workspaces for data collection.
    config : ReportConfig
        Report configuration.
    agent_config : AgentConfig, optional
        Required for AI-assisted reports.
    research_library : ResearchLibrary, optional
        Provides research context.
    job_id : str
        Scheduler job identifier.  Defaults to
        ``"report-<report_type>"``.
    on_success, on_failure : callable, optional
        Callbacks receiving the ``RunRecord``.

    Examples
    --------
    ::

        job = ReportJob(
            manager        = manager,
            config         = ReportConfig(
                report_type = "daily",
                formats     = ["pdf", "html"],
                delivery    = ["email"],
                email_to    = ["soc@example.com"],
                schedule    = "0 6 * * *",
            ),
            agent_config   = AgentConfig.from_ini(),
            research_library = lib,
        )

        with FeedScheduler() as sched:
            sched.add(job)
    """

    def __init__(
        self,
        manager: WorkspaceManager,
        config: ReportConfig,
        agent_config: AgentConfig | None = None,
        research_library: ResearchLibrary | None = None,
        job_id: str | None = None,
        on_success=None,
        on_failure=None,
    ):
        self._report_manager  = manager
        self._report_config   = config
        self._report_acfg     = agent_config
        self._report_lib      = research_library

        # Determine schedule
        interval_seconds = None
        cron = None
        if config.schedule:
            cron = config.schedule
        else:
            # Default schedules by report type.
            # Yearly uses a calendar-anchored cron (Jan 1 at 06:00 UTC) to
            # avoid 365-day interval drift after server restarts.
            _default_crons = {
                "yearly": "0 6 1 1 *",
            }
            _default_intervals = {
                "daily":  86400,
                "trends": 7 * 86400,
            }
            if config.report_type in _default_crons:
                cron = _default_crons[config.report_type]
            else:
                interval_seconds = _default_intervals.get(config.report_type, 86400)

        super().__init__(
            job_id          = job_id or f"report-{config.report_type}",
            reader_factory  = lambda ctx: None,   # overridden in execute()
            mapper_factory  = lambda ctx: None,
            interval_seconds= interval_seconds,
            cron            = cron,
            on_success      = on_success,
            on_failure      = on_failure,
        )

    def execute(self, scheduled_at=None) -> RunRecord:
        """Run the report generator, wrapped in FeedJob state management."""
        from gnat.ingest.base import IngestResult
        from gnat.schedule.job import RunRecord, _utcnow

        if not self.enabled:
            return RunRecord(
                run_number=self.run_count + 1,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(), finished_at=_utcnow(), status="skipped",
            )

        if not self._running_lock.acquire(blocking=False):
            return RunRecord(
                run_number=self.run_count + 1,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(), finished_at=_utcnow(), status="skipped",
                error="skipped: previous run still active",
            )

        self.run_count += 1
        started_at = _utcnow()
        sched_at   = scheduled_at or started_at

        record = RunRecord(
            run_number=self.run_count, scheduled_at=sched_at,
            started_at=started_at,
        )

        try:
            generator = ReportGenerator(
                manager          = self._report_manager,
                config           = self._report_config,
                agent_config     = self._report_acfg,
                research_library = self._report_lib,
            )
            report_result = generator.run()

            record.finished_at      = _utcnow()
            record.duration_seconds = (
                record.finished_at - started_at
            ).total_seconds()
            record.result = IngestResult(
                source_id      = self.job_id,
                total_records  = report_result.objects_analysed,
                written_objects= len(report_result.files_written),
                errors         = report_result.errors,
            )
            record.result.report_result = report_result

            if report_result.errors:
                record.status = "partial"
            else:
                record.status = "success"
                self.last_success_at = record.finished_at

            logger.info(
                "ReportJob %r run #%d: %s — %d files written",
                self.job_id, self.run_count, record.status,
                len(report_result.files_written),
            )

            if record.status == "success" and self.on_success:
                self._safe_callback(self.on_success, record)
            elif record.status == "partial" and self.on_failure:
                self._safe_callback(self.on_failure, record)

        except Exception as exc:
            record.finished_at      = _utcnow()
            record.duration_seconds = (
                record.finished_at - started_at
            ).total_seconds()
            record.status = "failed"
            record.error  = str(exc)
            logger.error("ReportJob %r run #%d FAILED — %s",
                         self.job_id, self.run_count, exc)
            if self.on_failure:
                self._safe_callback(self.on_failure, record)

        finally:
            self._running_lock.release()

        self._append_history(record)
        return record
