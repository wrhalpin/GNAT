"""
ctm_sak.reports
================

Automated threat intelligence report generation — daily, trends, and yearly.

Three canned report types, four output formats (PDF, HTML, Markdown, DOCX),
two delivery targets (email, SharePoint), configurable AI involvement.

Quick start::

    from ctm_sak.reports import ReportGenerator, ReportConfig, AIMode, ReportJob
    from ctm_sak.agents import AgentConfig
    from ctm_sak.research import ResearchLibrary

    config = ReportConfig(
        report_type = "daily",
        workspaces  = ["_ctmsak_library"],
        sectors     = ["Healthcare", "Opportunistic"],
        ai_mode     = AIMode.ASSISTED,
        formats     = ["pdf", "html", "markdown"],
        delivery    = ["email", "file"],
        email_to    = ["soc@example.com"],
        output_dir  = "/var/reports",
        org_name    = "Acme Health",
    )

    lib       = ResearchLibrary.default()
    generator = ReportGenerator(
        manager          = workspace_manager,
        config           = config,
        agent_config     = AgentConfig.from_ini(),
        research_library = lib,
    )
    result = generator.run()
    print(result.files_written)

Scheduled reports::

    from ctm_sak.reports import ReportJob
    from ctm_sak.schedule import FeedScheduler

    job = ReportJob(
        manager        = workspace_manager,
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

    with FeedScheduler() as scheduler:
        scheduler.add(job)
"""

from ctm_sak.reports.base import (
    AIMode, ReportConfig, ReportSection, ReportDocument,
    ReportResult, SectorFilter,
)
from ctm_sak.reports.aggregator import DataAggregator, ReportAggregates
from ctm_sak.reports.synthesizer import ReportSynthesizer
from ctm_sak.reports.renderers import (
    MarkdownRenderer, HTMLRenderer, PDFRenderer, DOCXRenderer,
)
from ctm_sak.reports.delivery import EmailDelivery, SharePointDelivery
from ctm_sak.reports.generator import ReportGenerator, ReportJob

__all__ = [
    # Configuration
    "AIMode", "ReportConfig", "SectorFilter",
    # Document model
    "ReportSection", "ReportDocument", "ReportResult",
    # Pipeline stages
    "DataAggregator", "ReportAggregates",
    "ReportSynthesizer",
    # Renderers
    "MarkdownRenderer", "HTMLRenderer", "PDFRenderer", "DOCXRenderer",
    # Delivery
    "EmailDelivery", "SharePointDelivery",
    # Orchestration
    "ReportGenerator", "ReportJob",
]
