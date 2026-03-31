"""
gnat.reports
================

Automated threat intelligence report generation — daily, trends, and yearly.

Three canned report types, four output formats (PDF, HTML, Markdown, DOCX),
two delivery targets (email, SharePoint), configurable AI involvement.

Quick start::

    from gnat.reports import ReportGenerator, ReportConfig, AIMode, ReportJob
    from gnat.agents import AgentConfig
    from gnat.research import ResearchLibrary

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

    from gnat.reports import ReportJob
    from gnat.schedule import FeedScheduler

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

from gnat.reports.aggregator import DataAggregator, ReportAggregates
from gnat.reports.base import (
    AIMode,
    ReportConfig,
    ReportDocument,
    ReportResult,
    ReportSection,
    SectorFilter,
)
from gnat.reports.delivery import EmailDelivery, SharePointDelivery
from gnat.reports.generator import ReportGenerator, ReportJob
from gnat.reports.renderers import (
    DOCXRenderer,
    HTMLRenderer,
    MarkdownRenderer,
    PDFRenderer,
)
from gnat.reports.synthesizer import ReportSynthesizer

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
