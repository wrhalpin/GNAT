"""
gnat.agents
==============

AI-powered threat intelligence agents using Claude and Microsoft Copilot.

Two agent types, both implementing standard gnat ingest interfaces so
they drop directly into IngestPipeline and FeedJob without special casing.

ResearchAgent (SourceReader)
    Uses Claude with web search to gather threat intelligence. Two modes:
    - Topic-driven: given threat topics, synthesizes research summaries
    - Feed-driven: monitors configured URLs for new threat content
    Yields RawRecord dicts consumed by ParsingAgent or any RecordMapper.

ParsingAgent (RecordMapper)
    Uses Claude to extract structured STIX intel from unstructured text.
    Flexible extraction: IOCs, TTPs, threat actors, CVEs — whatever is present.
    All output tagged x_source_type="ai_extracted" with confidence capped
    at AgentConfig.ai_confidence_ceiling (default 60).

CopilotReader (SourceReader)
    Queries Microsoft Copilot via DirectLine for content from configured
    M365 sources: SharePoint libraries, mailboxes, Teams channels, OneDrive.
    Output feeds into ParsingAgent for structured extraction.

Quick start::

    from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
    from gnat.ingest import IngestPipeline

    config = AgentConfig.from_ini()   # reads [claude] section from config.ini

    # Research → Parse → Write in one pipeline
    result = (
        IngestPipeline("apt29-research")
        .read_from(ResearchAgent(config, topics=["APT29", "Cozy Bear"]))
        .map_with(ParsingAgent(config))
        .write_to(threatq_client)
    ).run()

    print(result)

Scheduled feed monitoring::

    from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
    from gnat.schedule import FeedJob, FeedScheduler

    config = AgentConfig.from_ini()

    job = FeedJob(
        job_id="threat-feed-monitor",
        reader_factory=lambda ctx: ResearchAgent(
            config=config,
            monitored_sources=[
                {"url": "https://unit42.paloaltonetworks.com/", "label": "Unit42"},
                {"url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                 "label": "CISA"},
            ],
            newer_than=ctx.last_success_iso,
        ),
        mapper_factory=lambda ctx: ParsingAgent(config),
        interval_seconds=21600,
        client=threatq_client,
    )

    with FeedScheduler() as scheduler:
        scheduler.add(job)

M365 + Copilot::

    from gnat.agents import CopilotReader, ParsingAgent, AgentConfig

    job = FeedJob(
        job_id="m365-threat-intel",
        reader_factory=lambda ctx: CopilotReader.from_ini(
            sources=[
                {"type": "sharepoint", "name": "ThreatReports",
                 "url": "https://contoso.sharepoint.com/sites/ThreatReports"},
                {"type": "mailbox", "name": "VendorAdvisories",
                 "query": "from:vendor-alerts@contoso.com"},
            ],
            newer_than=ctx.last_success_iso,
        ),
        mapper_factory=lambda ctx: ParsingAgent(AgentConfig.from_ini()),
        interval_seconds=3600,
    )
"""

from gnat.agents.base import AgentConfig, ResearchResult, ParsedIntel, ClaudeClient
from gnat.agents.research import ResearchAgent
from gnat.agents.parsing import ParsingAgent
from gnat.agents.copilot import CopilotReader
from gnat.agents.llm import LLMClient
from gnat.agents.claude import ClaudeProvider
from gnat.agents.openai_compatible import OpenAICompatibleProvider


__all__ = [
    "AgentConfig",
    "ResearchResult",
    "ParsedIntel",
    "ClaudeClient",
    "ResearchAgent",
    "ParsingAgent",
    "CopilotReader",
    "LLMClient",
    "OpenAICompatibleProvider",
]
