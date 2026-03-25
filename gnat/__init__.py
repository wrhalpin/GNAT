"""
CTM-SAK: Cybersecurity Threat Management Swiss Army Knife
==========================================================

A universal client and ORM library for interacting with security platforms.
Provides a uniform abstraction layer over ThreatQ, Proofpoint, Netskope,
CrowdStrike, XSOAR 6, and Recorded Future, with STIX 2.1-compatible ORM
objects and urllib3-based HTTP clients.

Quick Start::

    import ctm_sak

    # Connect to a security platform
    cli = ctm_sak.SAKClient()
    cli.connect(target="threatq")

    # ORM usage — object-oriented, client-bound
    ind = ctm_sak.Indicator(client=cli, value="1.2.3.4", type="ip-addr")
    ind.id = "12"
    ind.select()
    print(ind.value)

Supported Targets:
    - ``threatq``       – ThreatQ Threat Intelligence Platform
    - ``proofpoint``    – Proofpoint Email Security
    - ``netskope``      – Netskope SASE/SSE Platform
    - ``crowdstrike``   – CrowdStrike Falcon Platform
    - ``xsoar``         – Palo Alto XSOAR 6
    - ``recordedfuture``– Recorded Future Intelligence Platform
"""

from ctm_sak.client import SAKClient
from ctm_sak.orm.indicator import Indicator
from ctm_sak.orm.threat_actor import ThreatActor
from ctm_sak.orm.malware import Malware
from ctm_sak.orm.vulnerability import Vulnerability
from ctm_sak.orm.attack_pattern import AttackPattern
from ctm_sak.orm.observable import Observable
from ctm_sak.orm.relationship import Relationship
from ctm_sak.config import SAKConfig






from ctm_sak.export import ExportPipeline, ExportResult
from ctm_sak.export.jobs import ExportJob



from ctm_sak.reports import (
    ReportGenerator, ReportJob, ReportConfig, AIMode, SectorFilter,
)
from ctm_sak.research import ResearchLibrary, ResearchEntry, CurationJob
from ctm_sak.agents import AgentConfig, ResearchAgent, ParsingAgent, CopilotReader
from ctm_sak.schedule import FeedJob, FeedScheduler, JobRunContext, RunRecord
from ctm_sak.viz import TabularView, GraphView, PowerBIExporter, grafana_dashboard, save_grafana_dashboard
from ctm_sak.context import (
    GlobalContext, GlobalContextRegistry,
    Workspace, WorkspaceManager, CommitResult, FlatFileStore,
)
from ctm_sak.ingest import IngestPipeline
from ctm_sak.ingest.sources import (
    PlainTextReader, CSVReader, JSONReader, JSONLReader,
    STIXBundleReader, TAXIICollectionReader, SQLReader,
    MISPReader, SyslogReader, RSSReader, EmailReader,
    OpenIOCReader, SplunkReader, ElasticReader,
)
from ctm_sak.ingest.mappers import (
    FlatIOCMapper, STIXPassthroughMapper, MISPAttributeMapper,
    CEFMapper, SQLRowMapper, CSVIndicatorMapper, RSSEntryMapper,
    EmailIOCMapper, OpenIOCMapper, SplunkResultMapper,
    ElasticResultMapper, NVDCVEMapper,
)
__version__ = "0.1.0"
__author__ = "CTM-SAK Contributors"
__all__ = [
    "SAKClient",
    "SAKConfig",
    "Indicator",
    "ThreatActor",
    "Malware",
    "Vulnerability",
    "AttackPattern",
    "Observable",
    "Relationship",
    # Ingest pipeline
    "IngestPipeline",
    # Source readers
    "PlainTextReader", "CSVReader", "JSONReader", "JSONLReader",
    "STIXBundleReader", "TAXIICollectionReader", "SQLReader",
    "MISPReader", "SyslogReader", "RSSReader", "EmailReader",
    "OpenIOCReader", "SplunkReader", "ElasticReader",
    # Mappers
    "FlatIOCMapper", "STIXPassthroughMapper", "MISPAttributeMapper",
    "CEFMapper", "SQLRowMapper", "CSVIndicatorMapper", "RSSEntryMapper",
    "EmailIOCMapper", "OpenIOCMapper", "SplunkResultMapper",
    "ElasticResultMapper", "NVDCVEMapper",
    # Context system
    "GlobalContext", "GlobalContextRegistry",
    "Workspace", "WorkspaceManager", "CommitResult", "FlatFileStore",
]
