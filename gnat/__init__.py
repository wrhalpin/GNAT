"""
GNAT: Cybersecurity Threat Management Swiss Army Knife
==========================================================

A universal client and ORM library for interacting with security platforms.
Provides a uniform abstraction layer over 29 threat intelligence and security
platforms, with STIX 2.1-compatible ORM objects and urllib3-based HTTP clients.

Quick Start::

    import gnat

    # Connect to a security platform
    cli = gnat.GNATClient()
    cli.connect(target="threatq")

    # ORM usage — object-oriented, client-bound
    ind = gnat.Indicator(client=cli, value="1.2.3.4", type="ip-addr")
    ind.id = "12"
    ind.select()
    print(ind.value)

Supported Targets:
    - ``threatq``        – ThreatQ Threat Intelligence Platform
    - ``proofpoint``     – Proofpoint TAP Email Security
    - ``netskope``       – Netskope SASE/SSE Platform
    - ``crowdstrike``    – CrowdStrike Falcon Platform
    - ``xsoar``          – Palo Alto XSOAR 6
    - ``recordedfuture`` – Recorded Future Intelligence Platform
    - ``splunk``         – Splunk Enterprise / Splunk ES
    - ``virustotal``     – VirusTotal
    - ``shadowserver``   – Shadowserver Foundation
    - ``rapid7``         – Rapid7 InsightVM / InsightIDR
    - ``nucleus``        – Nucleus Security
    - ``greymatter``     – GreyMatter
    - ``whistic``        – Whistic
    - ``riskrecon``      – RiskRecon
    - ``feedly``         – Feedly Threat Intelligence
    - ``controlup``      – ControlUp DEX
    - ``alienvault``     – AlienVault OTX
    - ``elastic``        – Elastic SIEM / Security
    - ``graylog``        – Graylog SIEM
    - ``misp``           – MISP
    - ``opencti``        – OpenCTI
    - ``ossim``          – AlienVault OSSIM
    - ``qradar``         – IBM QRadar
    - ``security_onion`` – Security Onion
    - ``sentinel``       – Microsoft Sentinel
    - ``snort``          – Snort IDS
    - ``suricata``       – Suricata IDS
    - ``wazuh``          – Wazuh SIEM
    - ``zeek``           – Zeek Network Monitor
"""

from gnat.client import GNATClient
from gnat.orm.indicator import Indicator
from gnat.orm.threat_actor import ThreatActor
from gnat.orm.malware import Malware
from gnat.orm.vulnerability import Vulnerability
from gnat.orm.attack_pattern import AttackPattern
from gnat.orm.observable import Observable
from gnat.orm.relationship import Relationship
from gnat.config import GNATConfig

from gnat.export import ExportPipeline, ExportResult
from gnat.export.jobs import ExportJob

from gnat.reports import (
    ReportGenerator, ReportJob, ReportConfig, AIMode, SectorFilter,
)
from gnat.research import ResearchLibrary, ResearchEntry, CurationJob
from gnat.agents import AgentConfig, ResearchAgent, ParsingAgent, CopilotReader
from gnat.schedule import FeedJob, FeedScheduler, JobRunContext, RunRecord
from gnat.viz import TabularView, GraphView, PowerBIExporter, grafana_dashboard, save_grafana_dashboard
from gnat.context import (
    GlobalContext, GlobalContextRegistry,
    Workspace, WorkspaceManager, CommitResult, FlatFileStore,
)
from gnat.ingest import IngestPipeline
from gnat.ingest.sources import (
    PlainTextReader, CSVReader, JSONReader, JSONLReader,
    STIXBundleReader, TAXIICollectionReader, SQLReader,
    MISPReader, SyslogReader, RSSReader, EmailReader,
    OpenIOCReader, SplunkReader, ElasticReader,
)
from gnat.ingest.mappers import (
    FlatIOCMapper, STIXPassthroughMapper, MISPAttributeMapper,
    CEFMapper, SQLRowMapper, CSVIndicatorMapper, RSSEntryMapper,
    EmailIOCMapper, OpenIOCMapper, SplunkResultMapper,
    ElasticResultMapper, NVDCVEMapper,
)

__version__ = "0.1.0"
__author__ = "GNAT Contributors"
__all__ = [
    "GNATClient",
    "GNATConfig",
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
    # Export
    "ExportPipeline", "ExportResult", "ExportJob",
    # Reports
    "ReportGenerator", "ReportJob", "ReportConfig", "AIMode", "SectorFilter",
    # Research
    "ResearchLibrary", "ResearchEntry", "CurationJob",
    # Agents
    "AgentConfig", "ResearchAgent", "ParsingAgent", "CopilotReader",
    # Scheduling
    "FeedJob", "FeedScheduler", "JobRunContext", "RunRecord",
    # Visualization
    "TabularView", "GraphView", "PowerBIExporter",
    "grafana_dashboard", "save_grafana_dashboard",
    # Context system
    "GlobalContext", "GlobalContextRegistry",
    "Workspace", "WorkspaceManager", "CommitResult", "FlatFileStore",
]
