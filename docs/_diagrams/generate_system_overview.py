# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Generate GNAT system overview architectural diagram.

Run from the repo root:
    python docs/_diagrams/generate_system_overview.py

Output: docs/explanation/architecture/img/system_overview.png
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall, Router, Switch
from diagrams.generic.storage import Storage
from diagrams.onprem.analytics import Spark
from diagrams.onprem.client import Users
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.monitoring import Grafana
from diagrams.onprem.network import Nginx
from diagrams.onprem.security import Vault
from diagrams.programming.language import Python

OUTPUT = os.path.join(
    os.path.dirname(__file__),
    "..",
    "explanation",
    "architecture",
    "img",
    "system_overview",
)

graph_attr = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "ortho",
}

node_attr = {
    "fontsize": "11",
}

with Diagram(
    "GNAT System Overview",
    filename=OUTPUT,
    show=False,
    direction="TB",
    graph_attr=graph_attr,
    node_attr=node_attr,
    outformat="png",
):
    analyst = Users("Analyst / SOC")
    ci = Server("CI / Automation")

    with Cluster("User Interfaces"):
        cli = Python("CLI (gnat/cli)")
        tui = Python("TUI (gnat/tui)")
        api = Nginx("REST API (gnat/serve)")

    with Cluster("GNATClient Facade\ngnat/client.py"):
        facade = Rack("GNATClient")

    with Cluster("Core Pipelines"):
        with Cluster("Ingestion\ngnat/ingest"):
            ingest = Spark("IngestPipeline")
        with Cluster("Analysis\ngnat/analysis"):
            analysis = Server("AnalysisLayer")
        with Cluster("AI Agents\ngnat/agents"):
            agents = Server("LLMClient")
        with Cluster("Research\ngnat/research"):
            research = Server("ResearchLibrary")

    with Cluster("Intelligence Products"):
        with Cluster("Reporting\ngnat/reporting"):
            reporting = Storage("ReportService")
        with Cluster("Dissemination\ngnat/dissemination"):
            dissemination = Router("ExportService")

    with Cluster("Data Layer"):
        with Cluster("STIX 2.1 ORM\ngnat/orm"):
            orm = PostgreSQL("STIXBase")
        with Cluster("Context & Workspace\ngnat/context"):
            workspace = Storage("Workspace")
        with Cluster("Search Sidecar\ngnat/search"):
            search = Vault("Solr Index")

    with Cluster("Platform Connectors\ngnat/connectors  (158 platforms)"):
        connectors = Switch("ConnectorMixin")

    with Cluster("HTTP Client Layer"):
        http_sync = Server("urllib3 (sync)")
        http_async = Server("httpx (async)")

    with Cluster("Scheduling\ngnat/schedule"):
        scheduler = Firewall("FeedScheduler")

    with Cluster("Observability"):
        grafana = Grafana("Grafana")

    # User entry points
    analyst >> cli
    analyst >> tui
    analyst >> api
    ci >> api

    # Entry points → facade
    cli >> facade
    tui >> facade
    api >> facade

    # Facade → core pipelines
    facade >> ingest
    facade >> analysis
    facade >> agents
    facade >> research

    # Core pipelines → data layer
    ingest >> orm
    analysis >> orm
    agents >> orm
    research >> orm

    # ORM ↔ workspace & search
    orm >> workspace
    orm >> search

    # Pipelines → intelligence products
    analysis >> reporting
    reporting >> dissemination

    # Connectors ↔ HTTP
    connectors >> http_sync
    connectors >> http_async

    # Facade ↔ connectors
    facade >> connectors

    # Scheduling
    scheduler >> ingest

    # Observability
    workspace >> grafana

print(f"Written → {OUTPUT}.png")
