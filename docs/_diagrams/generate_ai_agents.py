# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Generate GNAT AI agent layer diagram.

Run from the repo root:
    python docs/_diagrams/generate_ai_agents.py

Output: docs/explanation/architecture/img/ai_agent_layer.png
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.compute import Rack
from diagrams.generic.storage import Storage
from diagrams.onprem.client import User
from diagrams.onprem.compute import Server
from diagrams.onprem.security import Vault
from diagrams.saas.chat import Slack

OUTPUT = os.path.join(
    os.path.dirname(__file__),
    "..",
    "explanation",
    "architecture",
    "img",
    "ai_agent_layer",
)

graph_attr = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "ortho",
}

with Diagram(
    "GNAT AI Agent Layer",
    filename=OUTPUT,
    show=False,
    direction="TB",
    graph_attr=graph_attr,
    outformat="png",
):
    caller = User("GNATClient /\nAnalyst Code")

    with Cluster("AI Agent Layer  (gnat/agents/)"):
        llm_client = Rack("LLMClient\nUnified Facade")

        with Cluster("Specialist Agents"):
            research_agent = Server("ResearchAgent\n(SourceReader)")
            parsing_agent = Server("ParsingAgent\n(RecordMapper)")
            drafting = Server("ReportDraftingAssistant")
            gap_detector = Server("GapDetector")

        with Cluster("Quality Agents  (gnat/agents/quality/)"):
            qa = Server("FixtureAgent\nNormAgent\nContractAgent")

        with Cluster("Security Agents  (gnat/agents/security/)"):
            sec = Vault("SecretsHygieneAgent")

    with Cluster("LLM Providers"):
        claude = Slack("Claude\n(Anthropic)")
        openai = Slack("OpenAI\n(GPT-4)")
        grok = Slack("Grok\n(xAI)")
        gemini = Slack("Gemini\n(Google)")

    with Cluster("Downstream"):
        stix_orm = Storage("STIX ORM\ngnat/orm/")
        ingest = Storage("IngestPipeline\n(SourceReader)")
        reports = Storage("ReportService\ngnat/reporting/")

    # Caller → agent layer
    caller >> llm_client

    # LLMClient → providers (with fallback)
    llm_client >> claude
    llm_client >> openai
    llm_client >> grok
    llm_client >> gemini

    # LLMClient → specialist agents
    llm_client >> research_agent
    llm_client >> parsing_agent
    llm_client >> drafting
    llm_client >> gap_detector

    # Agents → downstream integrations
    research_agent >> ingest
    parsing_agent >> stix_orm
    drafting >> reports
    gap_detector >> reports

print(f"Written → {OUTPUT}.png")
