# How-to Guides

Task-oriented guides that answer "how do I accomplish X?"
Pick the guide for your goal — no need to read them in order.

| Guide | Description |
|-------|-------------|
| [Connect to Platforms](connect-to-platforms.md) | Authenticate and query ThreatQ, VirusTotal, ShadowServer, Rapid7, Nucleus, and more |
| [Use Abuse.ch Feeds](use-abuse-ch-feeds.md) | Query URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, and SSLBL through the unified `abusech` connector |
| [Work with STIX Objects](work-with-stix-objects.md) | Create, relate, and serialize STIX 2.1 objects using the GNAT ORM |
| [Run the Ingest Pipeline](run-ingest-pipeline.md) | Pull data from blocklists, TAXII feeds, CSV files, and Splunk |
| [Use Workspaces](use-workspaces.md) | Manage investigation workspaces and a global context registry |
| [Export Indicators](export-indicators.md) | Deliver indicators to Palo Alto EDLs, Netskope CE, and STIX bundle files |
| [Schedule Feeds](schedule-feeds.md) | Configure recurring ingest and export jobs with `FeedScheduler` |
| [Use AI Agents](use-ai-agents.md) | Run AI-assisted research, parsing, and M365 content ingestion |
| [Use the Research Library](use-research-library.md) | Cache, curate, and reuse threat research results |
| [Generate Reports](generate-reports.md) | Create PDF/HTML/DOCX reports with or without AI assistance |
| [Visualize Data](visualize-data.md) | Render graphs, timelines, risk heatmaps, and tables |
| [Use the Async Client](use-async-client.md) | Gather data from multiple platforms concurrently |
| [Use the Analysis Layer](use-analysis-layer.md) | Confidence scoring, TLP, analyst investigations, correlation, timelines, graph queries, and AI-assisted drafting |
| [Build Cross-Platform Investigations](build-investigations.md) | Collect and correlate evidence from multiple platforms into a unified evidence graph |
| [Create Intelligence Reports](create-intelligence-reports.md) | Author structured intelligence products with a formal lifecycle and STIX 2.1 export |
| [Disseminate Intelligence](disseminate-intelligence.md) | Export, webhook notifications, TAXII 2.1 serving, and REST API gateway |
| **Phase 4 — Control, Reasoning, Safety** | |
| [Use the Execution Context](use-execution-context.md) | Create and propagate `ExecutionContext`; enforce domain boundaries and trust levels; track query budgets |
| [Use the Reasoning Engine](use-reasoning-engine.md) | Score and rank observables; propose, evaluate, and close hypotheses; track negative evidence |
| [Agent Governance](agent-governance.md) | Permission checks, rate limiting, HITL review, XSOAR escalation, and agent audit trails |

---

> **Diataxis note:** How-to guides are task-oriented.
> For background understanding, see the [Explanation docs](../explanation/architecture/adrs/).
> For exact API details, see the [Reference docs](../reference/).

---

*Licensed under the Apache License, Version 2.0*
