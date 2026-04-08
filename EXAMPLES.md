# GNAT Examples

> The examples from this file have been reorganised into individual documents
> following the [Diátaxis](https://diataxis.fr/) documentation framework.
> This file is kept as a navigation index.

---

## Tutorials — learning by doing

Complete, end-to-end walkthroughs.

- [Daily SOC Workflow](docs/tutorials/daily-soc-workflow.md) — research, curate, push EDL
- [Production Scheduled Pipeline](docs/tutorials/production-scheduled-pipeline.md) — long-running ingest/export/report server
- [Analyst Intelligence Workflow](docs/tutorials/analyst-intelligence-workflow.md) — cross-platform investigation → structured report → publish

---

## How-to Guides — solving a task

| Task | Guide |
|------|-------|
| Connect to ThreatQ, VirusTotal, Rapid7, and more | [Connect to Platforms](docs/how-to/connect-to-platforms.md) |
| Create and serialize STIX objects | [Work with STIX Objects](docs/how-to/work-with-stix-objects.md) |
| Pull data from blocklists, TAXII, CSV, Splunk | [Run the Ingest Pipeline](docs/how-to/run-ingest-pipeline.md) |
| Manage investigation workspaces | [Use Workspaces](docs/how-to/use-workspaces.md) |
| Deliver indicators to EDLs and Netskope CE | [Export Indicators](docs/how-to/export-indicators.md) |
| Schedule recurring ingest/export jobs | [Schedule Feeds](docs/how-to/schedule-feeds.md) |
| AI research, parsing, and M365 ingestion | [Use AI Agents](docs/how-to/use-ai-agents.md) |
| Cache and reuse threat research | [Use the Research Library](docs/how-to/use-research-library.md) |
| Generate PDF/HTML/DOCX reports | [Generate Reports](docs/how-to/generate-reports.md) |
| Graphs, timelines, heatmaps, tables | [Visualize Data](docs/how-to/visualize-data.md) |
| Concurrent multi-platform data gathering | [Use the Async Client](docs/how-to/use-async-client.md) |
| Confidence scoring, TLP, correlation, gap detection | [Use the Analysis Layer](docs/how-to/use-analysis-layer.md) |
| Cross-platform evidence graph from multiple platforms | [Build Cross-Platform Investigations](docs/how-to/build-investigations.md) |
| Structured intelligence product lifecycle | [Create Intelligence Reports](docs/how-to/create-intelligence-reports.md) |
| Export, webhooks, TAXII, REST gateway | [Disseminate Intelligence](docs/how-to/disseminate-intelligence.md) |

---

## Reference — exact technical details

- [Configuration](docs/reference/configuration.md) — INI file format and all section keys

---

## Explanation — design rationale

Architecture Decision Records live in
[docs/explanation/architecture/adrs/](docs/explanation/architecture/adrs/).

---

*Licensed under the Apache License, Version 2.0*
