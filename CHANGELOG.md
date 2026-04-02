# Changelog

All notable changes to GNAT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detailed per-version release notes are available in [`docs/releases/`](docs/releases/).

---

## [v1.3.0] — Unreleased

9 new platform connectors (AWS Security Hub/GuardDuty, Cribl Stream, Datadog, Dragos, HIBP, SecurityScorecard, Synapse, Tanium, Trend Micro Vision One). Unified multi-LLM client (`LLMClient`) with Claude, OpenAI, and Grok backends and automatic fallback.

→ [Full release notes](docs/releases/v1.3.0.md)

---

## [v1.2.0] — 2026-03-30

25 new platform connectors across three batches (Censys, ServiceNow SecOps, Darktrace, ExtraHop, Lansweeper, Vectra, Sophos, Trellix, BitSight, Flashpoint, HudsonRock, Intel 471, UpGuard, Carbon Black, CortexXDR, Dragos, FortiEDR, FortiSIEM, FortiSOAR, Google Chronicle, GreyNoise, LogRhythm, Nozomi, Prisma Cloud, Shodan). CISA KEV connector. 89 new unit tests for previously untested connectors. Mass lint cleanup (4,647 auto-fixed issues + 141 manual fixes).

→ [Full release notes](docs/releases/v1.2.0.md)

---

## [v1.1.0] — 2026-03-30

13 new connectors (Armis, Axonius, Cortex Xpanse, CyCognito, DefectDojo, Greenbone, Group-IB, Orca, Qualys, SentinelOne, Tenable One, Wiz, ZeroFox). Optional Rust-accelerated IOC processing (`gnat-core`). Web dashboard, Textual TUI, TAXII 2.1 server, NLP query engine, STIX pattern validator, multi-tenant workspace isolation, XSOAR content pack generator, upstream contribution pipeline, connector health monitor, Solr/Grafana observability, Docker integration test harness, Jira connector, and numerous connector additions and fixes.

→ [Full release notes](docs/releases/v1.1.0.md)

---

## [v1.0.0] — 2026-03-28

First stable release. 29 platform connectors including SIEM/IDS/IPS platforms (Elastic, Graylog, MISP, OpenCTI, OSSIM, QRadar, Security Onion, Sentinel, Snort, Suricata, Wazuh, Zeek, ControlUp DEX, AlienVault OTX). Solr search sidecar. Report generation pipeline (PDF, HTML, DOCX, Markdown) with AI narration. AI agents (ResearchAgent, ParsingAgent, CopilotReader). Research Library with curation workflow.

→ [Full release notes](docs/releases/v1.0.0.md)

---

## [v0.9.0] — 2025-09-15

Research Library three-tier knowledge base (personal / staging / library workspaces) with TTL-based curation and INI configuration.

→ [Full release notes](docs/releases/v0.9.0.md)

---

## [v0.8.0] — 2025-07-01

AI agent integration: ResearchAgent (Claude-powered threat synthesis), ParsingAgent (unstructured text → STIX), and CopilotReader (Microsoft Copilot DirectLine). Config via `[claude]` INI section.

→ [Full release notes](docs/releases/v0.8.0.md)

---

## [v0.7.0] — 2025-05-15

Export pipeline with fluent builder API. 11 filter types (TypeFilter, ConfidenceFilter, TLPFilter, SectorFilter, etc.), EDL and Netskope CE transforms, and multiple delivery targets including EDLServer (FastAPI).

→ [Full release notes](docs/releases/v0.7.0.md)

---

## [v0.6.0] — 2025-04-01

Feed scheduling layer: `FeedScheduler`, `FeedJob`, `IngestJob`, cron expression support via croniter, and `gnat schedule` CLI subcommands.

→ [Full release notes](docs/releases/v0.6.0.md)

---

## [v0.3.0] — 2025-03-20

Async client (`AsyncGNATClient` on httpx). Full CLI (`gnat ping`, `query`, `list`, `ingest`, `codegen`, `config`). Visualization layer (TabularView, GraphView with sigma.js WebGL for 1000+ nodes, GrafanaServer, PowerBIExporter). Context system (GlobalContext, Workspace, WorkspaceManager, FlatFileStore/WorkspaceStore). Sphinx documentation. GitHub Actions CI/CD.

→ [Full release notes](docs/releases/v0.3.0.md)

---

## [v0.1.0] — 2025-03-19

Initial release. Core client layer (`GNATClient`, `BaseClient`, `CLIENT_REGISTRY`). STIX 2.1 ORM (`STIXBase` + 12 domain/observable types). 6 platform connectors (ThreatQ, CrowdStrike, Proofpoint, Netskope, XSOAR, Recorded Future). Ingestion framework with 14 source readers and 12 record mappers. OpenAPI code generator. Full unit and integration test scaffold.

→ [Full release notes](docs/releases/v0.1.0.md)

---

[Unreleased]: https://github.com/your-org/gnat/compare/v1.2.0...HEAD
[v1.3.0]: https://github.com/your-org/gnat/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/your-org/gnat/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/your-org/gnat/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/your-org/gnat/compare/v0.9.0...v1.0.0
[v0.9.0]: https://github.com/your-org/gnat/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/your-org/gnat/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/your-org/gnat/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/your-org/gnat/compare/v0.3.0...v0.6.0
[v0.3.0]: https://github.com/your-org/gnat/compare/v0.1.0...v0.3.0
[v0.1.0]: https://github.com/your-org/gnat/releases/tag/v0.1.0
