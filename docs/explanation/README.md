# Explanation

Architecture, rationale, and design choices behind GNAT.

| Topic | Description |
|-------|-------------|
| [Architecture](../architecture.md) | System overview: connectors, analysis, reporting, dissemination, telemetry |
| [Cross-Tool Investigation Model](cross-tool-investigation-model.md) | How SandGNAT, SenseGNAT, and RedGNAT attach outputs to GNAT investigations |
| [Rule Engine](rule-engine.md) | Why Hy, two-engine coexistence, advisor pattern, AI ceiling design |
| [Architecture Decision Records](architecture/adrs/README.md) | 55 ADRs documenting every design decision |
| [Diagrams](architecture/diagrams.md) | System architecture and data flow diagrams |
| [Implementation Plan](architecture/implementation-plan.md) | Build sequence and connector roadmap |
| **Automation** | |
| [Quality Agents](automation/quality-agents.md) | Fixture coverage, normalization regression, contract verification |
| [Security Agents](automation/security-agents.md) | Secrets hygiene and security scanning |
| [Secrets Broker](automation/secrets-broker-agent.md) | Credential management and provider abstraction |
| [Normalization Regression](automation/normalization-regression-agent.md) | Automated regression testing for STIX normalization |

---

> **Diataxis note:** Explanation docs are understanding-oriented.
> For task instructions, see the [How-to guides](../how-to/README.md).

---

*Licensed under the Apache License, Version 2.0*
