# How-to: Use the Analysis Layer

Work with confidence scoring, TLP classification, analyst investigations,
cross-platform correlation, timelines, evidence graphs, and AI-assisted
report drafting.

---

## Confidence scoring (NATO Admiralty Scale)

GNAT uses the **NATO Admiralty Scale** — the standard CTI confidence framework
that separates *source reliability* from *information credibility* — combined
with a STIX 2.1 numeric confidence value (0–100).

```python
from gnat.analysis.confidence import (
    ConfidenceScore,
    ConfidenceLevel,
    SourceReliability,
    InformationCredibility,
)

# Full constructor
score = ConfidenceScore(
    source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
    information_credibility = InformationCredibility.PROBABLY_TRUE,
    stix_confidence         = 75,
    rationale               = "Cross-corroborated by two independent sources.",
)

print(score.band)    # "HIGH"
print(score.label)   # "B2 (HIGH)"
print(score.stix_confidence)  # 75

# Convenience factories
high   = ConfidenceScore.high(rationale="Confirmed by trusted partner.")
medium = ConfidenceScore.medium()
low    = ConfidenceScore.low(rationale="Single unverified source.")

# Serialise / deserialise
d     = score.to_dict()
score2 = ConfidenceScore.from_dict(d)
```

Source reliability grades (A–F) and information credibility grades (1–6)
follow NATO STANAG 2511. The `ConfidenceLevel` enum maps to HIGH / MEDIUM / LOW
bands for downstream filters that don't need the full granularity.

---

## TLP classification

```python
from gnat.analysis.tlp import TLPLevel

level = TLPLevel.AMBER
print(level.label)    # "TLP:AMBER"
print(level.colour)   # "#FFA500"

# TLP 2.0 — AMBER+STRICT restricts sharing to the recipient's own org only
strict = TLPLevel.AMBER_STRICT
print(strict.label)   # "TLP:AMBER+STRICT"

# Ordering — higher rank = more restrictive
assert TLPLevel.RED > TLPLevel.AMBER > TLPLevel.GREEN

# All levels: WHITE (legacy) / CLEAR / GREEN / AMBER / AMBER_STRICT / RED
```

---

## Analyst investigations

```python
import os
from gnat.analysis.investigations import (
    Investigation,
    InvestigationService,
    InvestigationStore,
    InvestigationStatus,
    Hypothesis,
    AnalystNote,
    InvestigationTask,
)

# One-time setup (SQLite or Postgres via SQLAlchemy URL)
store   = InvestigationStore("sqlite:///" + os.path.expanduser("~/.gnat/gnat.db"))
store.create_all()
service = InvestigationService(store)

# Create an investigation
inv = service.create(
    title      = "APT28 Campaign — Apr 2026",
    created_by = "analyst@example.com",
    tlp        = TLPLevel.AMBER,
    tags       = ["apt28", "phishing", "healthcare"],
)

# Transition through the lifecycle
# OPEN → IN_PROGRESS → REVIEW → CLOSED
service.transition(inv.id, InvestigationStatus.IN_PROGRESS)

# Add hypotheses
service.add_hypothesis(
    inv.id,
    statement = "APT28 used spear-phishing to gain initial access.",
    created_by = "analyst@example.com",
)

# Add analyst notes
service.add_note(inv.id, text="Pivoting on 185.220.101.5 found 3 related domains.", author="analyst@example.com")

# Add tasks
service.add_task(inv.id, title="Extract email headers from INC-4892", assigned_to="analyst2@example.com")

# Link evidence
service.link_indicators(inv.id, ["indicator--abc123", "indicator--def456"])
service.link_observables(inv.id, ["observed-data--xyz789"])
service.link_threat_actors(inv.id, ["threat-actor--apt28-id"])

# Get a summary
summary = service.summary(inv.id)
print(summary)

# Close the investigation
service.transition(inv.id, InvestigationStatus.CLOSED)
```

---

## Cross-platform correlation

Deduplicate and correlate indicators observed across multiple platforms:

```python
from gnat.analysis.correlation import (
    EntityResolver,
    IndicatorRecord,
    RelationshipScorer,
    ClusterDetector,
    EnrichmentDispatcher,
)

# Build platform-sourced records
records = [
    IndicatorRecord("threatq",    "185.220.101.5",    "ipv4-addr", "501"),
    IndicatorRecord("greymatter", "185.220.101.5",    "ipv4-addr", "obs-301"),
    IndicatorRecord("xsoar",      "evil-corp.com",    "domain",    "ind-009"),
    IndicatorRecord("crowdstrike","evil-corp.com",    "domain",    "cs-4421"),
]

# Resolve cross-platform aliases into EntityGroups
resolver = EntityResolver()
groups   = resolver.resolve(records)          # dict: canonical_key → EntityGroup

for key, group in groups.items():
    if group.is_cross_platform:
        print(f"{key}: seen on {group.platforms} — max confidence {group.max_confidence}")

# Score entity-to-entity relationship strength
scorer = RelationshipScorer()
for g1, g2 in itertools.combinations(groups.values(), 2):
    score = scorer.score(g1, g2)
    print(f"{g1.canonical_key} ↔ {g2.canonical_key}: {score.label}")

# Cluster related indicators (shared /24, tags, timing)
detector  = ClusterDetector()
clusters  = detector.detect(list(groups.values()))
for cluster in clusters:
    print(f"Cluster ({cluster.confidence.band}): {cluster.member_ids}")

# Enrich a value across all registered connectors
dispatcher = EnrichmentDispatcher({
    "virustotal": vt_client,
    "shodan":     shodan_client,
    "greynoise":  gn_client,
})
result = dispatcher.enrich("185.220.101.5")
print(result)   # dict: platform → raw enrichment data (or None on error)
```

---

## Timeline reconstruction

Build a chronological view from investigations or evidence graphs:

```python
from gnat.analysis.timeline import TimelineBuilder, TimelineEvent, TimelineEventType

builder = TimelineBuilder()

# From an Investigation object
events = builder.from_investigation(investigation)

# From an EvidenceGraph (gnat.investigations)
events = builder.from_evidence_graph(evidence_graph)

# From raw platform records
events = builder.from_records([
    {"timestamp": "2026-04-01T08:00:00Z", "title": "Alert INC-4892 opened", "source": "xsoar"},
    {"timestamp": "2026-04-02T14:30:00Z", "title": "C2 domain resolved",    "source": "dns_log"},
])

for event in sorted(events, key=lambda e: e.timestamp):
    print(f"[{event.event_type.value}] {event.timestamp.isoformat()}  {event.title}")
```

---

## Evidence graph queries

Pivot and explore an `EvidenceGraph` (built by `gnat.investigations.InvestigationBuilder`)
without a separate graph database:

```python
from gnat.analysis.graph import GraphQuery, GraphContext

gq = GraphQuery(evidence_graph)

# Pivot: all entities related to a node within 2 hops
context = gq.pivot("xsoar::incident::INC-4892", hops=2)

# Expand: add immediate neighbours of a set of nodes
context = gq.expand(context, node_ids=["xsoar::indicator::185.220.101.5"])

# Filter: restrict by confidence, date range, or platform
context = gq.filter(
    context,
    min_confidence = 0.6,
    platforms      = ["xsoar", "threatq"],
    after          = datetime(2026, 4, 1),
)

print(f"Nodes: {context.node_count}, Edges: {context.edge_count}")
print(f"Platforms covered: {context.platforms()}")

# Shortest path between two nodes
path = gq.shortest_path(
    "xsoar::incident::INC-4892",
    "crowdstrike::indicator::evil-corp.com",
)
print(path)  # list of node IDs
```

---

## Evidence gap detection

Identify what is logically missing to support or refute a hypothesis:

```python
from gnat.analysis.copilot.gap_detector import GapDetector

detector = GapDetector()

# Single hypothesis
hypothesis = investigation.hypothesis[0]
gaps       = detector.detect(hypothesis, investigation)
for gap in gaps:
    print(f"[{gap.severity}] {gap.description}")
    print(f"  → {gap.suggested_action}")

# All hypotheses at once
all_gaps = detector.detect_all(investigation)
summary  = detector.summary(investigation)
print(summary)   # {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 1}
```

---

## AI-assisted report drafting

Generate an executive summary and key-findings narrative draft with an LLM
(requires `[claude]` or another AI backend configured in `gnat.ini`):

```python
from gnat.agents.llm import LLMClient
from gnat.analysis.copilot.drafting import ReportDraftingAssistant

llm       = LLMClient.from_ini()
assistant = ReportDraftingAssistant(llm_client=llm)

# Draft executive summary only
result = assistant.draft_executive_summary(report)
print(result.executive_summary)
print(f"Tokens used: {result.prompt_tokens} + {result.completion_tokens}")

# Draft key findings narrative only
result = assistant.draft_key_findings(report)
print(result.key_findings_narrative)

# Draft both in a single pass
result = assistant.draft_full(report)
print(result.executive_summary)
print(result.key_findings_narrative)

# Apply after analyst review
from gnat.reporting import ReportService
service.update_summary(report.id, result.executive_summary)
```

If no LLM is configured, `ReportDraftingAssistant` returns placeholder text
with a warning rather than raising an exception.

---

## See Also

- [How-to: Build Cross-Platform Investigations](build-investigations.md)
- [How-to: Create Intelligence Reports](create-intelligence-reports.md)
- [How-to: Disseminate Intelligence](disseminate-intelligence.md)
- [Explanation: Analysis Layer Architecture](../explanation/architecture/adrs/0031-ADR-analysis-layer-architecture.md)
- [Explanation: Confidence Scoring Model](../explanation/architecture/adrs/0033-ADR-confidence-scoring.md)

---

*Licensed under the Apache License, Version 2.0*
