# ADR-0051: Attribution & Campaign Tracking

**Decision:** Implement attribution and campaign tracking as a core
extension at `gnat/analysis/attribution/`, with a Campaign ORM SDO,
four-state campaign lifecycle, competing attribution hypotheses with
Admiralty Scale scoring, Diamond Model analysis, kill-chain
progression, infrastructure classification, and actor profiles.

**Problem statement:**
GNAT's analysis layer (ADR-0031) provides investigations, correlation,
and confidence scoring, but has no formal model for campaigns, threat
actor attribution, or kill-chain tracking. Analysts track campaigns
in spreadsheets or external tools, breaking the provenance chain from
raw indicators to finished attribution. The existing `ClusterDetector`
groups related indicators but has no mechanism to promote clusters to
named campaigns or attach competing attribution hypotheses.

## Core extension, not plugin

Attribution lives at `gnat/analysis/attribution/` rather than
`gnat/plugins/` because it has deep coupling to core internals:

- **ORM**: `Campaign` is a new STIX SDO (`gnat/orm/campaign.py`)
- **EvidenceGraph**: `DiamondAnalyzer` walks the graph to infer ACIV tuples
- **ClusterDetector**: `CampaignBuilder` consumes cluster output
- **RelationshipScorer**: `AttributionEngine` delegates confidence computation
- **ConfidenceScore**: All attribution assertions use ADR-0033 scoring
- **InvestigationService**: Campaigns link to investigations bidirectionally

A plugin boundary would require re-exporting most of `gnat.analysis`
internals, creating a facade that adds complexity without isolation benefit.

## Campaign lifecycle

```
SUSPECTED → ACTIVE → DORMANT → CONCLUDED (terminal)
              ↑         │
              └─────────┘
```

**Why four states, not two (open/closed):**
Campaigns have observable dormancy periods — the adversary pauses
operations, infrastructure goes quiet, no new indicators appear.
Dormancy is analytically distinct from conclusion: dormant campaigns
may reactivate (and frequently do). A two-state model forces analysts
to either close prematurely (losing context) or keep everything open
indefinitely (drowning in noise).

CONCLUDED is terminal — no reactivation. If a concluded campaign
resurfaces, it should be tracked as a new campaign linked via
`parent_campaign_id`.

## Competing hypotheses with Admiralty Scale

Each attribution is modeled as an `AttributionHypothesis` with:
- `campaign_id` + `threat_actor_id` (what's being attributed to whom)
- `confidence: ConfidenceScore` (NATO Admiralty Scale from ADR-0033)
- `status: HypothesisStatus` (OPEN / SUPPORTED / REFUTED / INCONCLUSIVE)
- `supporting_evidence` / `contradicting_evidence`
- `confidence_history: list[ConfidenceSnapshot]` (tracked over time)
- `source: "analyst" | "cluster_detector" | "ai_copilot"`

**Why not simple labels:**
Attribution is inherently uncertain and often contested. Labeling a
campaign as "APT28" without confidence context, evidence trail, or
competing alternatives creates false certainty. Multiple hypotheses
can coexist until evidence resolves them.

**AI confidence ceiling:** Machine-generated attributions
(`source="ai_copilot"`) are capped at confidence 60
(`AI_CONFIDENCE_CEILING`). AI can suggest attributions but cannot
achieve "Confirmed" status without analyst review. This follows the
pattern established in ADR-0033.

## Diamond Model as data, not visualization

`DiamondVertex` is a pure dataclass storing ACIV
(Adversary-Capability-Infrastructure-Victim) tuples:

```python
@dataclass
class DiamondVertex:
    adversary: str | None
    capability: list[str]
    infrastructure: list[str]
    victim: list[str]
    confidence: ConfidenceScore
    phase: str | None       # ATT&CK tactic
    result: str | None      # success / failure / unknown
```

`DiamondAnalyzer` walks the EvidenceGraph to infer ACIV tuples from
node types and edges. `find_pivot_points()` identifies infrastructure
reused across tuples — a key indicator of shared adversary operations.

**Rationale:** The Diamond Model is an analytical framework, not a
rendering format. Storing ACIV tuples as structured data lets any
consumer (CLI table, web UI, PDF report, STIX export) render them
appropriately. Coupling the model to a specific visualization would
limit reuse.

## Kill-chain tracking

`KillChainTracker` uses a 14-phase ATT&CK tactic ordering:

```
TA0043 Reconnaissance → TA0042 Resource Development → TA0001 Initial Access →
... → TA0010 Exfiltration → TA0040 Impact
```

`KillChainProgression` computes coverage percentage, identifies the
deepest phase reached, and lists unobserved gaps. Progression is
computed from linked technique IDs, not manually sequenced.

## Infrastructure classification

`InfrastructureClassifier` labels indicators by operational role:
C2, STAGING, EXFILTRATION, DELIVERY, PROXY, CREDENTIAL_HARVEST, UNKNOWN.

Classification priority:
1. STIX `infrastructure_types` (highest — explicit analyst labeling)
2. Kill-chain phase hints (TA0011→C2, TA0001→DELIVERY, etc.)
3. Port heuristics ({443, 8443, 4443, 8080, 80}→C2)
4. Default: UNKNOWN

AI classifications are capped at confidence 60. Rule-based
classifications inherit the source indicator's confidence.

## CampaignBuilder promotion

`CampaignBuilder.promote()` converts a `Cluster` from
`ClusterDetector` output into a formal `CampaignProfile`. The
promotion carries over:
- All cluster indicator IDs → `campaign.indicator_ids`
- Extracted technique IDs → `campaign.observed_techniques`
- Cluster confidence → campaign initial confidence
- Cluster label → campaign name (analyst-editable)

This bridges the automated correlation layer and the analyst-managed
campaign layer without requiring manual re-entry.

## Persistence

Follows the `InvestigationStore` pattern (ADR-0031): SQLAlchemy with
indexed metadata columns + full JSON blob. Three tables: `campaigns`,
`actor_profiles`, `attribution_hypotheses`. Gated behind
`pip install "gnat[analysis]"` (SQLAlchemy).

→ See: `gnat/analysis/attribution/`
→ Related: ADR-0031 (Analysis Layer Architecture — persistence pattern)
→ Related: ADR-0033 (Confidence Scoring — Admiralty Scale reuse)
→ Related: ADR-0034 (Report Lifecycle — lifecycle pattern reuse)
