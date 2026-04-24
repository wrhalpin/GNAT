# Cross-Tool Investigation Model

This document explains the design and rationale behind GNAT's cross-tool
investigation context — the mechanism that lets addon tools (SandGNAT,
SenseGNAT, RedGNAT) attach their output to GNAT investigations using
shared STIX properties.

For the formal property schema, see
[Investigation Context Schema Reference](../reference/investigation-context-schema.md).
For the architectural decision, see
[ADR-0055](architecture/adrs/0055-ADR-cross-tool-investigation-context.md).

---

## Why this model exists

GNAT's CTI lifecycle begins with collection (connectors, ingest
pipeline) and flows through analysis (investigations, correlation,
hypotheses) to dissemination (reports, STIX bundles, TAXII server).
Three addon tools extend this lifecycle by generating evidence that
feeds back into GNAT:

- **SandGNAT** detonates malware samples and produces extracted IOCs,
  behavioural reports, and STIX-formatted detonation results.
- **SenseGNAT** processes network sensor data (pcap, flow records,
  alerts) and produces STIX observables correlated to known threats.
- **RedGNAT** executes attack techniques against target environments
  and produces validation artifacts that confirm or refute exposure
  hypotheses.

Before the cross-tool investigation context, addon output arrived as
standalone STIX bundles. Analysts had to manually associate sandbox
results with the right investigation, match sensor alerts to ongoing
hunts, and cross-reference red team findings by timestamp. This
manual step broke the provenance chain and did not scale.

The cross-tool investigation context solves this by defining three
custom STIX properties (`x_gnat_investigation_id`,
`x_gnat_investigation_origin`, `x_gnat_investigation_link_type`) that
addons stamp on their output before sending it to GNAT. GNAT's ingest
pipeline reads these properties and automatically files the objects
into the correct investigation.

---

## How each addon participates

### SandGNAT (malware sandbox)

SandGNAT is invoked when an analyst submits a sample for detonation
from within an investigation. GNAT passes the `investigation_id` to
SandGNAT as a parameter. SandGNAT runs the detonation, produces STIX
objects (indicators for extracted C2 domains, malware SDOs, observed-data
for runtime behaviour), stamps each with the three properties, wraps
them in a Grouping, and sends the bundle back via TAXII.

Typical property values:
- `x_gnat_investigation_origin`: `"sandgnat"`
- `x_gnat_investigation_link_type`: `"confirmed"` (the analyst
  explicitly triggered the detonation in the context of this
  investigation)

### SenseGNAT (network sensors)

SenseGNAT runs continuously, processing network telemetry. It may be
configured to watch for IOCs associated with specific investigations.
When SenseGNAT detects traffic matching a watched IOC, it produces
STIX observed-data objects and stamps them with the investigation
context.

Because the correlation is automated (not analyst-initiated), the
typical link type is `"inferred"`:
- `x_gnat_investigation_origin`: `"sensegnat"`
- `x_gnat_investigation_link_type`: `"inferred"`

SenseGNAT may also produce objects with no investigation context
(general alerting). These are ingested normally and may later be
linked to investigations by GNAT's correlation engine.

### RedGNAT (red teaming)

RedGNAT is invoked when an analyst wants to validate an exposure
hypothesis — for example, confirming whether a specific ATT&CK
technique can succeed against the target environment. GNAT passes
the investigation context and the specific hypothesis to test.

RedGNAT executes the technique, records the result (success, failure,
partial), and produces STIX objects describing the execution. The
link type is `"confirmed"` because the analyst explicitly chose this
investigation and hypothesis:
- `x_gnat_investigation_origin`: `"redgnat"`
- `x_gnat_investigation_link_type`: `"confirmed"`

RedGNAT results are particularly valuable as hypothesis evidence —
they can directly support or refute hypotheses by demonstrating
whether a technique actually works in the target environment.

### GNAT core (internal correlation)

GNAT's correlation engine may also stamp objects with investigation
context when it discovers links between existing workspace objects
and investigations. In this case:
- `x_gnat_investigation_origin`: `"gnat"`
- `x_gnat_investigation_link_type`: `"inferred"` or `"suggested"`
- `x_gnat_correlation_confidence`: 0-100 (set only by GNAT core)

AI-assisted correlation (via the NLP or parsing agents) is capped
at confidence 60, consistent with the AI confidence ceiling policy.

---

## Relationship to existing primitives

### Investigation (`gnat.analysis.investigations`)

The `Investigation` dataclass (ADR-0031) is the authoritative owner of
investigation identity. Its `id` field is the UUID that populates
`x_gnat_investigation_id` on stamped objects. Key properties that
interact with the cross-tool context:

- `Investigation.indicators` — addon-produced indicator IDs are
  appended here on filing
- `Investigation.observables` — addon-produced observable IDs are
  appended here on filing
- `Investigation.source_connectors` — the addon's origin value
  (e.g., `"sandgnat"`) is added to this list, providing a record of
  which tools contributed to the investigation
- `Investigation.hypothesis` — RedGNAT results can be linked as
  supporting or refuting evidence on specific hypotheses

Addons never create `Investigation` objects. Investigation lifecycle
(OPEN, IN_PROGRESS, REVIEW, CLOSED) is managed exclusively by
`InvestigationService`.

### EvidenceGraph (`gnat.analysis.graph`)

The `EvidenceGraph` is the in-memory graph of nodes (entities) and
edges (relationships) that supports investigative pivoting. When
addon-stamped objects are filed into an investigation, they become
nodes in the investigation's evidence graph.

The `x_gnat_investigation_origin` value is stored as the node's
`platform` attribute, enabling graph queries like "show me all nodes
contributed by SandGNAT" or "find paths between SenseGNAT
observations and RedGNAT validations."

The `GraphQuery` API (pivot, expand, filter) works transparently with
addon-contributed nodes — no special handling is needed because the
nodes are standard EvidenceGraph entries.

### Report (`gnat.reports`)

When an analyst generates a report from an investigation (ADR-0034),
all objects filed into the investigation — including those contributed
by addons — are included in the report's evidence base. The
`x_gnat_investigation_origin` metadata flows through to the report,
enabling sections like "Evidence from sandbox analysis" or "Network
sensor corroboration."

The report lifecycle (DRAFT, REVIEW, APPROVED, PUBLISHED, ARCHIVED)
is independent of the investigation context. Reports consume
investigation data; they do not stamp or modify investigation context
properties.

### Campaign (`gnat.analysis.attribution`)

Addon-produced objects that are filed into an investigation inherit
the investigation's campaign associations via
`Investigation.campaigns`. If an investigation is linked to Campaign
X, sandbox results filed into that investigation are transitively
associated with Campaign X in the attribution engine.

The `DiamondAnalyzer` can walk addon-contributed nodes to infer ACIV
(Adversary-Capability-Infrastructure-Victim) tuples. SandGNAT-produced
malware nodes provide Capability data; SenseGNAT-produced network
nodes provide Infrastructure data; RedGNAT-produced technique
execution nodes provide Capability validation.

### ConfidenceScore (`gnat.analysis.confidence`)

The `x_gnat_correlation_confidence` property maps directly to
`ConfidenceScore.stix_confidence` when GNAT creates internal
correlation records. The Admiralty Scale decomposition (source
reliability + information credibility) is applied by the correlation
engine, not by addons.

Addons express confidence through the STIX standard `confidence`
field on their objects (0-100). The `x_gnat_investigation_link_type`
provides a qualitative confidence signal (`confirmed` > `inferred` >
`suggested`) that complements the numeric score.

---

## End-to-end flow

The following diagram traces a complete investigation lifecycle from
seed IOC through all three addon tools to a published report, showing
how `x_gnat_investigation_id` threads through every step.

```
                    GNAT creates Investigation
                    inv_id = a1b2c3d4
                            |
                            v
                  +-------------------+
                  | Investigation     |
                  | id: a1b2c3d4      |
                  | status: OPEN      |
                  | seed: malware.exe |
                  +-------------------+
                            |
             analyst submits sample to SandGNAT
             passes inv_id = a1b2c3d4
                            |
                            v
              +---------------------------+
              | SandGNAT detonation       |
              |                           |
              | Produces:                 |
              |  - indicator (C2 domain)  |
              |  - malware SDO            |
              |  - observed-data          |
              |  - grouping (run wrapper) |
              |                           |
              | All stamped with:         |
              |  investigation_id:        |
              |    a1b2c3d4               |
              |  origin: sandgnat         |
              |  link_type: confirmed     |
              +---------------------------+
                            |
                  TAXII 2.1 ingest
                  auto-filed into inv a1b2c3d4
                            |
                            v
                  +-------------------+
                  | Investigation     |
                  | id: a1b2c3d4      |
                  | status: IN_PROG   |
                  | indicators: +3    |
                  | source_connectors:|
                  |   [sandgnat]      |
                  +-------------------+
                            |
             SenseGNAT configured to watch C2 domain
             from inv a1b2c3d4
                            |
                            v
              +---------------------------+
              | SenseGNAT correlation     |
              |                           |
              | Detects:                  |
              |  - DNS queries to C2      |
              |  - Beaconing traffic      |
              |  - Lateral movement IPs   |
              |                           |
              | Produces:                 |
              |  - observed-data (DNS)    |
              |  - observed-data (flows)  |
              |  - indicator (lateral     |
              |    movement pattern)      |
              |  - grouping (run wrapper) |
              |                           |
              | All stamped with:         |
              |  investigation_id:        |
              |    a1b2c3d4               |
              |  origin: sensegnat        |
              |  link_type: inferred      |
              +---------------------------+
                            |
                  TAXII 2.1 ingest
                  auto-filed into inv a1b2c3d4
                            |
                            v
                  +-------------------+
                  | Investigation     |
                  | id: a1b2c3d4      |
                  | status: IN_PROG   |
                  | indicators: +4    |
                  | observables: +3   |
                  | source_connectors:|
                  |   [sandgnat,      |
                  |    sensegnat]     |
                  +-------------------+
                            |
             analyst creates hypothesis:
             "Attacker can exfiltrate via T1048"
             triggers RedGNAT validation
             passes inv_id = a1b2c3d4
                            |
                            v
              +---------------------------+
              | RedGNAT validation        |
              |                           |
              | Executes:                 |
              |  - T1048 exfiltration     |
              |    attempt against target |
              |                           |
              | Result: BLOCKED           |
              |                           |
              | Produces:                 |
              |  - observed-data          |
              |    (execution log)        |
              |  - attack-action SDO      |
              |    (technique result)     |
              |  - grouping (run wrapper) |
              |                           |
              | All stamped with:         |
              |  investigation_id:        |
              |    a1b2c3d4               |
              |  origin: redgnat          |
              |  link_type: confirmed     |
              +---------------------------+
                            |
                  TAXII 2.1 ingest
                  auto-filed into inv a1b2c3d4
                  RedGNAT result added as
                  refuting_evidence on hypothesis
                            |
                            v
                  +-------------------+
                  | Investigation     |
                  | id: a1b2c3d4      |
                  | status: REVIEW    |
                  | indicators: +4    |
                  | observables: +4   |
                  | hypothesis:       |
                  |   T1048 REFUTED   |
                  | source_connectors:|
                  |   [sandgnat,      |
                  |    sensegnat,     |
                  |    redgnat]       |
                  +-------------------+
                            |
             analyst generates report
                            |
                            v
              +---------------------------+
              | Report                    |
              | status: DRAFT -> REVIEW   |
              |   -> APPROVED -> PUBLISH  |
              |                           |
              | Evidence includes:        |
              |  - SandGNAT: C2 domain,   |
              |    malware SDO            |
              |  - SenseGNAT: DNS obs,    |
              |    flow obs, lateral      |
              |    movement indicator     |
              |  - RedGNAT: T1048 blocked |
              |                           |
              | STIX bundle generated     |
              | with all objects +        |
              | investigation context     |
              | properties preserved      |
              +---------------------------+
                            |
                            v
                  +-------------------+
                  | Investigation     |
                  | id: a1b2c3d4      |
                  | status: CLOSED    |
                  | reports: [rpt-1]  |
                  +-------------------+
```

### Key observations from the flow

1. **Investigation ID is threaded through every step.** Each addon
   receives `a1b2c3d4` from GNAT and stamps it on all output. The ID
   never changes and is never created by an addon.

2. **Different link types reflect different certainty levels.**
   SandGNAT and RedGNAT use `"confirmed"` because they are explicitly
   invoked by the analyst. SenseGNAT uses `"inferred"` because its
   correlation is automated.

3. **Ingest path is uniform.** All three addons send their output
   through the same TAXII 2.1 endpoint. The ingest pipeline's
   property inspection is the only new behaviour — no new endpoints
   or protocols.

4. **Evidence accumulates in the investigation.** Each addon run
   adds objects to the investigation's indicator and observable lists,
   adds its tool name to `source_connectors`, and contributes nodes
   to the EvidenceGraph.

5. **RedGNAT results directly affect hypotheses.** The T1048
   validation result is added as `refuting_evidence` on the
   exfiltration hypothesis, changing its status to REFUTED. This
   closes the loop between red team validation and analytical
   reasoning.

6. **Reports inherit everything.** The final report includes
   evidence from all three addons with full provenance. The
   `x_gnat_investigation_origin` metadata enables per-tool
   attribution in the report.

---

## Design constraints

### Additive, not mandatory

The investigation context properties are opt-in. Addons that do not
stamp their output continue to work exactly as before — their STIX
bundles are ingested normally and analysts file them manually. This
constraint ensures backward compatibility and allows incremental
adoption.

### GNAT owns investigation identity

Addons are consumers of investigation identity, not producers. They
receive an `investigation_id` from GNAT and reflect it back. This
avoids split-brain scenarios where two systems disagree about which
investigations exist.

### Tenant-scoped

Investigation IDs are scoped to a tenant (ADR-0027). A SandGNAT
instance serving tenant A cannot reference an investigation in tenant
B. Cross-tenant references are rejected at ingest and the offending
property is stripped (the object is still ingested).

### STIX 2.1 compliant

The three properties use the `x_gnat_` prefix, which is valid under
STIX 2.1 section 11.1 (custom properties). STIX consumers that do
not recognize these properties ignore them per section 3.2. The
Grouping SDO is a standard STIX type, not a custom object.

### No new transport protocol

Addons communicate with GNAT using the same TAXII 2.1 collection
endpoint or STIX-JSON file import that handles all other ingest.
This avoids introducing a new API surface and keeps the integration
footprint small.

---

*Licensed under the Apache License, Version 2.0*
