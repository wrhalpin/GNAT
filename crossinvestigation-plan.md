# GNAT — Cross-Tool Investigation Context Plan

**Scope:** this is GNAT’s side of the GNAT-o-sphere investigation-context work. It assumes SandGNAT, SenseGNAT, and RedGNAT will each ship a matching plan of their own. This document is the source of truth for the shared contract; the addon plans reference it.

**Intended audience:** Claude Code working in the `wrhalpin/GNAT` repo.

-----

## Context that must not be re-derived

GNAT already has:

- `gnat/analysis/investigations/` — `Investigation`, `Hypothesis`, `AnalystNote`, `InvestigationTask`, state machine (`OPEN → IN_PROGRESS → REVIEW → CLOSED`), `InvestigationService`, `InvestigationStore` (SQLAlchemy).
- `gnat/investigations/` — cross-platform evidence-graph builder. `EvidenceGraph`, `EvidenceNode`, `EvidenceEdge`, `Seed`, `SeedType`, five-step pipeline (`seed → incident expansion → normalise → correlate → materialise`).
- `gnat/analysis/correlation/` — `EntityResolver`, `RelationshipScorer`, `ClusterDetector`, `EnrichmentDispatcher`.
- `gnat/analysis/timeline.py`, `gnat/analysis/graph.py`, `gnat/analysis/copilot/gap_detector.py`, `gnat/analysis/copilot/drafting.py`.
- `gnat/reporting/` — `Report`, `Finding`, `EvidenceLink`, `Attribution`, five-state lifecycle, STIX 2.1 report SDO export.
- Admiralty Scale confidence scoring, TLP 2.0, AI confidence ceiling of 60.
- `TenantRegistry` and `WorkspaceManager` for multi-tenant isolation.

**Do not build a second investigation model.** The work in this plan extends the existing `gnat.analysis.investigations.Investigation` — it does not replace, shadow, or parallel it.

If any of the above has changed since this plan was written, confirm the current state in-conversation before proceeding. Do not assume this plan is current.

-----

## Goal

Let SandGNAT, SenseGNAT, and RedGNAT attach their outputs to GNAT investigations without coupling them to GNAT’s internals.

-----

## The shared contract (source of truth)

Three custom STIX properties on any object an addon emits:

|Property                        |Required                           |Purpose                                                                                                                                                                                                                   |
|--------------------------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`x_gnat_investigation_id`       |yes, when an investigation is known|Primary key of the `Investigation` row in GNAT. String. Must match an existing investigation ID; addons never mint new IDs.                                                                                               |
|`x_gnat_investigation_origin`   |yes                                |One of `"sandgnat"`, `"sensegnat"`, `"redgnat"`, `"gnat"`, `"external"`. Tells the receiver which addon produced the object so the evidence graph can label the node.                                                     |
|`x_gnat_investigation_link_type`|no, defaults to `"inferred"`       |One of `"confirmed"` (addon is certain this belongs to the investigation — e.g. RedGNAT emulated a specific hypothesis), `"inferred"` (correlation logic linked it), `"suggested"` (proposed, pending analyst acceptance).|

Addons should also wrap their per-run output in a STIX `Grouping` with the same three properties set on the Grouping itself. The Grouping’s `object_refs` lists the objects emitted in that run. Consumers can then either consume the Grouping as a single evidence bundle or iterate the individual objects.

Confidence scoring rules (from GNAT policy, not changed by this plan):

- Any object with `x_source_type = "ai_extracted"` is capped at confidence 60. Addons must respect this.
- Correlation-inferred links carry a separate `x_gnat_correlation_confidence` (0–100) independent of the object’s own confidence; GNAT assigns this at receive time.

**Investigation IDs are tenant-scoped.** The receiver validates that every stamped `x_gnat_investigation_id` belongs to an investigation in the tenant the incoming request is authenticated for. Cross-tenant references are rejected.

A formal JSON schema for these three properties and the Grouping envelope lives at `docs/reference/investigation-context-schema.md` (new — see phase 0).

-----

## Phase 0 — Docs and contract

Three documents, no code yet. These are the artifacts the three addon plans reference; lock them down before anyone starts coding.

### 0.1 ADR

Path: `docs/architecture/adrs/ADR-00XX-gnat-investigation-context.md` (pick the next available number).

Decisions to capture:

- Adopt `x_gnat_investigation_id`, `x_gnat_investigation_origin`, `x_gnat_investigation_link_type` as the shared cross-tool correlation contract.
- These properties are custom STIX properties stamped on individual objects **and** on a wrapping `Grouping` per addon run.
- Investigation identity is owned by GNAT’s existing `gnat.analysis.investigations.Investigation`. Addons never create investigations.
- Addons are never required to stamp the properties — objects without them are ingested normally. The properties are additive metadata, not a hard dependency.
- The receive path accepts externally-stamped STIX via existing TAXII 2.1 ingest; no new protocol is introduced.
- Cross-tenant investigation references are rejected at ingest.

### 0.2 Reference schema

Path: `docs/reference/investigation-context-schema.md`.

Contents: exact JSON schema for the three properties, constraints, examples of a single stamped `Indicator`, examples of a `Grouping` wrapping a SandGNAT detonation bundle, error cases (bad tenant, unknown investigation, malformed origin value).

### 0.3 Explanation doc

Path: `docs/explanation/cross-tool-investigation-model.md`.

Contents: why the model exists, how each addon participates, the relationship between this model and the existing `Investigation`, `EvidenceGraph`, and `Report` primitives. One end-to-end diagram showing a seed IOC → SandGNAT detonation → SenseGNAT correlation → RedGNAT validation → GNAT report, with the investigation_id threaded through every step.

-----

## Phase 1 — Investigation API surface (thin additions)

The existing `InvestigationService` has CRUD. Addons need a small, purposeful surface on top of it. Nothing here adds new models.

### 1.1 Addon-facing REST endpoints

Mount under the existing gateway router (`gnat/dissemination/api/`). All endpoints require the same `X-Api-Key` and tenant header the gateway already uses.

|Method|Path                                 |Purpose                                                                                                                                                                                                                                                   |
|------|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`GET` |`/api/investigations`                |List investigations visible to the authenticated tenant. Supports `status`, `created_since`, `tag`, pagination.                                                                                                                                           |
|`GET` |`/api/investigations/{id}`           |Fetch a single investigation with its hypotheses and linked object counts.                                                                                                                                                                                |
|`GET` |`/api/investigations/{id}/hypotheses`|List hypotheses for the investigation. RedGNAT uses this to pick a hypothesis to emulate.                                                                                                                                                                 |
|`POST`|`/api/investigations/{id}/evidence`  |Accept a STIX bundle or Grouping stamped with this investigation’s ID. Validates tenant, validates investigation exists and is not `CLOSED`, validates all contained objects carry a matching `x_gnat_investigation_id`, then routes into existing ingest.|

The `POST .../evidence` endpoint is the one new ingest path. Implementation should delegate to the existing ingest pipeline rather than reimplementing STIX validation.

### 1.2 InvestigationService method additions

In `gnat/analysis/investigations/service.py`:

- `attach_evidence_bundle(investigation_id, bundle, origin, tenant_id) -> AttachResult` — validates, routes to ingest, and returns a structured result (`accepted_count`, `rejected_count`, `rejection_reasons`).
- `find_by_subject(subject_ref, tenant_id) -> list[Investigation]` — returns investigations whose EvidenceGraph already contains `subject_ref`. SenseGNAT calls this at detector-emission time to auto-tag findings.

Both methods are thin — they orchestrate existing components.

### 1.3 Closed-investigation policy

When `POST /api/investigations/{id}/evidence` targets a `CLOSED` investigation:

- Reject with `409 Conflict` by default.
- Include an `X-Reopen-Investigation` header that an authorised caller can set to auto-reopen (move state back to `IN_PROGRESS`, log an `AnalystNote` recording why).

This keeps closed investigations stable while giving an explicit path to add late-arriving evidence.

-----

## Phase 2 — Evidence graph integration

Addon outputs must show up as nodes in the existing `EvidenceGraph`, correctly labeled by origin.

### 2.1 Normalizer pass-through

In `gnat/investigations/normalizer.py`:

- When a raw platform record carries `x_gnat_investigation_id`, `x_gnat_investigation_origin`, or `x_gnat_investigation_link_type`, those three fields must be preserved on the resulting `EvidenceNode` as node metadata.
- Add a new `origin` field on `EvidenceNode` (default `"gnat"`). It’s the source-of-truth label for graph views and report grouping.

### 2.2 Correlator behaviour

In `gnat/investigations/correlator.py`:

- Addon-sourced nodes must participate in correlation the same way as connector-sourced nodes.
- New edges that connect an addon-sourced node to another node get `link_type="inferred"` by default, unless the addon explicitly marked a link as `"confirmed"` (RedGNAT emulation against a specific hypothesis is the canonical case).

### 2.3 Graph query surface

In `gnat/analysis/graph.py`:

- Add `filter_by_origin(origin_list)` to `GraphQuery`. Analysts filtering a view to “show me only SenseGNAT-sourced nodes in this investigation” must work.

-----

## Phase 3 — Cross-tool report template

One new report template, nothing more. `gnat.reporting` already does the heavy lifting.

Path: `gnat/reports/templates/cross_tool_investigation.py`.

The template pulls, for a given `investigation_id`:

- Investigation header (title, status, hypotheses, analyst notes).
- Timeline from `TimelineBuilder` filtered by investigation_id.
- Sections grouped by `origin`:
  - **SandGNAT findings** — malware analyses, artifacts, extracted indicators, similarity neighbours.
  - **SenseGNAT findings** — behavioural detections with narrative strings intact.
  - **RedGNAT findings** — emulation runs, techniques exercised, detection gaps.
  - **GNAT / external** — everything else.
- Confidence and attribution summary from existing `Attribution` and `ConfidenceScore`.
- Recommendations section drafted by `ReportDraftingAssistant` (already exists; confidence-ceiling rules already apply).
- Appendix: raw STIX references.

Expose as `gnat report run --template cross_tool_investigation --investigation IC-2026-0001 --formats pdf html`.

-----

## Phase 4 — CLI additions

In `gnat/investigations/cli.py` (this CLI is light; don’t build a parallel CLI for `gnat.analysis.investigations`):

```
gnat investigation list [--tenant X] [--status open]
gnat investigation show <id>
gnat investigation evidence <id>          # list linked objects grouped by origin
gnat investigation graph <id> [--origin sandgnat,sensegnat]
gnat investigation export <id>            # STIX bundle, preserves custom properties
gnat investigation report <id> --format pdf
```

No `create` / `link` commands in this plan — creation and link management already have a surface in `InvestigationService` and the existing analyst UI. Keep this CLI focused on the cross-tool read path.

-----

## Phase 5 — Tests

### Unit

- `tests/unit/investigations/test_evidence_api.py` — the POST endpoint: accepts a valid stamped bundle, rejects mismatched investigation_id, rejects cross-tenant, rejects closed investigation without reopen header, accepts with reopen header.
- `tests/unit/investigations/test_normalizer_passthrough.py` — all three custom properties survive the normalize step and land on `EvidenceNode`.
- `tests/unit/investigations/test_service_additions.py` — `attach_evidence_bundle` and `find_by_subject`.
- `tests/unit/reports/test_cross_tool_template.py` — template renders with fixture data from all four origins.

### Integration

- `tests/integration/test_cross_tool_ingest.py` — spin up a tenant, create an investigation, POST a fixture bundle labelled each origin, verify evidence graph contains nodes labelled correctly.

Hit 70% coverage minimum (existing gate). Don’t lower it.

-----

## Out of scope

- A new investigation model. The existing one stays.
- A new evidence graph. Same.
- A new correlation engine. Same.
- “Investigation graph view UI” as a new feature — the existing TUI and web dashboard render `EvidenceGraph` today. The only UI work in this plan is the origin filter (Phase 2.3).
- STIX `Incident` object. Out of scope for this pass; `Grouping` covers the immediate need.

-----

## Acceptance criteria

1. An analyst creates an investigation in GNAT (existing flow, unchanged).
1. SandGNAT, SenseGNAT, and RedGNAT can each POST stamped STIX bundles to `/api/investigations/{id}/evidence` and the objects land in the investigation’s `EvidenceGraph` with correct `origin` labels.
1. `gnat investigation graph <id> --origin sensegnat` returns only SenseGNAT-sourced nodes.
1. `gnat investigation report <id> --format pdf` produces a report with sections grouped by origin.
1. STIX export of the investigation preserves all three custom properties on every object.
1. Existing standalone ingest paths (TAXII, ingest pipelines) still work without any `x_gnat_investigation_id` present.
1. Cross-tenant investigation references are rejected with a clear error.
1. Closed-investigation evidence POSTs are rejected unless `X-Reopen-Investigation` is set.

-----

## Risks

|Risk                                                                                       |Mitigation                                                                                                                                                |
|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
|Parallel investigation models appear because a future planner doesn’t see the existing one.|Keep this plan and its ADR in `docs/architecture/`. Any future plan that proposes a new investigation model must reference this ADR and justify deviation.|
|Cross-tenant ID leakage.                                                                   |Tenant validation on every endpoint touching investigation_id. Integration test covers it.                                                                |
|Addons silently drop the custom properties through a STIX round-trip.                      |Normalizer pass-through test (Phase 5). Run it in addon CI too.                                                                                           |
|Closed-investigation policy causes data loss.                                              |The `X-Reopen-Investigation` escape hatch with `AnalystNote` audit trail.                                                                                 |
|AI-generated “suggested” links pollute the graph.                                          |Existing `confidence_ceiling = 60` and the `"suggested"` link_type keep them filterable. Default view hides `"suggested"` unless opted in.                |

-----

## Handoff checklist before starting code

- [ ] Phase 0 docs written and reviewed.
- [ ] The three custom property names match exactly what the addon plans reference.
- [ ] The REST endpoints in Phase 1.1 are reviewed against the existing gateway router so we don’t create a parallel auth surface.
- [ ] Confirmed in-conversation (not from memory) that the module paths listed in “Context that must not be re-derived” are still the current structure. If anything has moved, update this plan before Code starts.