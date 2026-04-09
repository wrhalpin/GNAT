# ADR-0044 — Evidence-Weighted Observable Reasoning Engine (Phase 4C)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT ingests thousands of STIX observables per pipeline run from dozens of
connectors.  Prior to this ADR, analysts had no automated mechanism to answer
the question: **"Given everything GNAT knows right now, which of these
observables should I investigate first?"**

The existing confidence scoring (ADR-0033) assigned a single confidence value
per object based on connector-reported metadata.  This was insufficient for
prioritisation because:

1. **Single signal:** confidence came from one field on one object, ignoring the
   object's age, corroborating hits across other objects in the workspace, and
   negative evidence from connectors that had never seen the observable.
2. **Trust-agnostic:** a 0.9-confidence hit from AlienVault OTX (open community
   submissions) and a 0.9-confidence hit from the organisation's own Splunk
   deployment were scored identically, despite the profound difference in source
   authority.
3. **Not explainable:** a single float score gave analysts no insight into why
   an observable was scored high or low; it could not be audited.
4. **Not persisted:** scores were computed on demand and discarded; there was no
   record that prioritisation had occurred, breaking the lineage chain.

The `HypothesisEngine` (ADR-0042) and `NegativeEvidenceRecord` (ADR-0043)
introduced structured evidence objects that begged for a consumer: a scoring
engine that reads them and produces a ranked, explainable prioritisation list.

SOC analyst feedback collected during Phase 4B identified three signals as most
valuable for triage prioritisation:

- **Source authority** (whose data is this?)
- **Recency** (how recently was this observed or updated?)
- **Corroboration** (how many other data points mention this observable?)

A fourth signal — **absence of data** — was identified as equally important:
an observable not seen by any trusted connector is less urgent than one
confirmed by three.

---

## Decision

### `ReasoningEngine`

The scoring engine is defined in `gnat/reasoning/engine.py`:

```python
class ReasoningEngine:
    """
    Prioritises a set of STIX observables using a composite evidence-weighted
    score derived from trust level, age, Solr corroboration, and negative
    evidence penalties.

    Parameters
    ----------
    store : WorkspaceStore
        Workspace store used to persist STIX note objects when store_notes=True.
    search_index : SearchIndex
        Solr search index for corroboration queries.  Pass NullSearchIndex when
        Solr is unavailable; the engine degrades gracefully.
    neg_store : NegativeEvidenceStore
        Store for fresh NegativeEvidenceRecord lookups.
    trust_weights : dict[str, float] | None
        Override for the default TRUST_WEIGHTS mapping.  Pass None to use
        the shared constant from gnat.core.trust.
    """

    def __init__(
        self,
        store: WorkspaceStore,
        search_index: SearchIndex,
        neg_store: NegativeEvidenceStore,
        trust_weights: dict[str, float] | None = None,
    ) -> None:
        self._store = store
        self._search = search_index
        self._neg = neg_store
        self._weights = trust_weights or TRUST_WEIGHTS
```

### `prioritize()`

The primary public method:

```python
def prioritize(
    self,
    observable_set: list[STIXBase],
    ctx: ExecutionContext,
    store_notes: bool = True,
) -> list[tuple[STIXBase, float, dict]]:
    """
    Score and rank a list of STIX observables.

    Parameters
    ----------
    observable_set : list[STIXBase]
        The observables to score.  All must belong to ctx.workspace_id.
    ctx : ExecutionContext
        Execution context; trust_level and workspace_id are read from here.
    store_notes : bool
        When True, persist a STIX note object for each scored observable
        recording the score breakdown.  Defaults to True.

    Returns
    -------
    list[tuple[STIXBase, float, dict]]
        Triples of (observable, score, explanation), sorted by score descending.
        score is in [0.0, 1.0].  explanation is a machine-readable dict.
    """
    results = []
    for obs in observable_set:
        score, explanation = self._score_observable(obs, ctx)
        if store_notes:
            self._persist_note(obs, score, explanation, ctx)
        results.append((obs, score, explanation))

    results.sort(key=lambda t: t[1], reverse=True)
    return results
```

### Composite Scoring Formula

```
score = trust_weight × 0.4
      + age_factor   × 0.3
      + corroboration_bonus × 0.3
      − neg_penalty  × 0.5
```

The result is clamped to `[0.0, 1.0]`.

#### Component Definitions

**`trust_weight`** — derived from `ExecutionContext.trust_level`:

| Trust Level | trust_weight |
|-------------|-------------|
| `trusted_internal` | 0.9 |
| `semi_trusted` | 0.6 |
| `untrusted_external` | 0.3 |

The context trust level represents the highest-authority source in the pipeline
that produced or enriched this observable.

**`age_factor`** — time-decay from the observable's `modified` field:

```python
def _age_factor(self, obs: STIXBase) -> float:
    if obs.modified is None:
        return 0.5  # no timestamp: neutral decay
    days_old = (datetime.utcnow() - obs.modified).total_seconds() / 86400.0
    return max(0.0, 1.0 - 0.05 * days_old)
```

| Age (days) | age_factor |
|-----------|-----------|
| 0 (today) | 1.00 |
| 1 | 0.95 |
| 5 | 0.75 |
| 10 | 0.50 |
| 20 | 0.00 (floor) |

**`corroboration_bonus`** — Solr hit count for the observable's identifier fields:

```python
def _corroboration_bonus(self, obs: STIXBase) -> float:
    hits = self._search.query(
        obs.name or obs.id,
        fields=["name", "pattern", "value", "description"],
    )
    return min(len(hits) * 0.05, 0.25)
```

| Solr Hits | corroboration_bonus |
|-----------|-------------------|
| 0 | 0.00 |
| 1 | 0.05 |
| 3 | 0.15 |
| 5+ | 0.25 (cap) |

**`neg_penalty`** — count of unexpired `NegativeEvidenceRecord` objects for
this observable:

```python
def _neg_penalty(self, obs: STIXBase, workspace_id: str) -> float:
    count = self._neg.query_fresh_count(
        target_ref=obs.id,
        workspace_id=workspace_id,
    )
    return min(0.3 * count, 0.6)
```

| Fresh Negative Records | neg_penalty |
|------------------------|------------|
| 0 | 0.00 |
| 1 | 0.30 |
| 2+ | 0.60 (cap) |

The cap at 0.60 applied via the `× 0.5` formula coefficient means the maximum
negative penalty subtracted from the composite score is `0.60 × 0.5 = 0.30`,
preserving a floor above zero even for heavily negatively-evidenced observables.

### Full Scoring Implementation

```python
def _score_observable(
    self,
    obs: STIXBase,
    ctx: ExecutionContext,
) -> tuple[float, dict]:
    tw = self._weights.get(ctx.trust_level, 0.6)
    af = self._age_factor(obs)
    cb = self._corroboration_bonus(obs)
    np_ = self._neg_penalty(obs, ctx.workspace_id)

    raw = tw * 0.4 + af * 0.3 + cb * 0.3 - np_ * 0.5
    score = round(max(0.0, min(1.0, raw)), 4)

    explanation = {
        "score": score,
        "components": {
            "trust_weight":          tw,
            "trust_weight_coeff":    0.4,
            "age_factor":            af,
            "age_factor_coeff":      0.3,
            "corroboration_bonus":   cb,
            "corroboration_coeff":   0.3,
            "neg_penalty":           np_,
            "neg_penalty_coeff":     0.5,
        },
        "trust_level":   ctx.trust_level,
        "workspace_id":  ctx.workspace_id,
        "evaluated_at":  datetime.utcnow().isoformat(),
    }
    return score, explanation
```

### Explanation Dict Structure

The `explanation` dict is machine-readable, not free text, so that downstream
components (report generators, SOAR connectors, TUI) can format it as needed:

```json
{
  "score": 0.6250,
  "components": {
    "trust_weight":        0.9,
    "trust_weight_coeff":  0.4,
    "age_factor":          0.75,
    "age_factor_coeff":    0.3,
    "corroboration_bonus": 0.15,
    "corroboration_coeff": 0.3,
    "neg_penalty":         0.0,
    "neg_penalty_coeff":   0.5
  },
  "trust_level":  "trusted_internal",
  "workspace_id": "acme-corp",
  "evaluated_at": "2026-04-09T14:23:01.000Z"
}
```

### STIX Note Persistence

When `store_notes=True`, the engine persists a STIX 2.1 `note` object for each
scored observable:

```python
def _persist_note(
    self,
    obs: STIXBase,
    score: float,
    explanation: dict,
    ctx: ExecutionContext,
) -> None:
    note = STIXNote(
        id=f"note--{uuid4()}",
        abstract=f"ReasoningEngine score: {score:.4f}",
        content=json.dumps(explanation, indent=2),
        object_refs=[obs.id],
        created_by_ref=ctx.initiated_by,
    )
    self._store.upsert(note, ctx)
```

STIX `note` objects link to their target via `object_refs`, making the
score and explanation auditable via the standard STIX relationship graph
and exportable in STIX bundles.

### Solr Degradation

When Solr is unavailable, `NullSearchIndex` is substituted:

```python
class NullSearchIndex(SearchIndex):
    """No-op search index used when Solr is unavailable."""

    def query(self, query: str, fields: list[str] | None = None) -> list[dict]:
        return []
```

With `NullSearchIndex`, `corroboration_bonus` is always 0.0.  The engine
continues to score using `trust_weight`, `age_factor`, and `neg_penalty`,
producing a degraded but still useful ranking.

### Usage Example

```python
from gnat.reasoning.engine import ReasoningEngine
from gnat.search import GNATIndexer
from gnat.core.context import ExecutionContext

ctx = ExecutionContext.from_connector(
    connector=splunk_client,
    domain="analysis",
    workspace_id="acme-corp",
)

engine = ReasoningEngine(
    store=workspace_store,
    search_index=GNATIndexer.from_config(config),
    neg_store=neg_evidence_store,
)

ranked = engine.prioritize(
    observable_set=all_indicators,
    ctx=ctx,
    store_notes=True,
)

for obs, score, explanation in ranked[:10]:
    print(f"{score:.4f}  {obs.name or obs.id}")
    # > 0.7800  192.0.2.1
    # > 0.6550  evil-domain.example.com
    # > 0.4200  suspicious-hash-abc123
```

---

## Consequences

### Positive

- **Deterministic and reproducible:** given the same inputs (trust level, object
  timestamps, Solr hit counts, negative records), the formula always produces
  the same score.  This makes it testable with fixed fixtures and auditable
  after the fact.
- **Explainable:** the structured `explanation` dict exposes every scoring
  component; analysts can see exactly why an observable ranked high or low
  without reading source code.
- **Fully auditable:** STIX `note` objects link scores to observables in the
  standard STIX graph; the entire prioritisation history is queryable and
  exportable.
- **Solr-optional:** `NullSearchIndex` allows the engine to operate in minimal
  deployments (developer workstations, CI) without a Solr sidecar, with only
  the corroboration component degraded.
- **Composable:** the scoring formula uses components already computed by
  `NegativeEvidenceStore` and `ExecutionContext`; no new data collection is
  needed beyond what Phase 4C already produces.
- **No new dependencies:** all components are pure Python dataclass operations
  plus existing Solr and SQLAlchemy infrastructure; no new packages are required.

### Negative / Trade-offs

- **Context trust level is pipeline-level:** `trust_weight` is read from the
  `ExecutionContext`, which represents the trust of the pipeline that ingested
  the observable, not the trust of each individual source that contributed to
  the enrichment.  An observable enriched by both Splunk (trusted_internal) and
  AlienVault (untrusted_external) in different pipeline runs will be scored
  differently depending on which pipeline context `prioritize()` is called with.
  Per-observable trust aggregation is deferred.
- **Age factor assumes `modified` is reliable:** not all connectors reliably
  populate the STIX `modified` field; objects with no `modified` receive the
  neutral 0.5 factor, which may over- or under-rank them depending on their
  actual age.
- **Corroboration bonus is hit-count-based:** the Solr query returns a count of
  matching documents, not a measure of the quality or relevance of those
  matches.  A high Solr hit count on a generic observable (e.g. a popular CDN
  IP) may inflate the bonus.
- **Score storage growth:** with `store_notes=True`, every call to `prioritize()`
  on N observables creates N STIX note objects.  Regular re-prioritisation
  (e.g. on a daily schedule) accumulates many notes per observable.  A retention
  policy is needed.

### Deferred

- **Per-observable trust aggregation:** compute the effective trust weight from
  all connectors that have enriched the observable (max, weighted average, or
  union) rather than from the pipeline-level `ExecutionContext`.
- **ML-based weight calibration:** collect analyst feedback on scored results
  (accepted/rejected triage decisions) and use them to calibrate the formula
  coefficients (`0.4`, `0.3`, `0.3`, `0.5`) via a regression model.
- **Score note retention policy:** a `ScoreNotePurgeJob` that deletes note
  objects older than a configurable threshold, retaining only the most recent
  score per observable.
- **TUI prioritisation dashboard:** display the ranked observable list with
  expandable `explanation` views in the Textual TUI.
- **Streaming prioritisation:** emit score updates as new evidence arrives via
  the HookBus rather than requiring explicit `prioritize()` calls.

---

## Alternatives Considered

### ML-based ranking (deferred, not rejected)

A supervised ranking model trained on analyst triage decisions was the
originally proposed approach.  It was deferred (not rejected) because:

1. GNAT does not yet have labelled training data (analyst accept/reject
   decisions on scored observables); the formula-based engine will collect this
   data in production.
2. An ML model is harder to explain and audit; the formula produces an
   `explanation` dict that every component of the system can parse.
3. ML models require a training pipeline, model versioning, and serving
   infrastructure that are out of scope for Phase 4C.

The formula-based engine is explicitly designed to be replaceable: the scoring
logic is isolated in `_score_observable()`, and the coefficients are named
constants that a future calibration layer can tune without changing the public
API.

### Flat confidence score only

Retaining the Phase 3 single-field confidence score and not introducing a
multi-component formula was the minimal alternative.  Rejected because:

1. It ignores trust authority (source reliability) — the single most important
   factor identified in analyst feedback.
2. It ignores recency — a 1-year-old hit is less actionable than a hit from
   today.
3. It has no mechanism to penalise observables that multiple connectors have
   already examined and found unremarkable.
4. It is not explainable — analysts cannot determine why an observable ranked
   above another.

### Graph-centrality ranking

Using the STIX relationship graph to compute centrality scores (e.g. PageRank
over the STIX `relationship` graph) as the primary ranking signal was
considered.  Rejected because:

1. GNAT workspaces in early deployments may have sparse relationship graphs;
   centrality degrades to random ranking for isolated observables.
2. Graph traversal over potentially 100,000+ STIX objects requires significant
   compute and is not suitable for on-demand scoring within a pipeline run.
3. Centrality does not incorporate trust authority, recency, or negative
   evidence without substantial additional engineering.

Graph-based ranking remains a viable long-term complement to the formula and
may be reintroduced as an optional corroboration signal once workspaces have
sufficient relationship density.

---

*Licensed under the Apache License, Version 2.0*
