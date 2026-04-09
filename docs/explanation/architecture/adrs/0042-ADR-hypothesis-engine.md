# ADR-0042 — Hypothesis Testing Engine (Phase 4C)

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

Threat intelligence analysis is fundamentally a hypothesis-driven activity.
An analyst observing a cluster of suspicious indicators might form the hypothesis
"192.0.2.1 is a Lazarus Group command-and-control server" and then accumulate
evidence for or against that claim over days or weeks.

Prior to this ADR, GNAT had no structured mechanism for tracking hypotheses.
Analysts recorded their assessments as free-text investigation notes, which
meant:

- **No machine-readable lifecycle:** hypotheses could not transition through
  `pending → confirmed → refuted` states in a way that downstream systems
  (SOAR, reporting) could act on.
- **No evidence linkage:** supporting or refuting observations were stored as
  narrative text rather than as typed STIX relationship references, making it
  impossible to audit the evidence chain.
- **No automated corroboration:** the Solr search index (ADR-0028 derivative)
  accumulated relevant hits but nothing queried it on a hypothesis's behalf.
- **No confidence tracking:** a hypothesis's confidence was not updated as new
  evidence arrived; analysts had to manually re-read all notes to reassess.

The `ReasoningEngine` (ADR-0044) needed a structured hypothesis type to feed
into its scoring pipeline, and the `HypothesisEngine` itself needed a home in
the GNAT architecture that was consistent with the existing STIX custom object
pattern (ADR-0032).

---

## Decision

### `STIXHypothesis` Custom SDO

A new custom STIX Domain Object is defined in
`gnat/stix/sdos/hypothesis.py`:

```python
@dataclass
class STIXHypothesis(STIXBase):
    """
    x-gnat-hypothesis — STIX custom SDO for analyst hypotheses.

    Represents a structured claim about a threat actor, campaign, or observable
    that can be confirmed, refuted, or left inconclusive by accumulated evidence.
    """

    type: str = "x-gnat-hypothesis"
    schema_version: int = 1

    # Core fields
    statement: str = ""                    # Natural-language hypothesis text
    confidence: float = 0.2               # [0.0, 1.0]; updated by evaluate()
    status: str = "pending"               # pending | confirmed | refuted | inconclusive

    # Evidence arrays — store STIX relationship IDs
    supporting_evidence: list[str] = field(default_factory=list)
    refuting_evidence: list[str] = field(default_factory=list)

    # Provenance
    created_by: str = ""                   # initiated_by from the creating ExecutionContext
    workspace_id: str = ""
    created_at: datetime | None = None
    last_evaluated_at: datetime | None = None
```

`STIXHypothesis` is registered in `gnat/stix/sdos/__init__.py` alongside
other custom SDOs (`x-gnat-report-summary`, `x-gnat-enrichment-log`).

Evidence is stored as STIX relationship IDs (strings matching the STIX
`relationship--<uuid>` pattern) rather than direct STIX IDs so that the
evidence relationship itself carries the semantic link (e.g.
`relationship_type: "supports"` or `relationship_type: "refutes"`).

#### Status State Machine

```
              propose()
               ───────►  pending
                              │
                   evaluate() │
                 ┌────────────┤
                 │            │
      confidence ≥ 0.75       │  0.15 < confidence < 0.75
                 │            │
                 ▼            ▼            confidence ≤ 0.15
             confirmed    (unchanged)      AND refuting_evidence
                                               ───────────────►  refuted
                              │
                  close(verdict) │
                         ───────►  inconclusive (when verdict == "inconclusive")
```

### `HypothesisEngine`

`gnat/reasoning/hypothesis.py` provides the lifecycle manager:

```python
class HypothesisEngine:
    """
    Manages the full lifecycle of STIXHypothesis objects:
    propose → evaluate → close.
    """

    def __init__(
        self,
        store: WorkspaceStore,
        search_index: SearchIndex,  # SolrSearchIndex or NullSearchIndex
        trust_weights: dict[str, float] | None = None,
    ) -> None:
        self._store = store
        self._search = search_index
        self._weights = trust_weights or TRUST_WEIGHTS  # from gnat.core.trust
```

#### `propose()`

Creates and persists a new `STIXHypothesis` in the workspace:

```python
def propose(
    self,
    statement: str,
    initial_evidence: list[str],
    ctx: ExecutionContext,
    confidence: float = 0.2,
) -> STIXHypothesis:
    """
    Parameters
    ----------
    statement : str
        Natural-language hypothesis text (e.g. "192.0.2.1 is Lazarus C2").
    initial_evidence : list[str]
        STIX relationship IDs linking the hypothesis to supporting objects.
    ctx : ExecutionContext
        Execution context; workspace_id and initiated_by are taken from here.
    confidence : float
        Initial confidence score in [0.0, 1.0].  Defaults to 0.2 (weak prior).

    Returns
    -------
    STIXHypothesis
        The persisted hypothesis object.
    """
    hyp = STIXHypothesis(
        id=f"x-gnat-hypothesis--{uuid4()}",
        statement=statement,
        confidence=confidence,
        status="pending",
        supporting_evidence=list(initial_evidence),
        refuting_evidence=[],
        created_by=ctx.initiated_by,
        workspace_id=ctx.workspace_id,
        created_at=datetime.utcnow(),
    )
    self._store.upsert(hyp, ctx)
    return hyp
```

#### `evaluate()`

Queries Solr for corroborating or refuting evidence and updates confidence:

```python
def evaluate(
    self,
    hypothesis_id: str,
    ctx: ExecutionContext,
) -> STIXHypothesis:
    """
    Re-scores a hypothesis by querying the Solr search index for evidence
    corroborating or refuting its statement, then updates its confidence
    and (if thresholds are crossed) its status.
    """
    hyp = self._store.get(hypothesis_id, STIXHypothesis)

    # 1. Solr full-text query on the hypothesis statement
    hits = self._search.query(hyp.statement, fields=["name", "pattern", "description"])

    # 2. Weight each hit by the trust level of its source connector
    weighted_sum = 0.0
    for hit in hits:
        trust = hit.get("source_trust_level", "semi_trusted")
        weighted_sum += self._weights.get(trust, 0.6)

    # 3. Normalise to [0.0, 1.0]
    raw_corroboration = min(weighted_sum / max(len(hits), 1), 1.0)

    # 4. Blend with the existing confidence (Bayesian-inspired update)
    new_confidence = 0.4 * hyp.confidence + 0.6 * raw_corroboration
    new_confidence = round(max(0.0, min(1.0, new_confidence)), 4)

    # 5. Auto-classify
    new_status = hyp.status
    if new_confidence >= 0.75:
        new_status = "confirmed"
    elif new_confidence <= 0.15 and hyp.refuting_evidence:
        new_status = "refuted"

    hyp.confidence = new_confidence
    hyp.status = new_status
    hyp.last_evaluated_at = datetime.utcnow()
    self._store.upsert(hyp, ctx)
    return hyp
```

**Confidence scoring weights by trust level:**

| Source Trust Level | Weight Used in Corroboration |
|--------------------|------------------------------|
| `trusted_internal` | 0.9 |
| `semi_trusted` | 0.6 |
| `untrusted_external` | 0.3 |

**Auto-classification thresholds:**

| Condition | New Status |
|-----------|-----------|
| `confidence ≥ 0.75` | `confirmed` |
| `confidence ≤ 0.15` AND `refuting_evidence` non-empty | `refuted` |
| Neither threshold met | Unchanged (remains `pending`) |

#### `close()`

Locks the hypothesis with a final analyst verdict:

```python
def close(
    self,
    hypothesis_id: str,
    verdict: str,  # "confirmed" | "refuted" | "inconclusive"
    ctx: ExecutionContext,
) -> STIXHypothesis:
    """
    Closes a hypothesis with a final analyst-provided verdict.
    Closed hypotheses are not eligible for further evaluate() calls.
    """
    if verdict not in ("confirmed", "refuted", "inconclusive"):
        raise ValueError(f"Invalid verdict: {verdict!r}")
    hyp = self._store.get(hypothesis_id, STIXHypothesis)
    if hyp.status in ("confirmed", "refuted", "inconclusive"):
        raise HypothesisAlreadyClosedError(hypothesis_id)
    hyp.status = verdict
    hyp.last_evaluated_at = datetime.utcnow()
    self._store.upsert(hyp, ctx)
    return hyp
```

### Evidence Linkage via STIX Relationships

When an analyst (or an automated pipeline) identifies a STIX object that
supports or refutes a hypothesis, a STIX `relationship` is created linking the
two objects and the relationship ID is appended to the appropriate evidence list:

```python
# Analyst adds supporting evidence
rel = STIXRelationship(
    relationship_type="supports",
    source_ref=suspicious_ip.id,
    target_ref=hyp.id,
)
workspace.upsert(rel, ctx)
hyp.supporting_evidence.append(rel.id)
engine.evaluate(hyp.id, ctx)  # re-score with new evidence
```

This approach means that every piece of evidence is a first-class STIX object,
queryable, exportable as a STIX bundle, and auditable via the lineage tracker
(ADR-0038).

### Storage

`STIXHypothesis` is persisted via the existing `WorkspaceStore.upsert()`
mechanism.  No new database tables are required; the object lands in
`workspace_objects` like any other STIX object.  The idempotency key
(ADR-0041) ensures that `evaluate()` calls updating the same hypothesis do
not create duplicate rows.

---

## Consequences

### Positive

- **Structured hypothesis lifecycle:** hypotheses transition through a defined
  state machine (`pending → confirmed/refuted/inconclusive`) rather than
  existing only in analyst notes; downstream SOAR and reporting systems can
  filter by `status`.
- **Evidence provenance:** every piece of supporting or refuting evidence is a
  typed STIX relationship, exportable as a STIX bundle and auditable via the
  lineage tracker.
- **Automated corroboration:** `evaluate()` queries Solr without analyst
  intervention, updating confidence as new indicators arrive in the workspace.
- **Trust-weighted scoring:** evidence from internal SIEMs carries more weight
  than community feeds; this is not configurable per-call (it uses the shared
  `TRUST_WEIGHTS` constant) ensuring consistent behaviour across all hypotheses.
- **No new infrastructure:** `STIXHypothesis` uses the existing workspace store
  and Solr search index; no new tables, queues, or services are required.
- **Graceful Solr degradation:** if Solr is unavailable, `NullSearchIndex` is
  substituted and `evaluate()` returns the hypothesis unchanged (confidence not
  updated) rather than raising.

### Negative / Trade-offs

- **Solr dependency for corroboration:** `evaluate()` is only useful when the
  Solr sidecar is running.  Deployments without Solr get lifecycle management
  (`propose`, `close`) but not automated corroboration.
- **Statement-based Solr query:** Solr is queried with the raw hypothesis
  statement string.  If the statement uses phrasing that does not match indexed
  field content, corroboration scores will be low even when strong evidence
  exists.  Structured query decomposition (NLP-based entity extraction) is
  deferred.
- **No real-time push:** `evaluate()` is called on demand or on a schedule; it
  does not automatically fire when a new indicator arrives in the workspace.
  A watcher pattern (deferred) would close this gap.
- **Confidence blending is heuristic:** the 40/60 blend of existing and new
  confidence is not derived from a formal Bayesian model; it is a pragmatic
  approximation that may need tuning.

### Deferred

- **Scheduled re-evaluation:** a `HypothesisWatcher` job that calls `evaluate()`
  on all `pending` hypotheses when new objects are ingested into the same
  workspace.
- **NLP-based entity extraction:** decompose the hypothesis statement into
  structured entity queries (IP, domain, actor name) before querying Solr to
  improve corroboration recall.
- **STIX 2.1 Opinion SDO integration:** map `STIXHypothesis` closed verdicts
  to native STIX 2.1 `opinion` objects for maximum interoperability.
- **Multi-analyst collaboration:** allow multiple analysts to propose competing
  verdicts on the same hypothesis and surface disagreements.

---

## Alternatives Considered

### Free-text analyst notes

Keeping hypotheses as free-text entries in investigation notes was the simplest
option and required no new code.  Rejected because:

1. Notes are not machine-readable; SOAR and reporting systems cannot filter on
   `status == "confirmed"`.
2. Evidence linkage is lost; the note references the evidence by name but not
   by STIX ID, breaking the audit chain.
3. Confidence is not tracked; analysts must manually re-assess every note when
   new evidence arrives.

### External hypothesis management tools (e.g. Jupyter notebooks, Jira)

Using an external tool (Jira tickets, Jupyter analysis notebooks) to track
hypotheses was considered.  Rejected because it breaks GNAT's single-data-model
principle: all threat intelligence objects should be representable in STIX and
stored in the workspace.  An external tool would require a synchronisation
bridge and would not benefit from Solr corroboration, lineage tracking, or the
`ReasoningEngine` scoring pipeline.

### Native STIX 2.1 `opinion` SDO

STIX 2.1 includes an `opinion` SDO that expresses an assessment about the
correctness of STIX content.  Using `opinion` directly was considered.  Rejected
because `opinion` has a fixed enumerated value set
(`strongly-disagree` to `strongly-agree`) and no fields for a natural-language
statement, a confidence score, or an evidence list.  `STIXHypothesis`
(`x-gnat-hypothesis`) extends the STIX custom object pattern consistently with
ADR-0032 and can produce an `opinion` on `close()` as a derived output
(deferred).

---

*Licensed under the Apache License, Version 2.0*
