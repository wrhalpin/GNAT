# ADR-0054: Analysis Rule Engine

**Decision:** Implement a declarative rule engine at `gnat/analysis/rules/`
that evaluates `analysis.investigations.Hypothesis` objects and returns
status transition decisions. Rules are authored as `.hy` (Hy/Lisp) files,
loaded dynamically, and evaluated on hypothesis mutation. The engine is an
advisor — it returns decisions but never mutates state directly.

**Problem statement:**
`InvestigationService.update_hypothesis_status` is a pure setter with no
evaluation logic. Status transitions happen manually. The `reasoning.HypothesisEngine`
has hardcoded thresholds at the STIX level but operates on `STIXHypothesis`,
not `analysis.Hypothesis`. There is an empty slot at the analysis layer for
automated, auditable, analyst-authorable evaluation logic.

## Why Hy

Hy is a Lisp that compiles to Python AST and runs in the same interpreter.
It sits between "more declarative than Python" and "less foreign than Prolog,"
embedded in-process with no new service boundary.

**Alternatives considered:**
- **Prolog:** Strong for pure inference but requires a separate runtime.
  Marshaling STIX objects across the boundary breaks the
  Postgres-as-source-of-truth contract.
- **Clojure via Babashka:** Same cross-boundary cost as Prolog.
- **YAML + DSL:** Analyst-familiar but YAML-with-expressions becomes
  its own interpreter. May be added as a second engine post-v1.
- **Pure Python functions:** Works but loses the declarative-authoring
  property that is the engine's main value.

## Key Decisions

### Rules are advisors, not mutators

The engine's `evaluate()` returns a `RuleEvaluationResult` containing
decisions. It does not mutate state. An orchestrator reads the decision
and applies it via `InvestigationService.update_hypothesis_status`. This
keeps the state machine authority in one place and makes the engine
testable in isolation.

### Two-engine coexistence

`reasoning.HypothesisEngine` (STIX-level, ADR-0042) remains untouched.
The new `AnalysisRuleEngine` operates on `analysis.investigations.Hypothesis`
(analyst workspace level). These are different views of the same concept
at different layers. They do not merge.

### Evidence resolution via dedicated resolver

`Hypothesis.supporting_evidence` and `refuting_evidence` are lists of
STIX IDs. The engine resolves each ID to its originating connector via
`EvidenceResolver`, which queries `WorkspaceStore.get_source_platforms_bulk`
and looks up `TRUST_LEVEL` from `CLIENT_REGISTRY`. STIX objects are not
polluted with connector metadata.

### Audit-first with applied flag

Every rule evaluation writes an audit record BEFORE applying the decision.
The record has `applied: bool` that flips to true after successful mutation.
No transaction threading — sequential operations with audit as leading write.

### AI-60 confidence ceiling as predicate, not clamp

The AI confidence ceiling is enforced as a helper predicate
`within-ai-ceiling?` that rules call in their `:when` clause. Rules
refuse to promote if the ceiling is violated. The ceiling is NOT a
mutation that clamps the number — it stays visible in rule source code.

### Priority-based first-match semantics

Rules sorted by priority descending. First rule whose `:when` returns
truthy for a status-transition decision fires and consumes the transition
slot. Annotations always fire. `no_op` consumes the slot without mutating.

### Dirty-tree policy

In production, rules with uncommitted source file changes will not fire.
Git SHA captured in audit records. `GNAT_ALLOW_DIRTY_RULES=1` provides
emergency override.

### Feature flag default OFF

Existing users unaffected. Enable via `[rules] enabled = true` in config.

## Consequences

**Positive:** Analyst-authorable hypothesis evaluation, full audit trail,
declarative expression, testable in isolation from service layer.

**Negative:** Hy dependency (optional extra), helper library maintenance,
analyst learning curve for Lisp syntax.

**Neutral:** Second engine implementation (YAML, Python) possible later
via `RuleEngineProtocol` without refactoring the core.

→ Related: ADR-0031 (Analysis Layer Architecture)
→ Related: ADR-0033 (Confidence Scoring — Admiralty Scale)
→ Related: ADR-0042 (Hypothesis Engine — STIX-level, coexists)
