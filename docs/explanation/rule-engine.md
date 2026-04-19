# Rule Engine — Design Explanation

## Why a rule engine

`InvestigationService.update_hypothesis_status` is a pure setter — it
changes state but doesn't evaluate whether the change is warranted.
Today, hypothesis transitions happen manually. The `reasoning.HypothesisEngine`
has hardcoded thresholds, but it operates on `STIXHypothesis` (STIX-level
objects), not on `analysis.Hypothesis` (workspace-level objects).

The rule engine fills the gap: automated, auditable, analyst-authorable
hypothesis evaluation at the analysis layer.

## Why Hy (Lisp-on-Python)

Rules need to be:
- **Declarative** — analysts read the rule and understand what it does
- **In-process** — no separate runtime, no marshaling across boundaries
- **Composable** — helper predicates combine naturally

Hy compiles to Python AST and runs in the same interpreter. It's more
declarative than Python (S-expressions force a functional style) but
less foreign than Prolog (no separate process, no unification). YAML
was considered but rejected because expressions-in-YAML becomes its
own interpreter; a YAML engine may be added later via the Protocol.

## Two engines coexist

The `reasoning.HypothesisEngine` (ADR-0042) and the analysis
`AnalysisRuleEngine` (ADR-0054) are not duplicates. They operate
on different objects at different layers:

| | HypothesisEngine | AnalysisRuleEngine |
|---|---|---|
| Object type | `STIXHypothesis` | `analysis.Hypothesis` |
| Layer | STIX-level reasoning | Analyst workspace |
| Thresholds | Hardcoded in Python | Declared in `.hy` rule files |
| Authorship | GNAT maintainer | CTI analysts |

Neither modifies the other. They will eventually feed into each other
(STIX-level engine proposes, analysis-level engine evaluates), but
that integration is post-v1.

## Advisor pattern

Rules return decisions — they never mutate state directly. The
`RuleOrchestrator` reads the engine's `RuleEvaluationResult` and
applies the primary decision via `InvestigationService`. This keeps
state machine authority in one place and makes the engine testable
with no service dependency.

## Evidence resolution

`Hypothesis.supporting_evidence` and `refuting_evidence` are lists of
STIX IDs. To answer "is this evidence from a trusted source?", the
engine uses `EvidenceResolver`, which:

1. Batch-queries `WorkspaceStore.get_source_platforms_bulk()`
2. Looks up the connector class from `CLIENT_REGISTRY`
3. Reads `TRUST_LEVEL` from the class
4. Caches results for the evaluation's lifetime

STIX objects are never modified with connector metadata. The resolver
is a lookup layer, not a mutation layer.

## AI confidence ceiling

The policy that AI-generated confidence cannot exceed 60 is enforced
as a predicate (`within-ai-ceiling?`), not a clamp. Rules call it in
their `:when` clause — if the ceiling is violated, the rule refuses
to promote. The invariant is visible in rule source code, not hidden
in a mutation pipeline.

## Audit trail

Every rule evaluation writes an audit record **before** applying the
decision. The record captures: rule name, source file path, git SHA,
decision JSON, and a boolean `applied` flag. If mutation fails, the
error is recorded but the audit row already exists. This ensures
complete traceability even for failed transitions.

## Dirty-tree policy

In production, rule files with uncommitted changes will not fire. The
engine checks `git status --porcelain` for each rule's source file and
captures `git log` SHA at firing time. This protects the audit trail:
every fired rule can be traced to an exact committed version.

`GNAT_ALLOW_DIRTY_RULES=1` overrides this for development.

→ [ADR-0054: Analysis Rule Engine](architecture/adrs/0054-ADR-analysis-rule-engine.md)
→ [Rule Engine Spec](../reference/rule-engine-spec.md)
→ [Authoring Rules](../how-to/authoring-rules.md)
→ [Your First Rule](../tutorials/your-first-rule.md)
