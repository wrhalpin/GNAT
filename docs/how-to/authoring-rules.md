# Authoring Rules

Recipes for common hypothesis evaluation rule patterns.

## Pattern 1: Evidence-threshold promotion

Promote OPEN → SUPPORTED when evidence count meets a threshold:

```hy
(defrule promote-on-evidence
  :phase "open"
  :priority 100
  :when (fn [h ctx]
          (and (>= (supporting-count h) 3)
               (not (has-refutation? h))))
  :then (fn [h ctx]
          (set-status "supported" :reason "3+ supporting, no refutation")))
```

## Pattern 2: Refutation

Mark REFUTED when refuting evidence dominates:

```hy
(defrule refute-dominant
  :phase "open"
  :priority 90
  :when (fn [h ctx]
          (and (>= (refuting-count h) 2)
               (> (refuting-count h) (supporting-count h))))
  :then (fn [h ctx]
          (set-status "refuted" :reason "Refuting evidence exceeds supporting")))
```

## Pattern 3: Blocking with no-op

Prevent lower-priority rules from firing by consuming the transition slot:

```hy
(defrule block-low-confidence
  :phase "open"
  :priority 110
  :when (fn [h ctx]
          (and (has-confidence? h)
               (not (reliability-at-least? h "C"))))
  :then (fn [h ctx]
          (no-op :reason "Reliability below C — blocking promotion")))
```

## Pattern 4: AI confidence ceiling

Block promotion when all evidence is AI-sourced and confidence exceeds 60:

```hy
(defrule ai-ceiling-guard
  :phase "open"
  :priority 150
  :when (fn [h ctx]
          (and (ai-only? h ctx)
               (not (within-ai-ceiling? h ctx))))
  :then (fn [h ctx]
          (no-op :reason "AI-only evidence exceeds confidence ceiling")))
```

## Pattern 5: Staleness timeout

Mark hypotheses INCONCLUSIVE after extended inactivity:

```hy
(defrule stale-timeout
  :phase "open"
  :priority 20
  :when (fn [h ctx]
          (stale? h 90))
  :then (fn [h ctx]
          (set-status "inconclusive"
                      :reason "No updates in 90+ days")))
```

## Pattern 6: Source trust gate

Only promote when evidence includes at least one trusted_internal source:

```hy
(defrule require-trusted-source
  :phase "open"
  :priority 105
  :when (fn [h ctx]
          (and (>= (supporting-count h) 3)
               (not (has-trusted-evidence? h ctx))))
  :then (fn [h ctx]
          (no-op :reason "No trusted_internal evidence — cannot promote")))
```

## Pattern 7: Annotation (non-blocking)

Add metadata without affecting the transition slot:

```hy
(defrule flag-weak-evidence
  :phase "open"
  :priority 10
  :when (fn [h ctx]
          (< (supporting-count h) 2))
  :then (fn [h ctx]
          (annotate "needs-evidence" True
                    :reason "Fewer than 2 supporting items")))
```

## Priority guidelines

| Range | Use |
|-------|-----|
| 200+ | Analyst overrides |
| 100–199 | Production promotion/refutation rules |
| 50–99 | Secondary rules (guards, gates) |
| 1–49 | Annotations, informational |

## YAML alternative

All patterns above can be expressed in YAML without code. Set
`engine = yaml` in `[rules]` config. Example:

```yaml
rules:
  - name: promote-on-evidence
    phase: open
    priority: 100
    when:
      all:
        - supporting_count: { gte: 3 }
        - has_refutation: false
        - reliability_at_least: "B"
        - within_ai_ceiling: true
    then:
      set_status:
        target: supported
        reason: "Strong evidence"
```

See [Rule Engine Spec](../reference/rule-engine-spec.md) for the full
YAML condition DSL and Prolog syntax.

## Helper reference

Run `gnat rules list-helpers` for the complete helper catalog, or see
[Rule Engine Spec](../reference/rule-engine-spec.md).
