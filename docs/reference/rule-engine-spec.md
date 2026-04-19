# Rule Engine Specification

Authoritative reference for the GNAT analysis rule engine.

---

## 1. Rule File Format

Rule files are `.hy` (Hy/Lisp) files placed in the configured `rules_dir`.
Each file uses the `defrule` macro:

```hy
(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule <rule-name>
  :description <string>           ;; optional
  :phase <string>                 ;; required: "open", "supported", "refuted", "inconclusive"
  :target-status <string>         ;; optional: informational only
  :priority <integer>             ;; optional, default 50
  :tags [<string> ...]            ;; optional, default []
  :when (fn [h ctx] <body>)       ;; required: predicate returning truthy/falsy
  :then (fn [h ctx] <body>))      ;; required: returns a Decision
```

### Required keys

- **`:phase`** — hypothesis status the rule applies to (string matching `HypothesisStatus.value`)
- **`:when`** — predicate function `(hypothesis, ctx) -> bool`
- **`:then`** — decision function `(hypothesis, ctx) -> Decision`

### Decision constructors

| Constructor | Consumes slot? | Mutates? |
|-------------|---------------|----------|
| `(set-status <target> :reason <str>)` | Yes | Yes (via orchestrator) |
| `(annotate <key> <value> :reason <str>)` | No | No |
| `(no-op :reason <str>)` | Yes | No |

---

## 2. Helper Function Reference

### Evidence helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `supporting-count` / `supporting_count` | `(h) -> int` | Number of supporting evidence items |
| `refuting-count` / `refuting_count` | `(h) -> int` | Number of refuting evidence items |
| `evidence-count` / `evidence_count` | `(h) -> int` | Total evidence (supporting + refuting) |
| `has-refutation?` / `has_refutation` | `(h) -> bool` | True if any refuting evidence |
| `support-ratio` / `support_ratio` | `(h) -> float` | supporting / (total + 1) |

### Confidence helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `has-confidence?` / `has_confidence` | `(h) -> bool` | True if ConfidenceScore assigned |
| `stix-confidence` / `stix_confidence` | `(h) -> int` | STIX confidence 0-100, or 0 |
| `confidence-band` / `confidence_band` | `(h) -> str\|None` | HIGH/MEDIUM/LOW or None |
| `reliability-of` / `reliability_of` | `(h) -> str\|None` | Source reliability A-F |
| `credibility-of` / `credibility_of` | `(h) -> int\|None` | Information credibility 1-6 |
| `reliability-at-least?` / `reliability_at_least` | `(h, level) -> bool` | True if reliability >= level |
| `credibility-at-least?` / `credibility_at_least` | `(h, level) -> bool` | True if credibility <= level (lower is better) |

### Temporal helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `age-days` / `age_days` | `(h [now]) -> int` | Days since creation |
| `days-since-update` / `days_since_update` | `(h [now]) -> int` | Days since last update |
| `stale?` / `stale` | `(h [days=30] [now]) -> bool` | True if not updated in N days |
| `fresh?` / `fresh` | `(h [days=7] [now]) -> bool` | True if updated within N days |

### Status helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `status-of` / `status_of` | `(h) -> HypothesisStatus` | Current status enum |
| `is-open?` / `is_open` | `(h) -> bool` | Status is OPEN |
| `is-supported?` / `is_supported` | `(h) -> bool` | Status is SUPPORTED |
| `is-refuted?` / `is_refuted` | `(h) -> bool` | Status is REFUTED |
| `is-inconclusive?` / `is_inconclusive` | `(h) -> bool` | Status is INCONCLUSIVE |

### Policy helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `within-ai-ceiling?` / `within_ai_ceiling` | `(h, ctx) -> bool` | True if not AI-only or confidence <= ceiling |

### Source/trust helpers (require `ctx`)

| Function | Signature | Description |
|----------|-----------|-------------|
| `evidence-sources` / `evidence_sources` | `(h, ctx) -> set[str]` | Connector names for all evidence |
| `trust-levels` / `trust_levels` | `(h, ctx) -> set[str]` | Trust levels across sources |
| `has-trusted-evidence?` / `has_trusted_evidence` | `(h, ctx) -> bool` | Any trusted_internal source |
| `all-evidence-trusted?` / `all_evidence_trusted` | `(h, ctx [min]) -> bool` | All evidence meets minimum trust |
| `evidence-from?` / `evidence_from` | `(h, ctx, name) -> bool` | Evidence from named connector |
| `unknown-source-count` / `unknown_source_count` | `(h, ctx) -> int` | Evidence from unknown connectors |
| `ai-only?` / `ai_only` | `(h, ctx) -> bool` | All evidence from AI connectors |

---

## 3. Evaluation Model

### Priority and ordering

Rules are sorted by priority **descending** (highest first). For a given
hypothesis, the engine walks the sorted list sequentially.

### Transition slots

- The first rule returning `set-status` or `no-op` **consumes the
  transition slot**. No further transition decisions fire.
- Rules returning `annotate` **never consume the slot**. All matching
  annotation rules fire regardless of position.
- A `no-op` consumes the slot without mutating — use it to block
  lower-priority rules.

### Phase gates

A rule only evaluates if `hypothesis.status.value == rule.phase`. Rules
with `phase = None` match all statuses.

### Exception handling

If a rule's `:when` or `:then` raises an exception, the error is logged,
added to `result.errors`, and evaluation continues to the next rule.
Broken rules never halt hypothesis processing.

---

## 4. Audit Model

Every rule firing writes to the `rule_firing_audit` table (or in-memory
log) **before** the orchestrator applies the decision.

| Column | Type | Description |
|--------|------|-------------|
| `id` | BigInteger | Primary key |
| `investigation_id` | String | Investigation containing the hypothesis |
| `hypothesis_id` | String | Evaluated hypothesis |
| `workspace_id` | Integer | Workspace context |
| `rule_name` | Text | Rule that fired |
| `rule_source_file` | Text | Path to .hy file |
| `rule_git_sha` | String(40) | Git SHA of rule file at firing time |
| `fired_at` | DateTime(tz) | When the rule fired |
| `decision` | JSON | Serialized decision object |
| `applied` | Boolean | True after successful mutation |
| `applied_at` | DateTime(tz) | When mutation succeeded |
| `error_message` | Text | Error if mutation failed |
| `engine_version` | String(32) | Engine version |

---

## 5. Policy Parameters

Configured via `[rules]` INI section:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Feature flag — must be true for evaluation |
| `rules_dir` | string | `rules` | Directory containing .hy files |
| `ai_confidence_ceiling` | int | `60` | Max STIX confidence for AI-only evidence |
| `minimum_evidence_for_support` | int | `3` | Default evidence threshold |
| `stale_days_default` | int | `30` | Default staleness threshold |
| `fresh_days_default` | int | `7` | Default freshness threshold |
| `allow_dirty_rules` | bool | `false` | Allow uncommitted rule files to fire |

Environment override: `GNAT_ALLOW_DIRTY_RULES=1` forces `allow_dirty_rules=true`.

---

## 6. Error Handling

- **Rule load failure**: Logged, file skipped, other rules still load.
- **Rule evaluation exception**: Logged, added to `result.errors`, next rule evaluated.
- **Hy not installed**: Loader returns empty list, logs warning.
- **Git unavailable**: `rule_file_sha` returns None, `git_file_is_clean` returns False (fail closed).
- **Service mutation failure**: Audit row recorded with `error_message`, `applied=false`.
