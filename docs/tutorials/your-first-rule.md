# Your First Rule

This tutorial walks you through creating a minimal hypothesis evaluation
rule, enabling the engine, and seeing it fire.

## Prerequisites

- GNAT installed with `pip install "gnat[rules]"`
- A `config.ini` with a `[rules]` section
- Familiarity with GNAT investigations and hypotheses

## Step 1: Create a rules directory

```bash
mkdir -p rules/my-rules
```

## Step 2: Write a minimal rule

Create `rules/my-rules/hello-rule.hy`:

```hy
(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule hello-rule
  :description "Annotate open hypotheses with a greeting"
  :phase "open"
  :priority 10
  :tags ["tutorial"]
  :when (fn [h ctx]
          (is-open? h))
  :then (fn [h ctx]
          (annotate "greeted" True
                    :reason "Hello from my first rule!")))
```

This rule:
- Applies to hypotheses in the `"open"` phase
- Has priority 10 (low — won't preempt production rules)
- Checks if the hypothesis is open (always true for open-phase rules)
- Returns an annotation decision (does not change status)

## Step 3: Enable the engine

In your `config.ini`:

```ini
[rules]
enabled = true
rules_dir = rules/my-rules
allow_dirty_rules = true   # for development only
```

## Step 4: Trigger evaluation

```python
from gnat.analysis.rules.factory import create_engine
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.investigations.models import Hypothesis

# Create a test hypothesis
hyp = Hypothesis(statement="Test hypothesis")

# Create engine from config
import configparser
config = configparser.ConfigParser()
config.read("config.ini")

engine = create_engine(config)
result = engine.evaluate(hyp, investigation=None, workspace_id=1)

# See what fired
for firing in result.firings:
    print(f"Rule: {firing.rule_name}")
    print(f"Decision: {firing.decision.action.value}")
    print(f"Reason: {firing.decision.reason}")
```

## Step 5: Promote to a status-changing rule

Change the `:then` clause to return a status transition:

```hy
  :then (fn [h ctx]
          (set-status "supported"
                      :reason "Promoted by tutorial rule")))
```

Now the rule will recommend transitioning the hypothesis to SUPPORTED.
The orchestrator applies this via `InvestigationService`.

## What's next

- See [Authoring Rules](../how-to/authoring-rules.md) for common patterns
- See [Rule Engine Spec](../reference/rule-engine-spec.md) for the full reference
- See [Rule Engine Explanation](../explanation/rule-engine.md) for architecture
