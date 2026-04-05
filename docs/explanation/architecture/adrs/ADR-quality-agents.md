# ADR: Quality Agents for Connector Assurance

## Status

Accepted

## Context

GNAT maintenance agents can detect upstream drift, classify impact, and prepare repository changes.
That is necessary but not sufficient.

Connector repositories often fail in a more subtle way:
the code still runs, but the normalized meaning changes.
In a CTM-oriented platform, semantic drift and inconsistent connector structure are high-risk failure modes.

## Decision

GNAT will implement a dedicated quality agent family with three initial responsibilities:

1. normalization regression
2. connector contract enforcement
3. fixture coverage analysis

These agents will be separate from maintenance agents but wired into the same review and CI path.

## Rationale

### Why separate quality from maintenance

Maintenance focuses on change detection and repair planning.
Quality focuses on confidence in connector behavior and repository consistency.

Keeping these separate makes the policy model clearer:
- maintenance may propose changes
- quality decides how much those changes can be trusted

### Why normalization regression first

GNAT's true contract is the normalized output that downstream systems consume.
Preventing semantic drift protects that contract better than simple execution tests.

### Why contract enforcement

As connector count grows, the repo becomes harder to maintain if each connector evolves its own local conventions.
Contract checks create a lightweight, reviewable pressure toward consistency.

### Why fixture coverage analysis

Weak or shallow fixtures hide risk.
Coverage scoring makes fragility visible and provides a policy input for draft PRs, manual review, and prioritization.

## Consequences

### Positive

- higher confidence in connector meaning
- more consistent connector structure
- better visibility into test debt
- stronger maintenance PR gating

### Negative

- additional CI time
- more configuration and baseline data to maintain
- temporary friction while legacy connectors are brought up to standard

## Alternatives considered

### Fold all checks into maintenance agents

Rejected because it mixes change detection with trust evaluation and makes review policy harder to reason about.

### Rely on standard unit tests only

Rejected because semantic drift and fixture weakness are often not captured by ordinary unit test coverage.

## Future work

- connector-specific semantic diff rules
- bundle-aware STIX comparisons
- confidence scoring shared with maintenance agents
- automatic downgrading of risky patch PRs to draft
