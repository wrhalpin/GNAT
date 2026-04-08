# Quality Agents

## Overview

GNAT quality agents protect connector trustworthiness after basic maintenance and repair logic has been established.
These agents answer a different question than maintenance agents:

- maintenance asks whether something changed
- quality asks whether the connector still behaves correctly and consistently

## Agents in this family

### Normalization Regression Agent

Protects the semantic contract of connector output by replaying known source payloads and comparing normalized output
against approved golden baselines.

Use this when:
- mapper logic changes
- source API payloads drift
- maintenance agents propose connector repairs
- a PR touches normalization or translation code

### Contract Agent

Enforces the structural expectations of GNAT connectors.
It checks for required files, expected symbols, and minimum documentation hooks so connectors do not slowly diverge
from the repository's house style.

Use this when:
- adding a new connector
- refactoring shared connector abstractions
- reviewing large batches of community or generated connector changes

### Fixture Coverage Agent

Measures the strength of test fixtures for each connector.
It identifies shallow coverage, missing error-path samples, and missing backward-compatibility fixtures.

Use this when:
- prioritizing connectors for hardening
- deciding whether maintenance PRs should be draft-only
- planning test debt reduction

## Design notes

Quality agents are intentionally conservative.
They should produce reviewable signals and draft PR gating pressure before they mutate code.
In GNAT, a connector that still runs but emits the wrong meaning is more dangerous than one that simply fails fast.

## Recommended execution order

1. normalization regression
2. contract checks
3. fixture coverage scoring

## Integration guidance

- Run normalization checks on maintenance-generated branches.
- Fail hard on semantic drift unless explicitly approved.
- Run contract checks on all connector PRs.
- Use fixture coverage results as a policy input, not an immediate hard failure, until baseline coverage improves.

---

*Licensed under the Apache License, Version 2.0*
