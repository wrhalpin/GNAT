# Normalization Regression Agent

This agent protects GNAT's semantic contract: connector output should continue to normalize into the same expected structure unless a deliberate change is being made.

## Why this matters

A connector can stay healthy at the transport layer while silently changing meaning:
- field renames in upstream APIs
- mapper drift
- lossy translation changes
- reordered or dropped normalized artifacts

The normalization regression agent adds a golden-fixture layer that catches those shifts early.

## Seed fixture format

Each fixture lives under `tests/unit/agents/data/` and includes:
- `connector`
- `mapper`
- `method`
- `input`
- `expected`
- `policy`

The policy currently supports:
- `ignore_fields`: volatile keys such as timestamps or generated IDs
- `allow_additional_fields`: permit additive output changes while still enforcing required semantics
- `require_exact_list_length`: enforce cardinality on list outputs

## Recommended rollout

1. Start with a few translation-sensitive connectors such as Cribl, AlienVault, and MISP.
2. Add one or two golden fixtures per high-value normalization path.
3. Wire this workflow into the connector maintenance pipeline so repair PRs must preserve normalized meaning.
4. Expand fixture coverage before adding more autonomous repair behavior.

## Integration with maintenance agents

The maintenance pipeline should call this agent after patch generation and before PR creation. A patch that fixes transport compatibility but changes normalization should either:
- fail the branch outright, or
- open a draft PR with the regression clearly called out for review.

## Likely Phase 4 follow-ups

- fixture manifests instead of pure file globbing
- per-connector comparison policies
- support for bundle-level STIX comparison
- selective field tolerance for `x_*` vendor extension additions
- machine-readable regression reports for PR comments
