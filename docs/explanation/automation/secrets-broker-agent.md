# Secrets Broker Agent

This scaffold introduces a new `gnat/agents/secrets/` family designed for:

- brokered storage and retrieval of connector credentials
- Azure Key Vault support from day one
- CyberArk support as a first-class future provider
- secret leak scanning and duplicate detection up front
- redaction-safe handling throughout the platform

## Design goals

1. Use secret references everywhere possible.
2. Keep raw values at execution boundaries only.
3. Enforce policy before touching a vault.
4. Treat hygiene scanning as part of the same system, not an afterthought.
5. Preserve room for CyberArk's account checkout and rotation model.

## Phase A included here

- `SecretsBroker` with policy enforcement
- Azure Key Vault provider implementation
- in-memory provider for local tests and demos
- path-based secret naming
- redaction helpers
- leak scanning, duplicate detection, and unsafe secret heuristics

## Phase B candidates

- policy loading from YAML
- richer audit events
- secret version pinning and staged updates
- connector configuration helpers

## Phase C candidates

- rotation flows
- connector post-rotation verification
- richer CyberArk account workflows
