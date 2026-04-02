# Security Agents

## Overview

GNAT security agents protect credential handling, secret hygiene, and platform trust boundaries.
They are designed around a policy-first broker so connectors and maintenance agents do not need direct
knowledge of Azure Key Vault, CyberArk, or other secret backends.

## Phase B focus

This scaffold packages the broker hardening layer:
- provider capability model
- policy-driven reads and writes
- Azure Key Vault write-aware implementation
- CyberArk capability-first placeholder
- audit event capture
- connector config secret reference resolution

## Phase C foundation

This scaffold also includes the initial hygiene layer:
- leak scanning
- duplicate detection
- unsafe secret pattern detection
