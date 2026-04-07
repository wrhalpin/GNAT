# ADR: Security Agents Phase B

## Status
Accepted

## Context
GNAT needs a reusable, provider-agnostic security layer for connector credentials.
A simple get/put interface is too narrow because Azure Key Vault and CyberArk have different operational models.

## Decision
GNAT will implement a security agent family centered on a secrets broker with:
1. provider capability modeling
2. path-based secret references
3. policy-first read, write, and checkout decisions
4. audit event recording
5. hygiene agents for leak and unsafe-pattern detection

---

*Licensed under the Apache License, Version 2.0*
