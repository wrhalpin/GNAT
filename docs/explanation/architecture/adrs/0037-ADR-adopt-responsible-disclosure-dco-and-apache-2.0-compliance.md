# ADR-0007: Adopt Responsible Disclosure, DCO, and Apache-2.0 Compliance Practices

- **Status:** Proposed
- **Date:** 2026-04-07
- **Deciders:** GNAT maintainers
- **Technical Story:** Establish a lightweight governance baseline for contributions, licensing clarity, and security reporting as GNAT grows.

## Context

GNAT is evolving from an internal engineering effort into a platform that may attract broader use and contribution. The project already places strong emphasis on architecture, maintainability, and disciplined design. Governance around licensing, contribution attestation, and vulnerability disclosure should be made equally explicit.

Three needs have emerged:

1. **Licensing clarity**  
   GNAT is licensed under Apache License 2.0. The project should make reuse and redistribution straightforward for downstream users while keeping source files and documentation unambiguous.

2. **Contribution provenance with low friction**  
   GNAT needs a clear way for contributors to attest that they have the right to submit their work under the project license, without introducing unnecessary administrative burden.

3. **Private security reporting path**  
   Because GNAT may process sensitive intelligence and integrate with external systems, reporters need a clear, private channel for vulnerability disclosure and maintainers need a predictable response model.

A heavy governance model would work against GNAT's preference for clean structure, low-friction contribution, and maintainable process. A lightweight but explicit baseline is preferred.

## Decision

GNAT will adopt the following governance baseline:

### 1. Apache-2.0 compliance conventions

GNAT will continue to use Apache License 2.0 as the repository license.

The repository will include and maintain:

- `LICENSE` containing the full Apache License 2.0 text
- `NOTICE` for project-level notices and attribution where required
- Source-file license identification using SPDX headers where practical
- Documentation-level license references where full source headers are not appropriate

The preferred source-file header format is:

```text
SPDX-License-Identifier: Apache-2.0
Copyright 2026 GNAT contributors
```

Per-file author tags will not be required. Git history remains the source of truth for authorship.

### 2. DCO instead of CLA

GNAT will use the **Developer Certificate of Origin (DCO)** rather than a Contributor License Agreement (CLA).

Contributors will certify their commits using a sign-off line, typically added through:

```bash
git commit -s
```

Pull requests should be checked automatically for DCO sign-off.

This choice is intended to preserve contributor friendliness while still recording license attestation at contribution time.

### 3. Responsible disclosure process

GNAT will publish and maintain a root-level `SECURITY.md` file.

The security policy will:

- Ask reporters not to file public issues for vulnerabilities
- Provide a private reporting path
- Describe expected acknowledgement and remediation flow
- Define a coordinated disclosure model
- Clarify scope for connectors, agents, pipelines, secrets handling, and related components

## Consequences

### Positive

- Clarifies project expectations early
- Reduces ambiguity for adopters and contributors
- Creates a low-friction contribution process that scales better than a CLA for this project stage
- Improves project credibility, especially for a security-focused platform
- Encourages better operational hygiene around vulnerability handling

### Negative

- Maintainers must keep governance files current
- DCO enforcement adds one more CI gate
- Security contact handling becomes an operational responsibility
- SPDX and notice hygiene require some ongoing discipline during refactors and code imports

### Neutral

- This does not replace secure coding practices, threat modeling, or CI security testing
- This does not prevent adding a CLA later if project needs change

## Alternatives Considered

### Use no formal contribution attestation

Rejected because it leaves contribution provenance and licensing intent unnecessarily ambiguous.

### Use a CLA immediately

Rejected for now because it adds more friction than is justified at GNAT's current stage. A CLA may be revisited if commercial, organizational, or IP-control requirements change.

### Use only a LICENSE file with no headers or notice conventions

Rejected because copied files and partial redistributions become less clear, and compliance automation becomes harder.

### Keep security disclosure informal

Rejected because security-sensitive projects benefit from an explicit private reporting path and predictable disclosure expectations.

## Implementation Notes

The repository should add or maintain:

- `LICENSE`
- `NOTICE`
- `DCO.md`
- `CONTRIBUTING.md`
- `SECURITY.md`

The repository should also:

- Add DCO enforcement in CI for pull requests
- Prefer SPDX license identifiers in source files
- Avoid per-file author tags
- Preserve third-party notices and upstream license requirements when code is copied or vendored

## Follow-On Work

- Finalize the security contact and update `SECURITY.md`
- Add DCO instructions to `CONTRIBUTING.md`
- Add CI enforcement for signed-off commits
- Decide whether to standardize copyright naming as project name, individual maintainer, or organization
- Add an ADR covering dependency, SBOM, and supply-chain policy if GNAT distribution widens

## References

- Apache License 2.0
- Developer Certificate of Origin 1.1
- GNAT repository governance and documentation conventions
