# Security Policy

## Supported Versions

GNAT is an actively evolving project. Security fixes are applied to the latest version on the `main` branch unless otherwise specified.

| Version | Supported |
|---|---|
| `main` | Yes |
| older releases | Best effort |

## Reporting a Vulnerability

If you discover a security vulnerability in GNAT, please report it responsibly.

### Do not open a public issue

Instead, report vulnerabilities privately to the project maintainers.

**Security contact:** replace this line with your preferred address, such as `security@yourdomain.example` or a dedicated maintainer mailbox.

## What to Include

Please include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Affected components, such as connectors, agents, pipelines, or secrets handling
- Potential impact
- Suggested mitigation, if known

## Scope

This policy applies to:

- Core GNAT platform
- Connectors, including XSOAR, ThreatQ, GreyMatter, and future connectors
- Agent framework, including maintenance, quality, and security agents
- Secrets management components
- Data ingestion and processing pipelines
- Report generation and analyst workflow features as they are added

## Response Process

We aim to follow a responsible disclosure process:

1. **Acknowledgement**  
   We will try to acknowledge receipt within 72 hours.

2. **Investigation**  
   We will assess severity, scope, exploitability, and operational impact.

3. **Remediation**  
   We will develop and validate a fix or mitigation.

4. **Disclosure**  
   We will coordinate disclosure after a fix or mitigation is available. Credit will be given where appropriate unless anonymity is requested.

## Severity Guidelines

We generally prioritize reports in the following order.

### Critical
- Remote code execution
- Unauthorized access to protected data
- Secrets exposure
- Authentication or authorization bypass

### High
- Privilege escalation
- Connector compromise
- Material data integrity issues
- Agent behaviors that can be coerced into unsafe actions

### Medium
- Denial of service
- Information leakage
- Mis-scoped access controls

### Low
- Minor issues with limited impact or difficult exploitation paths

## Security Considerations

GNAT may handle sensitive intelligence and investigation data. Contributors and operators should:

- Avoid committing secrets or credentials
- Prefer secure storage backends and vault integrations
- Validate and normalize all external inputs
- Be explicit about trust boundaries for connectors and external services
- Review agent-generated actions before execution
- Keep dependencies and CI security checks current

## Disclosure Policy

GNAT follows coordinated responsible disclosure.

Public disclosure should occur only after:

- A fix is available, or
- A mitigation is available and documented, or
- The maintainers determine that users need immediate notice due to active exploitation

## Third-Party Dependencies

GNAT relies on external libraries, APIs, and services. Maintainers should:

- Monitor upstream advisories
- Run dependency and supply-chain scanning
- Patch critical issues promptly
- Preserve required notices for bundled or copied third-party code

## Security Best Practices for Contributors

Contributors should:

- Follow secure coding practices
- Add validation and error handling
- Avoid unsafe deserialization and unnecessary dynamic execution
- Use least-privilege access patterns in integrations
- Call out security-sensitive design choices in pull requests and ADRs

## Acknowledgements

We appreciate responsible disclosure and may acknowledge reporters unless anonymity is requested.

## Contact

For all security-related concerns, use the private security contact designated by the project maintainers.
