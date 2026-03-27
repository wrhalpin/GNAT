# “””
ctm_sak.connectors.wazuh.exceptions

Exception hierarchy for the Wazuh connector.

Wazuh error response shape (Manager API):
{
“title”:       “Permission Denied”,
“detail”:      “Permission denied: …”,
“remediation”: “…”,
“error”:       4000
}

Wazuh error codes of note:
4000  — Permission denied
4001  — Authentication error (bad credentials)
4009  — Token has expired
6001  — Agent not found
6003  — Agent name already exists
1750  — Rule not found
1802  — Decoder not found

## Hierarchy

WazuhError
├── WazuhConfigError
├── WazuhAuthError
│     └── WazuhTokenExpiredError
├── WazuhAPIError
│     ├── WazuhNotFoundError
│     ├── WazuhPermissionError
│     └── WazuhRateLimitError
├── WazuhSTIXError
└── WazuhIndexerError
“””

class WazuhError(Exception):
“”“Base exception for all Wazuh connector errors.”””

# ── Configuration ─────────────────────────────────────────────────────────────

class WazuhConfigError(WazuhError):
“”“Raised when [wazuh] INI section is missing or invalid.”””

# ── Authentication ────────────────────────────────────────────────────────────

class WazuhAuthError(WazuhError):
“””
Raised on authentication failures.
- Bad username/password (HTTP 401, error code 4001)
- Account locked or disabled
“””

class WazuhTokenExpiredError(WazuhAuthError):
“””
Raised when the JWT token has expired (error code 4009).
WazuhAuthManager catches this internally and re-authenticates;
it is only surfaced if re-authentication also fails.
“””

# ── API / HTTP ────────────────────────────────────────────────────────────────

class WazuhAPIError(WazuhError):
“””
Raised on unexpected HTTP responses or Wazuh error codes.

```
Attributes
----------
status_code : int | None
    HTTP status code.
error_code : int | None
    Wazuh internal error code from the response body.
endpoint : str | None
    The URL endpoint that returned the error.
title : str
    Wazuh error title string.
detail : str
    Wazuh error detail string.
remediation : str
    Wazuh suggested remediation, if provided.
"""

def __init__(
    self,
    message: str,
    status_code: int | None = None,
    error_code: int | None = None,
    endpoint: str | None = None,
    title: str = "",
    detail: str = "",
    remediation: str = "",
) -> None:
    super().__init__(message)
    self.status_code = status_code
    self.error_code = error_code
    self.endpoint = endpoint
    self.title = title
    self.detail = detail
    self.remediation = remediation

def __str__(self) -> str:
    parts = [super().__str__()]
    if self.status_code:
        parts.append(f"HTTP {self.status_code}")
    if self.error_code:
        parts.append(f"error_code={self.error_code}")
    if self.title:
        parts.append(f"title={self.title!r}")
    if self.detail:
        parts.append(f"detail={self.detail!r}")
    if self.endpoint:
        parts.append(f"endpoint={self.endpoint}")
    return " | ".join(parts)
```

class WazuhNotFoundError(WazuhAPIError):
“”“Raised on HTTP 404 or Wazuh ‘not found’ error codes.”””

class WazuhPermissionError(WazuhAPIError):
“””
Raised when the authenticated user lacks required RBAC permissions
(HTTP 403, Wazuh error code 4000).
“””

class WazuhRateLimitError(WazuhAPIError):
“”“Raised on HTTP 429. Wazuh rate-limits the authentication endpoint.”””

# ── STIX ─────────────────────────────────────────────────────────────────────

class WazuhSTIXError(WazuhError):
“””
Raised when Wazuh event → STIX 2.1 mapping fails.
Common causes: missing required fields, unsupported event type,
malformed input dict.
“””

# ── Indexer ───────────────────────────────────────────────────────────────────

class WazuhIndexerError(WazuhError):
“””
Raised on Wazuh Indexer (OpenSearch) API errors.
Only raised when `indexer_enabled = true` in config.
“””