# “””
ctm_sak.connectors.elastic.exceptions

Exception hierarchy for the Elastic Security connector.

Elasticsearch error response shape:
{
“error”: {
“root_cause”: [{“type”: “…”, “reason”: “…”}],
“type”: “search_phase_execution_exception”,
“reason”: “…”,
“caused_by”: {“type”: “…”, “reason”: “…”}
},
“status”: 400
}

Kibana error response shape:
{
“statusCode”: 404,
“error”: “Not Found”,
“message”: “Saved object [security-rule/abc] not found”
}

Or for validation errors:
{
“statusCode”: 400,
“error”: “Bad Request”,
“message”: “[request body.name]: expected value of type [string]”
}

## Hierarchy

ElasticError
├── ElasticConfigError
├── ElasticAuthError
├── ElasticAPIError               — Elasticsearch API errors
│     ├── ElasticNotFoundError
│     ├── ElasticRateLimitError
│     └── ElasticConflictError   — 409 version conflict / duplicate
├── ElasticKibanaError            — Kibana API errors
│     ├── ElasticKibanaNotFoundError
│     └── ElasticKibanaValidationError
└── ElasticSTIXError
“””

class ElasticError(Exception):
“”“Base exception for all Elastic Security connector errors.”””

# ── Configuration ─────────────────────────────────────────────────────────────

class ElasticConfigError(ElasticError):
“”“Raised when [elastic] INI section is missing or invalid.”””

# ── Authentication ────────────────────────────────────────────────────────────

class ElasticAuthError(ElasticError):
“””
Raised on authentication failures.
- Missing or invalid API key (HTTP 401)
- API key lacks required cluster/index privileges (HTTP 403)
“””

# ── Elasticsearch API ─────────────────────────────────────────────────────────

class ElasticAPIError(ElasticError):
“””
Raised on Elasticsearch REST API errors.

```
Attributes
----------
status_code : int | None
    HTTP status code.
error_type : str
    Elasticsearch error type string (e.g. 'index_not_found_exception').
reason : str
    Human-readable error reason from ES.
endpoint : str | None
    URL that returned the error.
"""

def __init__(
    self,
    message: str,
    status_code: int | None = None,
    error_type: str = "",
    reason: str = "",
    endpoint: str | None = None,
) -> None:
    super().__init__(message)
    self.status_code = status_code
    self.error_type = error_type
    self.reason = reason
    self.endpoint = endpoint

def __str__(self) -> str:
    parts = [super().__str__()]
    if self.status_code:
        parts.append(f"HTTP {self.status_code}")
    if self.error_type:
        parts.append(f"type={self.error_type}")
    if self.reason:
        parts.append(f"reason={self.reason!r}")
    if self.endpoint:
        parts.append(f"endpoint={self.endpoint}")
    return " | ".join(parts)
```

class ElasticNotFoundError(ElasticAPIError):
“”“Raised on HTTP 404 from the Elasticsearch API.”””

class ElasticRateLimitError(ElasticAPIError):
“”“Raised on HTTP 429 from Elasticsearch.”””

class ElasticConflictError(ElasticAPIError):
“””
Raised on HTTP 409.
Typically a document version conflict or duplicate index.
“””

# ── Kibana API ────────────────────────────────────────────────────────────────

class ElasticKibanaError(ElasticError):
“””
Raised on Kibana API errors (Security, Cases, Spaces APIs).

```
Attributes
----------
status_code : int | None
    HTTP status code.
kibana_message : str
    Error message from Kibana response body.
endpoint : str | None
    Kibana endpoint URL.
"""

def __init__(
    self,
    message: str,
    status_code: int | None = None,
    kibana_message: str = "",
    endpoint: str | None = None,
) -> None:
    super().__init__(message)
    self.status_code = status_code
    self.kibana_message = kibana_message
    self.endpoint = endpoint

def __str__(self) -> str:
    parts = [super().__str__()]
    if self.status_code:
        parts.append(f"HTTP {self.status_code}")
    if self.kibana_message:
        parts.append(f"kibana_message={self.kibana_message!r}")
    if self.endpoint:
        parts.append(f"endpoint={self.endpoint}")
    return " | ".join(parts)
```

class ElasticKibanaNotFoundError(ElasticKibanaError):
“”“Raised on HTTP 404 from the Kibana API.”””

class ElasticKibanaValidationError(ElasticKibanaError):
“”“Raised on HTTP 400 from the Kibana API (validation failure).”””

# ── STIX ─────────────────────────────────────────────────────────────────────

class ElasticSTIXError(ElasticError):
“””
Raised when Elastic ↔ STIX 2.1 mapping fails.
Covers ECS-to-STIX and STIX-to-ECS field mapping errors.
“””