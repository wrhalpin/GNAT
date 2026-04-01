"""
gnat.connectors.qradar.exceptions
=======================================
Exception hierarchy for the QRadar connector.

QRadar error response shape
----------------------------
QRadar returns structured JSON errors for all 4xx/5xx responses:

  {
    "http_response": {
      "code": 403,
      "message": "Forbidden"
    },
    "code": 1002,
    "description": "You are not authorized to access this endpoint.",
    "details": {},
    "message": "403 Forbidden"
  }

The ``code`` field is QRadar's internal error code (distinct from HTTP).
The ``description`` field is the human-readable error detail.

Notable QRadar error codes:
  1002  — not authorised (missing capability)
  1003  — resource not found
  1004  — bad request / validation failure
  1005  — method not allowed
  38001 — Ariel search syntax error
  38002 — Ariel search timeout
  38003 — Ariel search cancelled

Hierarchy
---------
QRadarError
  ├── QRadarConfigError
  ├── QRadarAuthError              — 401 / 403 / code 1002
  ├── QRadarAPIError               — general API errors
  │     ├── QRadarNotFoundError    — 404 / code 1003
  │     ├── QRadarRateLimitError   — 429
  │     └── QRadarConflictError    — 409 (duplicate resource)
  ├── QRadarArielError             — Ariel search job failures
  └── QRadarSTIXError              — STIX mapping failures
"""


class QRadarError(Exception):
    """Base exception for all QRadar connector errors."""


# ── Configuration ─────────────────────────────────────────────────────────────


class QRadarConfigError(QRadarError):
    """Raised when [qradar] INI section is missing or invalid."""


# ── Authentication ────────────────────────────────────────────────────────────


class QRadarAuthError(QRadarError):
    """
    Raised on authentication / authorisation failures.
      - HTTP 401: invalid or missing SEC token
      - HTTP 403: token lacks required capability
      - QRadar error code 1002
    """


# ── API ───────────────────────────────────────────────────────────────────────


class QRadarAPIError(QRadarError):
    """
    Raised on unexpected QRadar API responses.

    Attributes
    ----------
    status_code : int | None
        HTTP status code.
    qradar_code : int | None
        QRadar internal error code.
    description : str
        QRadar error description string.
    endpoint : str | None
        URL that returned the error.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        qradar_code: int | None = None,
        description: str = "",
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.qradar_code = qradar_code
        self.description = description
        self.endpoint = endpoint

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.qradar_code:
            parts.append(f"qradar_code={self.qradar_code}")
        if self.description:
            parts.append(f"description={self.description!r}")
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        return " | ".join(parts)


class QRadarNotFoundError(QRadarAPIError):
    """Raised on HTTP 404 or QRadar error code 1003."""


class QRadarRateLimitError(QRadarAPIError):
    """Raised on HTTP 429."""


class QRadarConflictError(QRadarAPIError):
    """
    Raised on HTTP 409.
    Typically a duplicate reference set name or existing resource.
    """


# ── Ariel ─────────────────────────────────────────────────────────────────────


class QRadarArielError(QRadarError):
    """
    Raised on Ariel search job failures.

    Attributes
    ----------
    search_id : str | None
        QRadar Ariel search ID for diagnostics.
    status : str | None
        Last known job status ('ERROR', 'CANCELLED', 'WAIT', etc.)
    error_messages : list[str]
        Error messages from the search job.
    """

    def __init__(
        self,
        message: str,
        search_id: str | None = None,
        status: str | None = None,
        error_messages: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.search_id = search_id
        self.status = status
        self.error_messages = error_messages or []

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.search_id:
            parts.append(f"search_id={self.search_id}")
        if self.status:
            parts.append(f"status={self.status}")
        if self.error_messages:
            parts.append(f"errors={self.error_messages[:2]}")
        return " | ".join(parts)


# ── STIX ─────────────────────────────────────────────────────────────────────


class QRadarSTIXError(QRadarError):
    """
    Raised when QRadar ↔ STIX 2.1 mapping fails.
    Common causes: unsupported offense type, missing required fields.
    """
