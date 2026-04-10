# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dynatrace.exceptions
==========================================
Exception hierarchy for the Dynatrace connector.

Dynatrace REST API error response shape
-----------------------------------------
  {
    "error": {
      "code": 400,
      "message": "Constraints violated.",
      "constraintViolations": [...]
    }
  }

Hierarchy
---------
DynatraceError
  ├── DynatraceConfigError          — Missing/invalid [dynatrace] config
  ├── DynatraceAuthError            — Token acquisition failure, 401/403
  ├── DynatraceAPIError(GNATClientError)
  │     ├── DynatraceNotFoundError  — HTTP 404
  │     ├── DynatraceRateLimitError — HTTP 429
  │     └── DynatraceConflictError  — HTTP 409
  ├── DynatraceSTIXError            — STIX mapping failures
  └── DynatraceQueryTimeoutError    — Grail DQL poll timed out
"""

from gnat.clients.base import GNATClientError


class DynatraceError(Exception):
    """Base exception for all Dynatrace connector errors."""


class DynatraceConfigError(DynatraceError):
    """Raised when [dynatrace] INI section is missing or invalid."""


class DynatraceAuthError(DynatraceError):
    """
    Raised on OAuth2 token acquisition failures or HTTP 401/403.

    Attributes
    ----------
    dt_error_code : str
        Dynatrace error code string from the token endpoint response.
    """

    def __init__(self, message: str, dt_error_code: str = "") -> None:
        """Initialize DynatraceAuthError."""
        super().__init__(message)
        self.dt_error_code = dt_error_code


class DynatraceAPIError(GNATClientError):
    """
    Raised on unexpected Dynatrace REST API responses.

    Attributes
    ----------
    status_code : int | None
    dt_error_code : str
    endpoint : str | None
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        dt_error_code: str = "",
        endpoint: str | None = None,
    ) -> None:
        """Initialize DynatraceAPIError."""
        super().__init__(message, status=status_code or 0)
        self.status_code = status_code
        self.dt_error_code = dt_error_code
        self.endpoint = endpoint

    def __str__(self) -> str:
        """Return human-readable string representation."""
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.dt_error_code:
            parts.append(f"code={self.dt_error_code}")
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        return " | ".join(parts)


class DynatraceNotFoundError(DynatraceAPIError):
    """Raised on HTTP 404 from the Dynatrace API."""


class DynatraceRateLimitError(DynatraceAPIError):
    """Raised on HTTP 429."""


class DynatraceConflictError(DynatraceAPIError):
    """Raised on HTTP 409."""


class DynatraceSTIXError(DynatraceError):
    """Raised when STIX 2.1 ↔ Dynatrace object mapping fails."""


class DynatraceQueryTimeoutError(DynatraceError):
    """Raised when a Grail DQL query poll exceeds the maximum wait time."""
