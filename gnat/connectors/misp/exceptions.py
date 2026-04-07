# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.misp.exceptions
=====================================
Exception hierarchy for the MISP connector.

MISP error response shapes
---------------------------
Success (200): {"saved": true, "success": true, "id": "123", ...}
  or for lists: {"Event": [...]} or just a list

Error (4xx/5xx): {"message": "...", "errors": {...}}
  or: {"name": "...", "message": "...", "url": "..."}
  or just plain text for some endpoints

MISP uses HTTP 200 for some errors (check "errors" key) and HTTP
40x for auth/not-found errors.

Hierarchy
---------
MISPError
  ├── MISPConfigError
  ├── MISPAuthError         — 401/403 or missing API key
  ├── MISPAPIError          — general REST API errors
  │     ├── MISPNotFoundError   — 404
  │     ├── MISPValidationError — 400 / {"errors": {...}}
  │     └── MISPRateLimitError  — 429
  └── MISPSTIXError         — STIX mapping failures
"""


class MISPError(Exception):
    """Base exception for all MISP connector errors."""


class MISPConfigError(MISPError):
    """Raised when [misp] INI section is missing or invalid."""


class MISPAuthError(MISPError):
    """Raised when the MISP API key is rejected (HTTP 401/403)."""


class MISPAPIError(MISPError):
    """
    Raised on unexpected MISP API responses.

    Attributes
    ----------
    status_code : int | None
    misp_message : str
    endpoint : str | None
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        misp_message: str = "",
        endpoint: str | None = None,
    ) -> None:
        """Initialize MISPAPIError."""
        super().__init__(message)
        self.status_code = status_code
        self.misp_message = misp_message
        self.endpoint = endpoint

    def __str__(self) -> str:
        """Return human-readable string representation."""
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.misp_message:
            parts.append(f"misp={self.misp_message!r}")
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        return " | ".join(parts)


class MISPNotFoundError(MISPAPIError):
    """Raised on HTTP 404 from the MISP API."""


class MISPValidationError(MISPAPIError):
    """Raised when MISP returns validation errors."""


class MISPRateLimitError(MISPAPIError):
    """Raised on HTTP 429."""


class MISPSTIXError(MISPError):
    """Raised when MISP ↔ STIX 2.1 mapping fails."""
