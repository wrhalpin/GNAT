"""
ctm_sak.connectors.sentinel.exceptions
=========================================
Exception hierarchy for the Microsoft Sentinel connector.

Azure REST API error response shape
--------------------------------------
  {
    "error": {
      "code": "AuthorizationFailed",
      "message": "The client '...' does not have authorization to perform
                  action 'Microsoft.SecurityInsights/incidents/read'..."
    }
  }

Notable Azure error codes:
  AuthorizationFailed     — missing RBAC role on the service principal
  InvalidAuthenticationToken — token expired or malformed
  ResourceNotFound        — subscription/RG/workspace not found
  WorkspaceNotFound       — Sentinel workspace not found
  BadRequest              — malformed request body

Hierarchy
---------
SentinelError
  ├── SentinelConfigError
  ├── SentinelAuthError              — token acquisition failure / 401 / 403
  │     └── SentinelTokenExpiredError
  ├── SentinelAPIError               — general Azure REST API errors
  │     ├── SentinelNotFoundError    — 404
  │     ├── SentinelRateLimitError   — 429
  │     └── SentinelConflictError    — 409
  └── SentinelSTIXError
"""


class SentinelError(Exception):
    """Base exception for all Sentinel connector errors."""


class SentinelConfigError(SentinelError):
    """Raised when [sentinel] INI section is missing or invalid."""


class SentinelAuthError(SentinelError):
    """
    Raised on Azure OAuth2 token acquisition failures or HTTP 401/403.

    Attributes
    ----------
    azure_error_code : str
        Azure error code string (e.g. 'AuthorizationFailed').
    """
    def __init__(self, message: str, azure_error_code: str = "") -> None:
        super().__init__(message)
        self.azure_error_code = azure_error_code


class SentinelTokenExpiredError(SentinelAuthError):
    """Raised when the access token has expired mid-session."""


class SentinelAPIError(SentinelError):
    """
    Raised on unexpected Azure REST API responses.

    Attributes
    ----------
    status_code : int | None
    azure_error_code : str
    azure_message : str
    endpoint : str | None
    """
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        azure_error_code: str = "",
        azure_message: str = "",
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.azure_error_code = azure_error_code
        self.azure_message = azure_message
        self.endpoint = endpoint

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.azure_error_code:
            parts.append(f"code={self.azure_error_code}")
        if self.azure_message:
            parts.append(f"message={self.azure_message!r}")
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        return " | ".join(parts)


class SentinelNotFoundError(SentinelAPIError):
    """Raised on HTTP 404 from the Sentinel API."""


class SentinelRateLimitError(SentinelAPIError):
    """Raised on HTTP 429."""


class SentinelConflictError(SentinelAPIError):
    """Raised on HTTP 409 (e.g. duplicate watchlist alias)."""


class SentinelSTIXError(SentinelError):
    """Raised when STIX 2.1 ↔ Sentinel TI indicator mapping fails."""
