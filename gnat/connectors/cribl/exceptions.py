"""Exception hierarchy for the Cribl connector."""

from __future__ import annotations

from typing import Optional


class CriblError(Exception):
    """
    Base exception for all Cribl connector errors.

    Parameters
    ----------
    message : str
        Human-readable description of the error.
    status_code : int, optional
        HTTP status code associated with the error.
    response_body : str, optional
        Raw response body from the API.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class CriblAuthError(CriblError):
    """Raised when authentication against the Cribl API fails."""


class CriblNotFoundError(CriblError):
    """Raised when a requested Cribl resource cannot be found (HTTP 404)."""


class CriblValidationError(CriblError):
    """Raised when the Cribl API rejects a request payload (HTTP 400)."""


class CriblRateLimitError(CriblError):
    """Raised when the Cribl API rate-limits the client (HTTP 429)."""
