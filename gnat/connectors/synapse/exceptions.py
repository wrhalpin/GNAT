"""Exception hierarchy for the Synapse connector."""

from __future__ import annotations

from typing import Optional


class SynapseError(Exception):
    """
    Base exception for all Synapse connector errors.

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


class SynapseAuthError(SynapseError):
    """Raised when authentication against the Synapse API fails."""


class SynapseNotFoundError(SynapseError):
    """Raised when a requested Synapse node or resource is not found."""


class SynapseStormError(SynapseError):
    """
    Raised when a Storm query returns an error message.

    Parameters
    ----------
    message : str
        Human-readable description.
    query : str
        The Storm query that triggered the error.
    status_code : int, optional
        HTTP status code.
    response_body : str, optional
        Raw response body.
    """

    def __init__(
        self,
        message: str,
        query: str = "",
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response_body=response_body)
        self.query = query


class SynapseValidationError(SynapseError):
    """Raised when the Synapse API rejects a request payload (HTTP 400)."""
