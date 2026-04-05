"""
gnat.connectors.splunk.exceptions

Exception hierarchy for the Splunk connector.

All exceptions inherit from SplunkError so callers can catch the
entire connector's error surface with a single except clause.

## Hierarchy

SplunkError                         -- base
├── SplunkConfigError             -- bad/missing INI config
├── SplunkAuthError               -- authentication / token failures
├── SplunkAPIError                -- HTTP-level or JSON parse errors
│     ├── SplunkRateLimitError    -- 429 / rate throttled
│     └── SplunkNotFoundError     -- 404 resource not found
├── SplunkSearchError             -- SPL search job failures
├── SplunkThreatIntelError        -- ES Threat Intel API errors
└── SplunkSTIXError               -- STIX mapping / serialization errors
"""


class SplunkError(Exception):
    """Base exception for all Splunk connector errors."""

    # ── Configuration ─────────────────────────────────────────────────────────────


class SplunkConfigError(SplunkError):
    """
    Raised when the [splunk] INI section is missing, malformed,
    or contains invalid values.
    """

    # ── Authentication ────────────────────────────────────────────────────────────


class SplunkAuthError(SplunkError):
    """
    Raised on authentication failures:
    - Bad username/password (403)
    - Expired or revoked session token
    - Token renewal failure
    """

    # ── API / HTTP ────────────────────────────────────────────────────────────────


class SplunkAPIError(SplunkError):
    """
    Raised on unexpected HTTP responses or JSON parse errors.

    Attributes
    ----------
    status_code : int | None
        HTTP status code from the Splunk response, if available.
    endpoint : str | None
        The URL endpoint that returned the error.
    messages : list[str]
        Error messages extracted from Splunk's JSON error body.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        endpoint: str | None = None,
        messages: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint
        self.messages = messages or []

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        if self.messages:
            parts.append(f"messages={self.messages}")
        return " | ".join(parts)


class SplunkRateLimitError(SplunkAPIError):
    """
    Raised on HTTP 429 (Too Many Requests).

    Splunk does not expose a Retry-After header consistently;
    callers should implement exponential backoff.
    """


class SplunkNotFoundError(SplunkAPIError):
    """Raised on HTTP 404 -- resource (index, saved search, etc.) not found."""

    # ── Search ────────────────────────────────────────────────────────────────────


class SplunkSearchError(SplunkError):
    """
    Raised when a search job fails or times out.

    Attributes
    ----------
    job_sid : str | None
        Splunk search job SID for diagnostics.
    dispatch_state : str | None
        Last known job dispatch state (e.g. 'FAILED', 'PAUSED').
    """

    def __init__(
        self,
        message: str,
        job_sid: str | None = None,
        dispatch_state: str | None = None,
    ) -> None:
        super().__init__(message)
        self.job_sid = job_sid
        self.dispatch_state = dispatch_state

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.job_sid:
            parts.append(f"sid={self.job_sid}")
        if self.dispatch_state:
            parts.append(f"state={self.dispatch_state}")
        return " | ".join(parts)

    # ── Threat Intel ──────────────────────────────────────────────────────────────


class SplunkThreatIntelError(SplunkError):
    """
    Raised on Enterprise Security Threat Intel API failures.

    Only raised when ``es_enabled = true`` in config.
    Covers IOC upload, collection management, and feed errors.
    """

    # ── STIX ─────────────────────────────────────────────────────────────────────


class SplunkSTIXError(SplunkError):
    """
    Raised when STIX 2.1 ↔ Splunk field mapping fails.

    Common causes:
      - STIX object type not supported by Splunk ES (e.g. indicator patterns)
      - Missing required STIX properties for mapping
      - Malformed STIX bundle passed to the mapper
    """
