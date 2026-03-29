"""
gnat.utils.url_security
========================
Shared URL validation helpers to prevent SSRF and scheme-injection attacks.
"""

from __future__ import annotations

import urllib.parse


_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def validate_url_scheme(url: str, *, allow_http: bool = True) -> str:
    """
    Validate that *url* uses an allowed scheme and return it unchanged.

    Only ``https`` (and optionally ``http``) are permitted.  File, FTP,
    custom, or empty schemes raise :class:`ValueError` to prevent SSRF and
    path-traversal via ``file://`` URLs.

    Parameters
    ----------
    url : str
        The URL to validate.
    allow_http : bool
        If ``False``, only ``https`` is accepted (default: ``True``).

    Returns
    -------
    str
        The original *url* unchanged.

    Raises
    ------
    ValueError
        When the scheme is not in the allowed set.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    allowed = _ALLOWED_SCHEMES if allow_http else frozenset({"https"})
    if scheme not in allowed:
        raise ValueError(
            f"Blocked URL scheme {scheme!r} in {url!r}. "
            f"Only {sorted(allowed)} URLs are permitted."
        )
    return url
