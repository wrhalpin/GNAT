# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.taxii._protocol
====================
Low-level TAXII 2.1 protocol helpers shared by
``gnat.serve.taxii`` and ``gnat.dissemination.taxii``.

These utilities deal **only** with the wire format defined by the
TAXII 2.1 specification (https://docs.oasis-open.org/cti/taxii/v2.1/).
They have no knowledge of collection backends, authentication schemes,
or application-level business logic.

Helpers
-------
Constants
~~~~~~~~~
``TAXII_MEDIA_TYPE``
    ``application/taxii+json;version=2.1`` — required ``Content-Type``
    for all TAXII responses (spec §3.1).

``STIX_MEDIA_TYPE``
    ``application/stix+json;version=2.1`` — content type for STIX 2.1
    bundles returned inside TAXII envelopes.

Pagination
~~~~~~~~~~
``encode_cursor(offset)``
    Encode an integer list offset as an opaque URL-safe base64 token
    suitable for the TAXII ``next`` query parameter.

``decode_cursor(token)``
    Decode a cursor token back to an integer offset.  Returns ``0`` for
    any invalid or non-integer token — never raises.

Response helpers
~~~~~~~~~~~~~~~~
``taxii_response(content, status_code=200)``
    Return a ``fastapi.responses.JSONResponse`` carrying the TAXII 2.1
    media type.  FastAPI is imported lazily so this module can be
    imported without the ``[serve]`` extra installed.

``utcnow_iso()``
    Current UTC time as an ISO 8601 string (millisecond precision).

STIX bundle
~~~~~~~~~~~
``make_stix_bundle(objects)``
    Build a minimal STIX 2.1 bundle envelope dict with a random UUID.

Discovery / API-root bodies
~~~~~~~~~~~~~~~~~~~~~~~~~~~
``make_discovery_body(title, description, contact, default_root, api_roots)``
    Build a TAXII 2.1 Discovery response body (spec §4.1).

``make_api_root_body(title, description, max_content_length)``
    Build a TAXII 2.1 API-root information response body (spec §4.2).
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Media-type constants (spec §3.1)
# ---------------------------------------------------------------------------

TAXII_MEDIA_TYPE: str = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE: str = "application/stix+json;version=2.1"


# ---------------------------------------------------------------------------
# Cursor-based pagination helpers
# ---------------------------------------------------------------------------


def encode_cursor(offset: int) -> str:
    """Encode an integer list offset as an opaque base64 pagination cursor.

    Parameters
    ----------
    offset : int
        Zero-based list offset to encode.

    Returns
    -------
    str
        URL-safe base64 string suitable for use as the TAXII ``next``
        query parameter.
    """
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def decode_cursor(token: str) -> int:
    """Decode a pagination cursor token to an integer offset.

    Parameters
    ----------
    token : str
        Cursor token previously produced by :func:`encode_cursor`.

    Returns
    -------
    int
        Decoded offset, or ``0`` if *token* is missing, invalid base64,
        or does not decode to an integer string.
    """
    import binascii

    try:
        return int(base64.urlsafe_b64decode(token.encode()).decode())
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error):
        return 0


# ---------------------------------------------------------------------------
# Response helper
# ---------------------------------------------------------------------------


def taxii_response(content: Any, status_code: int = 200) -> Any:
    """Return a FastAPI JSONResponse with the TAXII 2.1 media type.

    FastAPI is imported lazily; this function will raise ``ImportError``
    at call time if FastAPI is not installed (``pip install 'gnat[serve]'``).

    Parameters
    ----------
    content : Any
        JSON-serialisable response body.
    status_code : int
        HTTP status code.  Defaults to ``200``.

    Returns
    -------
    fastapi.responses.JSONResponse
    """
    from fastapi.responses import JSONResponse  # lazy — avoid hard dep

    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type=TAXII_MEDIA_TYPE,
    )


# ---------------------------------------------------------------------------
# Time helper
# ---------------------------------------------------------------------------


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string (millisecond precision).

    Returns
    -------
    str
        e.g. ``"2026-04-08T18:00:00.000+00:00"``
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# STIX bundle envelope
# ---------------------------------------------------------------------------


def make_stix_bundle(objects: list[dict]) -> dict:
    """Build a minimal STIX 2.1 bundle envelope dict.

    Parameters
    ----------
    objects : list[dict]
        STIX objects to include in the bundle.

    Returns
    -------
    dict
        A STIX 2.1 bundle with a fresh random ``id``, ``spec_version``
        ``"2.1"``, and the supplied ``objects``.
    """
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# Discovery / API-root response bodies (spec §4.1, §4.2)
# ---------------------------------------------------------------------------


def make_discovery_body(
    title: str,
    description: str,
    contact: str,
    default_root: str,
    api_roots: list[str],
) -> dict:
    """Build a TAXII 2.1 Discovery response body (spec §4.1).

    Parameters
    ----------
    title : str
        Human-readable server title.
    description : str
        Short server description.
    contact : str
        Contact e-mail or URL (may be empty).
    default_root : str
        URL path of the default API root.
    api_roots : list[str]
        All available API root URL paths.

    Returns
    -------
    dict
        TAXII 2.1 Discovery resource.
    """
    return {
        "title": title,
        "description": description,
        "contact": contact,
        "default": default_root,
        "api_roots": api_roots,
    }


def make_api_root_body(
    title: str,
    description: str,
    max_content_length: int = 10_485_760,
) -> dict:
    """Build a TAXII 2.1 API-root information response body (spec §4.2).

    Parameters
    ----------
    title : str
        Human-readable API root title.
    description : str
        Short description of what this API root contains.
    max_content_length : int
        Maximum accepted request body size in bytes.
        Defaults to 10 MiB (10 * 1024 * 1024).

    Returns
    -------
    dict
        TAXII 2.1 API-root resource.
    """
    return {
        "title": title,
        "description": description,
        "versions": [TAXII_MEDIA_TYPE],
        "max_content_length": max_content_length,
    }
