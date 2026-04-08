# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.taxii
==========
Shared TAXII 2.1 protocol utilities used by both
``gnat.serve.taxii`` and ``gnat.dissemination.taxii``.

Public surface
--------------
.. automodule:: gnat.taxii._protocol
"""

from gnat.taxii._protocol import (
    STIX_MEDIA_TYPE,
    TAXII_MEDIA_TYPE,
    decode_cursor,
    encode_cursor,
    make_api_root_body,
    make_discovery_body,
    make_stix_bundle,
    taxii_response,
    utcnow_iso,
)

__all__ = [
    "TAXII_MEDIA_TYPE",
    "STIX_MEDIA_TYPE",
    "encode_cursor",
    "decode_cursor",
    "taxii_response",
    "utcnow_iso",
    "make_stix_bundle",
    "make_discovery_body",
    "make_api_root_body",
]
