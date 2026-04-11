# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix.version
=====================

Central STIX specification version constant for GNAT.

Why this file exists
--------------------
Before this module, the string literal ``"2.1"`` was inlined in 121
connector ``to_stix()`` implementations, the ORM default, helper
functions in :mod:`gnat.utils.stix_helpers`, the TAXII server's media
types, and the object validator's closed vocabulary — a total of more
than 370 touch points across the codebase.

Consolidating the version into a single constant means that a minor
STIX version bump (e.g. 2.1 → 2.2) is a one-line change in this file
instead of a sed-across-158-files operation.

What to do on a STIX release
----------------------------
* **Minor bump** (backwards-compatible): bump
  :data:`CURRENT_SPEC_VERSION` and add the new version to
  :data:`SUPPORTED_SPEC_VERSIONS`. Everything that imports from this
  module picks up the change for free. Also add any new SDO/SCO types
  as helpers in :mod:`gnat.utils.stix_helpers` and new ORM classes in
  :mod:`gnat.orm`.
* **Major bump** (breaking — e.g. STIX 3.0): bump the constants here,
  but expect to also audit each connector's ``to_stix()`` for renamed
  fields, pattern-grammar changes, and SCO layout changes. This module
  alone is not enough for a major bump, but it's the right place to
  start.

Downstream consumers
--------------------
* :class:`gnat.orm.base.STIXBase` — default ``spec_version`` field
* :mod:`gnat.utils.stix_helpers` — every envelope / pattern helper
* :class:`gnat.stix.object_validator.STIXObjectValidator` — closed
  vocabulary for the ``spec_version`` property
* :mod:`gnat.stix.pattern_validator` — ``stix_version`` argument
  forwarded to the ``stix2-patterns`` grammar library
* :mod:`gnat.taxii._protocol` — ``application/stix+json`` and
  ``application/taxii+json`` media types
* Every connector in :mod:`gnat.connectors` — emitted in ``to_stix()``
"""

from __future__ import annotations

#: The STIX specification version emitted by GNAT's helpers, ORM
#: defaults, custom SDOs, and connector ``to_stix()`` implementations.
#: Bump this when OASIS releases a new STIX 2.x minor version.
CURRENT_SPEC_VERSION: str = "2.1"

#: Every STIX version GNAT is prepared to ingest / validate. Used by
#: :class:`gnat.stix.object_validator.STIXObjectValidator`'s closed
#: vocabulary for the ``spec_version`` field. Older versions stay in
#: this set for backwards-compatibility with upstream feeds that have
#: not yet migrated.
SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"2.0", "2.1"})

#: MIME type served by the GNAT TAXII 2.1 server and expected from
#: upstream TAXII sources. Derived from :data:`CURRENT_SPEC_VERSION`
#: so a minor version bump automatically updates the media-type
#: version parameter.
TAXII_MEDIA_TYPE: str = f"application/taxii+json;version={CURRENT_SPEC_VERSION}"

#: MIME type for STIX-JSON envelopes as defined by the TAXII 2.1 spec.
#: Derived from :data:`CURRENT_SPEC_VERSION` for the same reason as
#: :data:`TAXII_MEDIA_TYPE`.
STIX_MEDIA_TYPE: str = f"application/stix+json;version={CURRENT_SPEC_VERSION}"

__all__ = [
    "CURRENT_SPEC_VERSION",
    "SUPPORTED_SPEC_VERSIONS",
    "STIX_MEDIA_TYPE",
    "TAXII_MEDIA_TYPE",
]
