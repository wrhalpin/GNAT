# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix
=========
STIX 2.1 utilities — pattern validation and object-level validation.

Pattern validation::

    from gnat.stix import validate_pattern, PatternValidationError

    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']")
    if not result:
        print(result.errors)

    # Strict mode — uses stix2-patterns ANTLR grammar when installed:
    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']", strict=True)

Object-level validation::

    from gnat.stix import validate_object, validate_bundle, ObjectValidationError

    result = validate_object({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--1d8d7c3e-abc1-4a7e-9f15-0123456789ab",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00.000Z",
    })
    assert result.valid

    # Strict mode — open-vocabulary violations become errors:
    validate_object(obj, strict=True, raise_on_error=True)

    # Bundle validation:
    bundle_result = validate_bundle({"type": "bundle", "id": "bundle--...", "objects": [...]})
"""

from gnat.stix.object_validator import (
    BundleValidationResult,
    ObjectValidationError,
    ObjectValidationResult,
    STIXBundleValidator,
    STIXObjectValidator,
    validate_bundle,
    validate_object,
)
from gnat.stix.pattern_validator import (
    PatternValidationError,
    PatternValidator,
    ValidationResult,
    validate_pattern,
)
from gnat.stix.version import (
    CURRENT_SPEC_VERSION,
    STIX_MEDIA_TYPE,
    SUPPORTED_SPEC_VERSIONS,
    TAXII_MEDIA_TYPE,
)

__all__ = [
    # Version constants
    "CURRENT_SPEC_VERSION",
    "SUPPORTED_SPEC_VERSIONS",
    "STIX_MEDIA_TYPE",
    "TAXII_MEDIA_TYPE",
    # Pattern validation
    "validate_pattern",
    "PatternValidator",
    "PatternValidationError",
    "ValidationResult",
    # Object-level validation
    "validate_object",
    "validate_bundle",
    "STIXObjectValidator",
    "STIXBundleValidator",
    "ObjectValidationResult",
    "BundleValidationResult",
    "ObjectValidationError",
]
