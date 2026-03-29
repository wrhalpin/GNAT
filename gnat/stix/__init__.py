"""
gnat.stix
=========
STIX 2.1 utilities — pattern validation and (future) object-level validation.

Usage::

    from gnat.stix import validate_pattern, PatternValidationError

    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']")
    if not result:
        print(result.errors)

    # Raise on failure:
    validate_pattern("[bad pattern", strict=True)   # raises PatternValidationError

    # Strict mode — uses stix2-patterns (pip install "gnat[stix-validate]") when available:
    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']", strict=True)
    print(result.strict)  # True if ANTLR grammar was used
"""

from gnat.stix.pattern_validator import (
    PatternValidationError,
    PatternValidator,
    ValidationResult,
    validate_pattern,
)

__all__ = [
    "validate_pattern",
    "PatternValidator",
    "PatternValidationError",
    "ValidationResult",
]
