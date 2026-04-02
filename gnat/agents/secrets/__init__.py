"""Secrets broker agents for GNAT.

This package provides a vault abstraction for connector credentials and
secret-hygiene helpers for leak scanning and duplicate detection.
"""

from .broker import SecretsBroker
from .models import SecretGetRequest, SecretPutRequest, SecretRecord, SecretRef

__all__ = [
    "SecretsBroker",
    "SecretRef",
    "SecretRecord",
    "SecretPutRequest",
    "SecretGetRequest",
]
