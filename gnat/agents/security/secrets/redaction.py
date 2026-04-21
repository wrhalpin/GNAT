# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.redaction
==========================================

Redaction utilities and helpers for the GNAT toolkit.
"""

from collections.abc import Iterable


def redact_text(text: str, secrets: Iterable[str]) -> str:
    """Redact text."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***REDACTED***")
    return text
