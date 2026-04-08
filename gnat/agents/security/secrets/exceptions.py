# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.security.secrets.exceptions
===========================================

Exceptions utilities and helpers for the GNAT toolkit.
"""
class SecretError(Exception):
    """Raised when a secret error error occurs."""


class SecretPolicyError(SecretError):
    """Raised when a secret policy error error occurs."""


class SecretProviderError(SecretError):
    """Raised when a secret provider error error occurs."""


class UnsupportedProviderAction(SecretProviderError):
    """UnsupportedProviderAction implementation."""
