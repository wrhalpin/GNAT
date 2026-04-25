# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schemas for the auth domain."""

from gnat.schemas.auth.identity import APIKeySchema, OIDCIdentitySchema

__all__ = [
    "APIKeySchema",
    "OIDCIdentitySchema",
]
