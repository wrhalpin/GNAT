# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.securitytrails
==================================

SecurityTrails connector — passive DNS, historical DNS, WHOIS, and
infrastructure pivoting. Wraps ``https://api.securitytrails.com/v1/``.
"""

from .client import SecurityTrailsClient

__all__ = ["SecurityTrailsClient"]
