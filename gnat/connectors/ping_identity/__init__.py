# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.ping_identity
=================================

Ping Identity (PingOne) connector. Wraps the v1 API at
``https://api.pingone.com/v1/``.
"""

from .client import PingIdentityClient

__all__ = ["PingIdentityClient"]
