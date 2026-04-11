# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.xm_cyber
============================

XM Cyber Attack Path Management connector. Wraps the v2 API at
``https://<tenant>.xmcyber.com/api/v2/``.
"""

from .client import XMCyberClient

__all__ = ["XMCyberClient"]
